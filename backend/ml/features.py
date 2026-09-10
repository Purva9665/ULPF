"""
ULPF Feature Extraction - the vector every detector and the fusion model share.

Three families of feature, deliberately kept separable
------------------------------------------------------
1. **Intrinsic** - computable from the single event. Port, volume, protocol,
   direction, time of day. This is all the previous engine had.

2. **Behavioural** - the event compared against the entity's own baseline.
   "Has this host used this port before?" is not answerable from one log line;
   it is answerable from a profile. These carry most of the detection signal
   for reconnaissance, brute force and lateral movement, none of which look
   unusual in any single event.

3. **Parse confidence** - how much the parser trusts the fields the other two
   families just used. This family is USP-1 and does not exist in any other
   pipeline, because every wire format between a pipeline and a SIEM discards
   per-field confidence.

They are kept separable so the ablation in the evaluation protocol can switch
family 3 off and measure exactly what it contributes. A USP that cannot be
switched off cannot be shown to work.

Ordering guarantee
------------------
Features are computed against the baseline *as it stood before this event*,
and only then is the profile updated. Reversing that order lets an event
contaminate the baseline it is being judged against, which silently destroys
the signal for exactly the slow-and-low attacks profiling is meant to catch.
`extract()` enforces the order; callers must not update profiles themselves.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.core.models import ULPFNormalizedEvent
from backend.ml.profiles import MIN_EVENTS_FOR_BASELINE, ProfileStore

#: Entity key under which network-wide baselines are kept. Lets a detector ask
#: "is this port rare for this host?" and "is it rare for this network?"
#: separately - a host's first use of port 443 is unremarkable, its first use
#: of port 4444 is not, and only the global baseline knows the difference.
GLOBAL_ENTITY = "__network__"

#: Ports disproportionately represented in lateral movement and remote-access
#: abuse. Used as one weak feature, never as a rule on its own.
SENSITIVE_PORTS = frozenset({
    22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
    9200, 11211, 27017, 2375, 2376, 4444, 5555, 8080, 8443,
})


@dataclass(frozen=True)
class FeatureSpec:
    """One named feature: how it is computed and what it means.

    Names are stable and exported alongside the model, so a per-feature
    contribution can be rendered as a sentence in the evidence panel rather
    than as `feature_17`.
    """
    name: str
    family: str          # "intrinsic" | "behavioural" | "confidence"
    description: str


class FeatureExtractor:
    """Builds the shared feature vector and keeps entity profiles current."""

    def __init__(self, profiles: Optional[ProfileStore] = None,
                 use_confidence_features: bool = True):
        self.profiles = profiles if profiles is not None else ProfileStore()
        #: The ablation switch. Off reproduces a conventional pipeline that has
        #: no access to parse confidence, which is the comparison USP-1 needs.
        self.use_confidence_features = use_confidence_features
        self._specs: List[FeatureSpec] = self._build_specs()

    # -- public API ---------------------------------------------------------

    @property
    def specs(self) -> List[FeatureSpec]:
        return list(self._specs)

    @property
    def feature_names(self) -> List[str]:
        return [s.name for s in self._specs]

    def describe(self) -> Dict[str, Any]:
        by_family: Dict[str, List[str]] = {}
        for s in self._specs:
            by_family.setdefault(s.family, []).append(s.name)
        return {
            "n_features": len(self._specs),
            "families": {k: len(v) for k, v in by_family.items()},
            "confidence_features_enabled": self.use_confidence_features,
            "names_by_family": by_family,
        }

    def extract(
        self,
        norm: ULPFNormalizedEvent,
        *,
        update_profiles: bool = True,
    ) -> Tuple[List[float], Dict[str, float]]:
        """Feature vector for one event.

        Returns `(vector, named)` - the ordered vector the model consumes and
        the same values keyed by name for explanation and debugging.

        Profiles are read first and updated afterwards; see the module
        docstring on why that order is not negotiable.
        """
        ctx = _EventContext(norm)

        values: Dict[str, float] = {}
        values.update(self._intrinsic(ctx))
        values.update(self._behavioural(ctx))
        if self.use_confidence_features:
            values.update(self._confidence(ctx, norm))

        if update_profiles:
            self._update_profiles(ctx)

        vector = [float(values.get(s.name, 0.0)) for s in self._specs]
        return vector, values

    # -- family 1: intrinsic ------------------------------------------------

    def _intrinsic(self, c: "_EventContext") -> Dict[str, float]:
        byte_ratio = (c.bytes_out + 1.0) / (c.bytes_in + 1.0)
        return {
            "dst_port_scaled": min(c.dst_port, 65535) / 65535.0,
            "dst_port_is_sensitive": 1.0 if c.dst_port in SENSITIVE_PORTS else 0.0,
            "dst_port_is_ephemeral": 1.0 if c.dst_port >= 49152 else 0.0,
            "src_port_is_ephemeral": 1.0 if c.src_port >= 49152 else 0.0,
            "log_bytes_out": _log1p_scaled(c.bytes_out),
            "log_bytes_in": _log1p_scaled(c.bytes_in),
            "log_bytes_total": _log1p_scaled(c.bytes_out + c.bytes_in),
            "byte_ratio_log": _squash(math.log10(max(byte_ratio, 1e-6)) / 3.0),
            "log_packets_total": _log1p_scaled(c.packets_total, cap=6.0),
            "is_zero_payload": 1.0 if (c.bytes_out + c.bytes_in) == 0 else 0.0,
            "proto_is_tcp": 1.0 if c.protocol == "TCP" else 0.0,
            "proto_is_udp": 1.0 if c.protocol == "UDP" else 0.0,
            "proto_is_icmp": 1.0 if c.protocol == "ICMP" else 0.0,
            "dir_is_inbound": 1.0 if c.direction == "INBOUND" else 0.0,
            "dir_is_outbound": 1.0 if c.direction == "OUTBOUND" else 0.0,
            "action_is_denied": 1.0 if c.is_denied else 0.0,
            # Cyclic encoding: 23:00 and 00:00 are adjacent, and a raw 0-23
            # integer would tell a tree they are maximally distant.
            "hour_sin": math.sin(2 * math.pi * c.hour / 24.0),
            "hour_cos": math.cos(2 * math.pi * c.hour / 24.0),
            "is_off_hours": 1.0 if (c.hour < 6 or c.hour >= 20) else 0.0,
        }

    # -- family 2: behavioural ----------------------------------------------

    def _behavioural(self, c: "_EventContext") -> Dict[str, float]:
        src = self.profiles.peek("ip", c.src_ip) if c.src_ip else None
        dst = self.profiles.peek("ip", c.dst_ip) if c.dst_ip else None
        glob = self.profiles.peek("global", GLOBAL_ENTITY)

        out: Dict[str, float] = {}
        port_s = str(c.dst_port)

        # --- source entity: how unusual is this event for this host? --------
        if src is None:
            out.update({
                "src_port_surprisal": 0.0,
                "src_peer_surprisal": 0.0,
                "src_proto_surprisal": 0.0,
                "src_hour_surprisal": 0.0,
                "src_port_is_new": 0.0,
                "src_peer_is_new": 0.0,
                "src_bytes_out_z": 0.0,
                "src_fanout_ports": 0.0,
                "src_fanout_peers": 0.0,
                "src_deny_ratio": 0.0,
                "src_activity": 0.0,
                "src_baseline_cold": 1.0,
                "src_beacon_score": 0.0,
            })
        else:
            cold = src.is_cold()
            # Surprisal against a baseline of four events is noise. It is
            # zeroed rather than reported, and `src_baseline_cold` tells the
            # model the zero means "unknown", not "normal".
            damp = 0.0 if cold else 1.0
            deny = src.actions.weight_of("denied") + src.actions.weight_of("blocked")
            total_actions = max(src.actions.total(), 1.0)
            out.update({
                "src_port_surprisal": damp * src.dst_ports.surprisal(port_s),
                "src_peer_surprisal": damp * (
                    src.peers.surprisal(c.dst_ip) if c.dst_ip else 0.0
                ),
                "src_proto_surprisal": damp * src.protocols.surprisal(c.protocol),
                "src_hour_surprisal": damp * src.hours.surprisal(str(c.hour)),
                "src_port_is_new": 1.0 if src.dst_ports.is_new(port_s) else 0.0,
                "src_peer_is_new": 1.0 if (
                    c.dst_ip and src.peers.is_new(c.dst_ip)
                ) else 0.0,
                "src_bytes_out_z": _squash(src.bytes_out.zscore(c.bytes_out) / 6.0),
                # Fan-out is the defining signature of scanning: one source,
                # many destination ports or many peers, in a short span.
                "src_fanout_ports": _log1p_scaled(src.dst_ports.cardinality(), cap=3.0),
                "src_fanout_peers": _log1p_scaled(src.peers.cardinality(), cap=3.0),
                "src_deny_ratio": deny / total_actions,
                "src_activity": _log1p_scaled(src.event_count, cap=5.0),
                "src_baseline_cold": 1.0 if cold else 0.0,
                "src_beacon_score": damp * _beacon_score(src, c.dst_ip),
            })

        # --- destination entity: is this host being converged on? -----------
        # Many distinct sources hitting one destination is the DDoS signature,
        # and it is invisible from the source's profile alone.
        if dst is None:
            out.update({
                "dst_fanin_peers": 0.0,
                "dst_activity": 0.0,
                "dst_deny_ratio": 0.0,
            })
        else:
            deny = dst.actions.weight_of("denied") + dst.actions.weight_of("blocked")
            out.update({
                "dst_fanin_peers": _log1p_scaled(dst.peers.cardinality(), cap=3.0),
                "dst_activity": _log1p_scaled(dst.event_count, cap=5.0),
                "dst_deny_ratio": deny / max(dst.actions.total(), 1.0),
            })

        # --- network-wide: rare for the host, or rare for everyone? ---------
        if glob is None:
            out.update({"net_port_surprisal": 0.0, "net_proto_surprisal": 0.0})
        else:
            out.update({
                "net_port_surprisal": glob.dst_ports.surprisal(port_s),
                "net_proto_surprisal": glob.protocols.surprisal(c.protocol),
            })

        return out

    # -- family 3: parse confidence (USP-1) ---------------------------------

    def _confidence(
        self, c: "_EventContext", norm: ULPFNormalizedEvent
    ) -> Dict[str, float]:
        """How much the parser trusts the fields the detectors just used.

        The sharp version of this idea is not the event-level average but
        `evidence_field_confidence`: confidence in the *specific* fields that
        carried the detection signal. An event can be 95% well-parsed overall
        and still have got the destination port wrong, and the port is what
        the scan detector is about to rely on.
        """
        q = norm.parse_quality()

        evidence_paths = ("destination.port", "source.ip", "destination.ip",
                          "network.protocol", "event.action")
        confs = [norm.field_confidence(p) for p in evidence_paths]
        evidence_conf = min(confs) if confs else 1.0

        return {
            "parse_mean_confidence": float(q["mean_confidence"]),
            "parse_min_confidence": float(q["min_confidence"]),
            "parse_mapped_ratio": float(q["mapped_ratio"]),
            "parse_unmapped_count": _log1p_scaled(q["fields_unmapped"], cap=2.0),
            "parse_has_low_conf": 1.0 if q["low_confidence_fields"] else 0.0,
            "evidence_field_confidence": evidence_conf,
            "parse_inferred_ratio": (
                float(q["by_method"].get("inferred", 0) + q["by_method"].get("defaulted", 0))
                / max(float(q["fields_tracked"]), 1.0)
            ),
        }

    # -- profile maintenance ------------------------------------------------

    def _update_profiles(self, c: "_EventContext") -> None:
        action = "denied" if c.is_denied else "allowed"
        if c.src_ip:
            self.profiles.get("ip", c.src_ip).observe(
                dst_port=c.dst_port, peer=c.dst_ip, protocol=c.protocol,
                action=action, threat_class=c.threat_class, hour=c.hour,
                bytes_out=c.bytes_out, bytes_in=c.bytes_in, timestamp=c.epoch,
            )
        if c.dst_ip:
            # The destination's peer set is its set of *sources*, which is what
            # makes fan-in measurable.
            self.profiles.get("ip", c.dst_ip).observe(
                dst_port=c.dst_port, peer=c.src_ip, protocol=c.protocol,
                action=action, threat_class=c.threat_class, hour=c.hour,
                bytes_out=c.bytes_in, bytes_in=c.bytes_out, timestamp=c.epoch,
            )
        self.profiles.get("global", GLOBAL_ENTITY).observe(
            dst_port=c.dst_port, protocol=c.protocol, action=action,
            threat_class=c.threat_class, hour=c.hour, timestamp=c.epoch,
        )

    # -- spec table ---------------------------------------------------------

    def _build_specs(self) -> List[FeatureSpec]:
        I, B, C = "intrinsic", "behavioural", "confidence"
        specs = [
            FeatureSpec("dst_port_scaled", I, "Destination port, scaled to 0-1"),
            FeatureSpec("dst_port_is_sensitive", I, "Port is a common remote-access or database port"),
            FeatureSpec("dst_port_is_ephemeral", I, "Destination port is in the ephemeral range"),
            FeatureSpec("src_port_is_ephemeral", I, "Source port is in the ephemeral range"),
            FeatureSpec("log_bytes_out", I, "Outbound bytes, log-scaled"),
            FeatureSpec("log_bytes_in", I, "Inbound bytes, log-scaled"),
            FeatureSpec("log_bytes_total", I, "Total bytes, log-scaled"),
            FeatureSpec("byte_ratio_log", I, "Outbound-to-inbound byte ratio, log-scaled"),
            FeatureSpec("log_packets_total", I, "Total packets, log-scaled"),
            FeatureSpec("is_zero_payload", I, "Connection carried no payload bytes"),
            FeatureSpec("proto_is_tcp", I, "Protocol is TCP"),
            FeatureSpec("proto_is_udp", I, "Protocol is UDP"),
            FeatureSpec("proto_is_icmp", I, "Protocol is ICMP"),
            FeatureSpec("dir_is_inbound", I, "Traffic direction is inbound"),
            FeatureSpec("dir_is_outbound", I, "Traffic direction is outbound"),
            FeatureSpec("action_is_denied", I, "Device denied or blocked the connection"),
            FeatureSpec("hour_sin", I, "Hour of day, cyclic sine component"),
            FeatureSpec("hour_cos", I, "Hour of day, cyclic cosine component"),
            FeatureSpec("is_off_hours", I, "Event occurred outside 06:00-20:00"),

            FeatureSpec("src_port_surprisal", B, "How unusual this destination port is for this source"),
            FeatureSpec("src_peer_surprisal", B, "How unusual this peer is for this source"),
            FeatureSpec("src_proto_surprisal", B, "How unusual this protocol is for this source"),
            FeatureSpec("src_hour_surprisal", B, "How unusual this hour is for this source"),
            FeatureSpec("src_port_is_new", B, "Source has never used this destination port"),
            FeatureSpec("src_peer_is_new", B, "Source has never contacted this peer"),
            FeatureSpec("src_bytes_out_z", B, "Outbound volume vs this source's own baseline"),
            FeatureSpec("src_fanout_ports", B, "Distinct destination ports this source has used"),
            FeatureSpec("src_fanout_peers", B, "Distinct peers this source has contacted"),
            FeatureSpec("src_deny_ratio", B, "Fraction of this source's traffic that was denied"),
            FeatureSpec("src_activity", B, "Total events observed from this source"),
            FeatureSpec("src_baseline_cold", B, "Source baseline too thin to judge against"),
            FeatureSpec("src_beacon_score", B, "Regularity of this source's contact intervals with the peer"),
            FeatureSpec("dst_fanin_peers", B, "Distinct sources that have contacted this destination"),
            FeatureSpec("dst_activity", B, "Total events observed against this destination"),
            FeatureSpec("dst_deny_ratio", B, "Fraction of traffic to this destination that was denied"),
            FeatureSpec("net_port_surprisal", B, "How unusual this port is network-wide"),
            FeatureSpec("net_proto_surprisal", B, "How unusual this protocol is network-wide"),
        ]
        if self.use_confidence_features:
            specs += [
                FeatureSpec("parse_mean_confidence", C, "Mean parser confidence across normalized fields"),
                FeatureSpec("parse_min_confidence", C, "Lowest parser confidence of any normalized field"),
                FeatureSpec("parse_mapped_ratio", C, "Share of parsed fields that reached the taxonomy"),
                FeatureSpec("parse_unmapped_count", C, "Count of fields left unmapped, log-scaled"),
                FeatureSpec("parse_has_low_conf", C, "At least one field parsed below 0.7 confidence"),
                FeatureSpec("evidence_field_confidence", C, "Confidence in the specific fields this detection relies on"),
                FeatureSpec("parse_inferred_ratio", C, "Share of fields inferred or defaulted rather than extracted"),
            ]
        return specs


# -- helpers ---------------------------------------------------------------


class _EventContext:
    """Flattened, type-safe view of the fields feature code needs.

    Parsers vary in what they populate and in what types they use. Normalising
    that once here keeps every feature function free of None-checks and
    coercions, which is where this kind of code usually rots.
    """

    __slots__ = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                 "direction", "bytes_out", "bytes_in", "packets_total",
                 "is_denied", "hour", "epoch", "threat_class")

    def __init__(self, norm: ULPFNormalizedEvent):
        self.src_ip = norm.source.ip or ""
        self.dst_ip = norm.destination.ip or ""
        self.src_port = _as_int(norm.source.port)
        self.dst_port = _as_int(norm.destination.port)
        self.protocol = (norm.network.protocol or "UNKNOWN").upper()
        self.direction = (norm.network.direction or "UNKNOWN").upper()

        self.bytes_out = _as_int(norm.source.bytes)
        self.bytes_in = _as_int(norm.destination.bytes)
        if not (self.bytes_out or self.bytes_in):
            self.bytes_out = _as_int(norm.network.bytes_total)
        self.packets_total = _as_int(norm.network.packets_total) or (
            _as_int(norm.source.packets) + _as_int(norm.destination.packets)
        )

        action = str(getattr(norm.event.action, "value", norm.event.action) or "").lower()
        self.is_denied = action in {"denied", "blocked", "dropped", "rejected",
                                    "deny", "block", "drop", "reject", "quarantined"}

        self.epoch, self.hour = _timestamp_parts(norm)
        self.threat_class = (norm.classification or {}).get("threat_class")


def _timestamp_parts(norm: ULPFNormalizedEvent) -> Tuple[float, int]:
    """Epoch seconds and hour-of-day, falling back through available stamps."""
    for candidate in (norm.event.timestamp, norm.event.ingested_at):
        if not candidate:
            continue
        try:
            text = str(candidate).replace("Z", "+00:00")
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp(), dt.hour
        except (ValueError, TypeError):
            continue
    return 0.0, 0


def _as_int(value: Any) -> int:
    try:
        if value is None:
            return 0
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def _log1p_scaled(value: float, cap: float = 7.0) -> float:
    """log10(1+x) scaled to roughly 0-1 over [0, 10**cap].

    Log scaling because byte counts and event counts span six orders of
    magnitude; a linear feature would let one 2 GB transfer dominate the split
    points for every other value in the tree.
    """
    try:
        v = max(float(value), 0.0)
    except (TypeError, ValueError):
        return 0.0
    return min(1.0, math.log10(1.0 + v) / cap)


def _squash(x: float) -> float:
    """Map an unbounded real to (-1, 1) so outliers cannot dominate."""
    return math.tanh(x)


def _beacon_score(profile, peer: str) -> float:
    """Regularity of contact intervals with one peer, in [0, 1].

    Command-and-control beacons contact their controller on a timer, so the
    inter-arrival gaps have very low relative dispersion. Human and
    application traffic is bursty and irregular. The coefficient of variation
    (sigma/mu) separates the two without needing to know the beacon period,
    which is the property that makes this work against an unknown implant.

    Requires enough intervals to be meaningful; below that it returns 0.0
    rather than a confident-looking number derived from three samples.
    """
    if not peer:
        return 0.0
    stats = profile.intervals.get(peer)
    if stats is None or stats.n < 8 or stats.mean <= 0:
        return 0.0
    cv = stats.stddev / stats.mean
    # cv <= 0.15 is a strong beacon; cv >= 1.0 is ordinary bursty traffic.
    if cv >= 1.0:
        return 0.0
    return float(min(1.0, max(0.0, (1.0 - cv) ** 2)))
