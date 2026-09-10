"""
Entity behaviour detector (UEBA).

Detects what a single event cannot show: deviation from an entity's own
established pattern. Reconnaissance, credential attacks and lateral movement
are all built out of individually unremarkable events - a single connection to
a single port looks like nothing. What gives them away is the *shape* of an
entity's behaviour changing.

This detector consumes the behavioural feature family; it does not recompute
baselines. Feature extraction owns the ordering guarantee (score against the
baseline as it stood before this event), and duplicating that logic here would
be a second place for it to go wrong.

Cold baselines
--------------
When an entity has too little history, this detector returns a low score with
*low confidence* rather than a zero with high confidence. Those are different
statements - "nothing unusual" versus "I cannot tell" - and collapsing them is
how UEBA systems end up silently blind on their first day in a new network.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from backend.ml.detectors.base import Evidence, Signal

#: Distinct-port fan-out above which scanning becomes the likely explanation.
#: Expressed on the log-scaled feature, where 1.0 corresponds to ~1000 ports.
_FANOUT_PORTS_SUSPICIOUS = 0.60      # ~60 distinct ports
_FANOUT_PEERS_SUSPICIOUS = 0.60

#: Denied-traffic ratio above which an entity looks like it is probing.
_DENY_RATIO_SUSPICIOUS = 0.50


class BehaviourDetector:
    """Scores an event against its source and destination entity baselines."""

    name = "behaviour"

    def analyse(
        self,
        features: Dict[str, float],
        norm: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Signal:
        f = features
        cold = f.get("src_baseline_cold", 1.0) >= 1.0
        evidence = []
        contributions = []

        def add(signal: str, value: Any, argues: str, weight: float) -> None:
            evidence.append(Evidence(signal=signal, observed=value,
                                     argues=argues, weight=weight))
            contributions.append(weight)

        # --- fan-out: the defining shape of scanning ------------------------
        fanout_ports = f.get("src_fanout_ports", 0.0)
        if fanout_ports >= _FANOUT_PORTS_SUSPICIOUS:
            add("port_fanout", round(fanout_ports, 3),
                "This source has contacted an unusually wide range of ports",
                0.55 * fanout_ports)

        fanout_peers = f.get("src_fanout_peers", 0.0)
        if fanout_peers >= _FANOUT_PEERS_SUSPICIOUS:
            add("peer_fanout", round(fanout_peers, 3),
                "This source has contacted an unusually large number of hosts",
                0.45 * fanout_peers)

        # --- fan-in: the shape of a distributed flood -----------------------
        fanin = f.get("dst_fanin_peers", 0.0)
        if fanin >= _FANOUT_PEERS_SUSPICIOUS:
            add("peer_fanin", round(fanin, 3),
                "This destination is being contacted by an unusually large "
                "number of distinct sources",
                0.40 * fanin)

        # --- refusal ratio: the shape of probing ----------------------------
        deny = f.get("src_deny_ratio", 0.0)
        if deny >= _DENY_RATIO_SUSPICIOUS:
            add("deny_ratio", round(deny, 3),
                f"{deny:.0%} of this source's recent traffic was refused",
                0.45 * deny)

        # --- novelty against the entity's own history -----------------------
        if not cold:
            port_s = f.get("src_port_surprisal", 0.0)
            if port_s > 0.30:
                add("port_novelty", round(port_s, 3),
                    "This source rarely or never uses this destination port",
                    0.40 * port_s)

            peer_s = f.get("src_peer_surprisal", 0.0)
            if peer_s > 0.30:
                add("peer_novelty", round(peer_s, 3),
                    "This source rarely or never contacts this host",
                    0.30 * peer_s)

            hour_s = f.get("src_hour_surprisal", 0.0)
            if hour_s > 0.40:
                add("time_novelty", round(hour_s, 3),
                    "This source is not usually active at this hour",
                    0.25 * hour_s)

            volume_z = f.get("src_bytes_out_z", 0.0)
            if volume_z > 0.5:
                add("volume_deviation", round(volume_z, 3),
                    "Outbound volume is well above this source's own baseline",
                    0.45 * volume_z)

            proto_s = f.get("src_proto_surprisal", 0.0)
            if proto_s > 0.50:
                add("protocol_novelty", round(proto_s, 3),
                    "This source does not normally use this protocol",
                    0.20 * proto_s)

        # --- evidence against -----------------------------------------------
        if not cold and not contributions:
            add("matches_baseline", True,
                "Every attribute of this event is consistent with this "
                "source's established behaviour",
                -0.20)

        # Combined with a noisy-OR rather than a sum: several weak, correlated
        # behavioural signals (wide fan-out AND many refusals AND a new port
        # are all facets of one scan) should not add up past certainty.
        score = _noisy_or([w for w in contributions if w > 0])

        if cold:
            # Not "nothing unusual" - "not enough history to say".
            confidence = 0.25
            evidence.append(Evidence(
                signal="cold_baseline",
                observed=int(f.get("src_activity", 0.0) * 100),
                argues="This source has too little history for its baseline to "
                       "be meaningful; behavioural signals are unreliable here",
                weight=0.0,
            ))
        else:
            confidence = 0.60 + 0.35 * min(1.0, f.get("src_activity", 0.0))

        return Signal(
            detector=self.name,
            score=score,
            confidence=confidence,
            evidence=evidence,
            state={"cold_baseline": bool(cold)},
        )


def _noisy_or(weights) -> float:
    """Combine independent-ish positive signals without exceeding 1.0.

    P(any) = 1 - product(1 - w). Correlated evidence still accumulates, but
    with diminishing returns, which is the right behaviour when several
    signals are facets of the same underlying event.
    """
    product = 1.0
    for w in weights:
        product *= (1.0 - max(0.0, min(1.0, w)))
    return 1.0 - product
