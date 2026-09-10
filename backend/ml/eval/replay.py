"""
Corpus replay - render labelled flows as real device log lines.

Why render instead of injecting
-------------------------------
It would be far easier to build `ULPFNormalizedEvent` objects straight from the
corpus CSV and hand them to the model. That would also be dishonest: it would
measure a classifier on clean tabular data while bypassing the parsers,
normalizer, taxonomy and provenance layers that are the actual product. Any
parsing defect would be invisible, and the demo would prove nothing about the
framework.

So each flow is rendered into the wire format of a real perimeter device and
pushed through the same pipeline a live syslog listener would feed. The
parsers do the work they would do in production. If a renderer emits something
a parser cannot read, the round-trip test fails and we find out.

Fidelity, and where it is deliberately lossy
--------------------------------------------
Real devices do not all report the same things, and pretending otherwise would
overstate what the pipeline receives:

* **Fortinet key-value** carries per-direction bytes and packets - the richest
  of the three, and closest to lossless for our purposes.
* **Cisco ASA** teardown messages carry a *single* total byte count and no
  packet counts. Rendering a flow as ASA genuinely loses the forward/backward
  split, exactly as it would in production.
* **Suricata EVE** carries per-direction bytes and packets in its `flow`
  object, plus an alert only when a signature fired.

That variation is the point. A framework claiming to normalize heterogeneous
sources should be evaluated on heterogeneous sources, including ones that
report less than others. The round-trip test asserts what each format is
expected to preserve, not that all three preserve everything.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from backend.ml.eval.corpus import FlowRecord

#: ASA severity by whether the flow was permitted. Denies are level 4, builds
#: and teardowns level 6 - matching real ASA behaviour.
_ASA_DENY_SEVERITY = 4
_ASA_ALLOW_SEVERITY = 6

#: Attack labels a perimeter IPS would plausibly have a signature for. Used
#: only to decide whether a rendered Suricata line carries an alert block, and
#: never fed to the model as a feature - that would leak the label.
_SIGNATURE_VISIBLE = {
    "PortScan": ("ET SCAN Suspicious inbound port scan", "attempted-recon"),
    "FTP-Patator": ("ET SCAN Potential FTP Brute-Force attempt", "attempted-recon"),
    "SSH-Patator": ("ET SCAN Potential SSH Brute-Force attempt", "attempted-recon"),
    "DDoS": ("ET DOS Inbound high-rate connection flood", "attempted-dos"),
    "Heartbleed": ("ET EXPLOIT OpenSSL Heartbleed overread", "attempted-admin"),
}


def _asa_duration(duration_us: int) -> str:
    total_s = max(0, duration_us) // 1_000_000
    return f"{total_s // 3600}:{(total_s % 3600) // 60:02d}:{total_s % 60:02d}"


def render_cisco_asa(flow: FlowRecord, denied: bool) -> str:
    """Cisco ASA syslog. Lossy by design: total bytes only, no packet counts."""
    proto = flow.protocol.lower()
    if denied:
        return (
            f"%ASA-{_ASA_DENY_SEVERITY}-106023: Deny {proto} "
            f"src outside:{flow.src_ip}/{flow.src_port} "
            f"dst inside:{flow.dst_ip}/{flow.dst_port} "
            f"by access-group 'OUTSIDE-IN' [0x0, 0x0]"
        )
    conn_id = abs(hash((flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port))) % 1_000_000
    return (
        f"%ASA-{_ASA_ALLOW_SEVERITY}-302014: Teardown "
        f"{'TCP' if flow.protocol == 'TCP' else 'UDP'} connection {conn_id} "
        f"for outside:{flow.src_ip}/{flow.src_port} "
        f"to inside:{flow.dst_ip}/{flow.dst_port} "
        f"duration {_asa_duration(flow.duration_us)} bytes {flow.total_bytes} "
        f"{'TCP FINs' if flow.protocol == 'TCP' else 'UDP timeout'}"
    )


def render_fortinet_kv(flow: FlowRecord, denied: bool) -> str:
    """FortiGate key-value syslog. Preserves per-direction bytes and packets."""
    proto_num = {"TCP": 6, "UDP": 17, "ICMP": 1}.get(flow.protocol, 0)
    return (
        f'date={flow.timestamp:%Y-%m-%d} time={flow.timestamp:%H:%M:%S} '
        f'devname="FGT-PERIMETER-01" devid="FGT60F0000000001" '
        f'type="traffic" subtype="forward" level="notice" '
        f'srcip={flow.src_ip} srcport={flow.src_port} '
        f'dstip={flow.dst_ip} dstport={flow.dst_port} '
        f'proto={proto_num} action="{"deny" if denied else "accept"}" '
        f'policyid=42 service="{_service_for(flow.dst_port)}" '
        f'duration={max(0, flow.duration_us) // 1_000_000} '
        f'sentbyte={flow.fwd_bytes} rcvdbyte={flow.bwd_bytes} '
        f'sentpkt={flow.fwd_packets} rcvdpkt={flow.bwd_packets}'
    )


def render_suricata_eve(flow: FlowRecord, denied: bool) -> str:
    """Suricata EVE JSON. Carries an alert block only when a signature fired."""
    record: Dict[str, object] = {
        "timestamp": flow.timestamp.isoformat() + "+0000",
        "flow_id": abs(hash((flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port))) % (10 ** 15),
        "event_type": "flow",
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dest_ip": flow.dst_ip,
        "dest_port": flow.dst_port,
        "proto": flow.protocol,
        "flow": {
            "pkts_toserver": flow.fwd_packets,
            "pkts_toclient": flow.bwd_packets,
            "bytes_toserver": flow.fwd_bytes,
            "bytes_toclient": flow.bwd_bytes,
            "start": flow.timestamp.isoformat() + "+0000",
            "state": "closed" if not denied else "new",
            "reason": "timeout",
        },
    }
    signature = _SIGNATURE_VISIBLE.get(flow.label)
    if signature:
        record["event_type"] = "alert"
        record["alert"] = {
            "action": "blocked" if denied else "allowed",
            "signature": signature[0],
            "category": signature[1],
            "severity": 2,
            "gid": 1,
            "signature_id": 2000000 + (abs(hash(signature[0])) % 9999),
        }
    return json.dumps(record, separators=(",", ":"))


def _service_for(port: int) -> str:
    return {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 53: "DNS",
            3389: "RDP", 445: "SMB", 25: "SMTP"}.get(port, f"tcp/{port}")


#: Renderer registry. Names match the vendor whose format is emitted.
RENDERERS: Dict[str, Callable[[FlowRecord, bool], str]] = {
    "cisco_asa": render_cisco_asa,
    "fortinet_kv": render_fortinet_kv,
    "suricata_eve": render_suricata_eve,
}

#: The 5-tuple every format must carry. Anything less and the event cannot be
#: attributed to an entity, which breaks all behavioural features.
_FIVE_TUPLE = frozenset({"src_ip", "dst_ip", "src_port", "dst_port", "protocol"})

#: Per-direction counters, for formats that carry them.
_DIRECTIONAL = frozenset({"fwd_bytes", "bwd_bytes", "fwd_packets", "bwd_packets"})


def preserved_fields(vendor: str, denied: bool) -> frozenset:
    """What a rendered line is expected to preserve through parse + normalize.

    This depends on the *message variant*, not just the vendor, because real
    devices carry different things in different messages. A Cisco ASA deny
    (106023) reports that a connection was refused and nothing about volume -
    there were no bytes to count. Only the teardown (302014) carries a byte
    total, and even then a single one rather than a per-direction split.

    Encoding that honestly matters: asserting a format preserves something it
    physically cannot would either force a dishonest renderer or produce a
    permanently failing test.
    """
    if vendor == "cisco_asa":
        return _FIVE_TUPLE if denied else (_FIVE_TUPLE | {"total_bytes"})
    if vendor in ("fortinet_kv", "suricata_eve"):
        return _FIVE_TUPLE | _DIRECTIONAL
    raise KeyError(f"No fidelity contract for vendor {vendor!r}")


def is_denied(flow: FlowRecord) -> bool:
    """Public alias of the action rule, for tests and the evaluation harness."""
    return _is_denied(flow)


@dataclass(frozen=True)
class ReplayEvent:
    """A rendered log line plus the ground truth it was rendered from.

    The label travels *alongside* the log line, never inside it. Nothing the
    pipeline can read carries the answer.
    """

    raw_log: str
    vendor: str
    label: str
    is_attack: bool
    day: str
    flow: FlowRecord


def _is_denied(flow: FlowRecord) -> bool:
    """Whether a perimeter device would plausibly have blocked this flow.

    Deliberately *not* a function of the label. Deriving the action from the
    ground truth would leak the answer into the input: every attack would
    arrive pre-marked as denied and the model would learn `action == deny`
    instead of learning anything about traffic.

    A flow that produced no response bytes and no response packets is one the
    device dropped or that was never answered - which is observable from the
    flow itself, exactly as a real device would observe it.
    """
    return flow.bwd_packets == 0 and flow.bwd_bytes == 0


def assign_vendor(flow: FlowRecord, vendors: Sequence[str]) -> str:
    """Deterministically assign a rendering format to a flow.

    Deterministic (hash of the 5-tuple) rather than random so a replay is
    reproducible, and so the same flow always exercises the same parser across
    runs - otherwise a metric change could be a vendor-mix change instead of a
    model change.
    """
    key = (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol)
    return vendors[abs(hash(key)) % len(vendors)]


def render(flow: FlowRecord, vendor: str) -> str:
    renderer = RENDERERS.get(vendor)
    if renderer is None:
        raise KeyError(f"No renderer for vendor {vendor!r}; "
                       f"have {sorted(RENDERERS)}")
    return renderer(flow, _is_denied(flow))


def replay(
    flows: Iterator[FlowRecord],
    vendors: Optional[Sequence[str]] = None,
) -> Iterator[ReplayEvent]:
    """Render a stream of flows as device log lines with ground truth attached."""
    chosen = list(vendors) if vendors else sorted(RENDERERS)
    for flow in flows:
        vendor = assign_vendor(flow, chosen)
        yield ReplayEvent(
            raw_log=render(flow, vendor),
            vendor=vendor,
            label=flow.label,
            is_attack=flow.is_attack,
            day=flow.day,
            flow=flow,
        )
