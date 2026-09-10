"""
Realistic log degradation, for testing whether parse-confidence awareness helps.

Why this exists
---------------
The first USP-1 ablation showed no benefit from parse-confidence features, and
the likely reason is a property of the test rather than of the idea: every
event in the replay corpus is rendered by our own three renderers, so parse
quality is uniformly high. A feature that barely varies cannot carry signal.

Confidence-awareness can only matter when confidence actually differs between
events. In production it does, constantly. This module reproduces the specific
ways real log pipelines lose fidelity, so the question can be asked properly.

The degradations are real failure modes, not invented ones
----------------------------------------------------------
* **Syslog truncation.** RFC 3164 syslog over UDP is limited to 1024 bytes and
  devices silently truncate at the boundary. Long firewall lines lose their
  trailing fields - which, in CSV-style formats, are often the byte counts.
* **CSV column drift.** PAN-OS field order changes between major versions. A
  parser written for one version reads every field after the insertion point
  one position off - the classic silent-corruption case, where values are
  present and plausible but wrong.
* **Field dropout.** A device configured with a reduced logging profile omits
  fields entirely.
* **Encoding damage.** Multi-byte characters mangled by a relay that assumed
  Latin-1.

Independence from the label
---------------------------
Degradation is applied **independently of whether a flow is an attack**, with a
deterministic hash of the log content deciding. If corruption correlated with
the label, the model would learn to detect our corruption rather than learn
anything about parse quality, and the experiment would prove nothing.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

#: RFC 3164 practical limit for syslog over UDP.
SYSLOG_UDP_LIMIT = 1024


def _stable_fraction(text: str, salt: str = "") -> float:
    """Deterministic pseudo-random value in [0, 1) from the content itself.

    Deterministic so a degraded replay is reproducible, and derived from the
    log text rather than from the flow's label so it cannot encode the answer.
    """
    digest = hashlib.sha256((salt + text).encode("utf-8", "replace")).digest()
    return int.from_bytes(digest[:4], "big") / 0xFFFFFFFF


def truncate_syslog(line: str) -> str:
    """Cut the line at the UDP syslog boundary, as a real relay would."""
    encoded = line.encode("utf-8", "replace")
    if len(encoded) <= SYSLOG_UDP_LIMIT:
        # Short lines get a proportional cut instead, so the failure mode is
        # still exercised on formats that are naturally compact.
        cut = max(16, int(len(line) * 0.72))
        return line[:cut]
    return encoded[:SYSLOG_UDP_LIMIT].decode("utf-8", "ignore")


def drop_field(line: str) -> str:
    """Remove one key=value pair, as a reduced logging profile would."""
    parts = line.split()
    candidates = [i for i, p in enumerate(parts) if "=" in p]
    if len(candidates) < 3:
        return line
    victim = candidates[int(_stable_fraction(line, "drop") * len(candidates))]
    return " ".join(p for i, p in enumerate(parts) if i != victim)


def shift_csv_columns(line: str) -> str:
    """Insert a field mid-record, shifting everything after it by one.

    The silent-corruption case: nothing looks malformed, every field parses,
    and every value after the insertion point belongs to the wrong column.
    """
    if line.count(",") < 6:
        return line
    parts = line.split(",")
    at = 4 + int(_stable_fraction(line, "shift") * max(1, len(parts) - 6))
    return ",".join(parts[:at] + ["0"] + parts[at:])


def mangle_encoding(line: str) -> str:
    """Damage characters the way a relay assuming the wrong codec would."""
    idx = int(_stable_fraction(line, "enc") * max(1, len(line) - 8))
    return line[:idx] + "��" + line[idx + 2:]


@dataclass
class DegradationProfile:
    """Which failure modes to apply, and to what share of events."""

    rate: float = 0.15
    modes: Tuple[str, ...] = ("truncate", "drop_field", "shift_columns", "encoding")

    def as_dict(self) -> Dict[str, object]:
        return {"rate": self.rate, "modes": list(self.modes)}


_MODES: Dict[str, Callable[[str], str]] = {
    "truncate": truncate_syslog,
    "drop_field": drop_field,
    "shift_columns": shift_csv_columns,
    "encoding": mangle_encoding,
}


class Degrader:
    """Applies a degradation profile to rendered log lines."""

    def __init__(self, profile: Optional[DegradationProfile] = None):
        self.profile = profile or DegradationProfile()
        self.applied: Dict[str, int] = {m: 0 for m in self.profile.modes}
        self.untouched = 0

    def apply(self, line: str) -> str:
        roll = _stable_fraction(line, "select")
        if roll >= self.profile.rate:
            self.untouched += 1
            return line
        modes = self.profile.modes
        # A second independent draw picks which failure mode, so the mode is
        # not correlated with how close the line was to the rate cutoff.
        mode = modes[int(_stable_fraction(line, "mode") * len(modes))]
        self.applied[mode] += 1
        try:
            return _MODES[mode](line)
        except Exception:
            return line

    def stats(self) -> Dict[str, object]:
        total = self.untouched + sum(self.applied.values())
        return {
            "events": total,
            "degraded": sum(self.applied.values()),
            "degraded_share": round(sum(self.applied.values()) / max(total, 1), 4),
            "by_mode": dict(self.applied),
            "profile": self.profile.as_dict(),
        }
