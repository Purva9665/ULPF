"""
Detector contract.

Every detector returns a score **and the evidence that produced it**. A bare
number is not actionable: an analyst asked to act on "0.83" has to either trust
it blindly or ignore it, and in practice they ignore it. That is how SIEM risk
scores lose their audience.

Evidence is structured rather than a formatted string so the UI, the exporters
and the detection bundle can each render it their own way, and so a reviewer
can machine-check a verdict instead of reading prose.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol


@dataclass(frozen=True)
class Evidence:
    """One observation that argued for or against a verdict.

    `weight` is signed: negative weight is evidence *against*, which detectors
    are expected to report. A system that only ever reports what supports its
    conclusion is not explaining, it is advocating.
    """

    signal: str
    observed: Any
    argues: str
    weight: float

    def as_dict(self) -> Dict[str, Any]:
        return {
            "signal": self.signal,
            "observed": self.observed,
            "argues": self.argues,
            "weight": round(float(self.weight), 4),
        }


@dataclass
class Signal:
    """One detector's opinion about one event."""

    detector: str
    score: float                      # 0.0 - 1.0, higher = more suspicious
    confidence: float                 # 0.0 - 1.0, how much to trust the score
    evidence: List[Evidence] = field(default_factory=list)
    #: Free-form detector state, e.g. whether a model was fitted yet. Reported
    #: so a cold-start score is never mistaken for a warm one.
    state: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.score = _clamp(self.score)
        self.confidence = _clamp(self.confidence)

    @property
    def top_evidence(self) -> List[Evidence]:
        return sorted(self.evidence, key=lambda e: abs(e.weight), reverse=True)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "score": round(self.score, 4),
            "confidence": round(self.confidence, 4),
            "evidence": [e.as_dict() for e in self.top_evidence],
            "state": self.state,
        }


class Detector(Protocol):
    """What every detector must provide."""

    name: str

    def analyse(
        self,
        features: Dict[str, float],
        norm: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Signal:
        ...


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return lo
    if v != v:                       # NaN
        return lo
    return max(lo, min(hi, v))
