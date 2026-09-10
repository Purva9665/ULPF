"""
Detection engine - features, detectors, fusion, and a verdict that explains itself.

Replaces the single-estimator `MLAnomalyEngine`. That engine remains in the
tree for the existing pipeline path; this is what the trained model and the
detections layer use.

Flow for one event:

    normalized event
        -> FeatureExtractor      (44 features, profiles updated after read)
        -> RuleDetector          deterministic, works on event one
        -> BehaviourDetector     against this entity's own baseline
        -> TemporalDetector      burst, failure runs, periodicity
        -> NoveltyDetector       ECOD + Isolation Forest
        -> FusionModel           calibrated probability
        -> Verdict + evidence

Every stage contributes evidence, and the verdict carries all of it. The point
is not that the number is right - it is that a reviewer can see what produced
the number and disagree with it specifically.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

from backend.ml.detectors import (
    BehaviourDetector,
    NoveltyDetector,
    RuleDetector,
    Signal,
    TemporalDetector,
)
from backend.ml.features import FeatureExtractor
from backend.ml.fusion import DETECTOR_ORDER, FusionModel, FusionVerdict
from backend.ml.profiles import ProfileStore


@dataclass
class Verdict:
    """Everything the system concluded about one event, and why."""

    event_id: str
    probability: float
    is_anomalous: bool
    risk_level: str
    mode: str
    signals: Dict[str, Signal] = field(default_factory=dict)
    fusion: Optional[FusionVerdict] = None
    evidence_quality: Dict[str, Any] = field(default_factory=dict)
    duration_us: int = 0

    def top_evidence(self, limit: int = 8) -> List[Dict[str, Any]]:
        items = []
        for name, signal in self.signals.items():
            for ev in signal.evidence:
                items.append({**ev.as_dict(), "detector": name})
        return sorted(items, key=lambda e: abs(e["weight"]), reverse=True)[:limit]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "probability": round(self.probability, 4),
            "is_anomalous": self.is_anomalous,
            "risk_level": self.risk_level,
            "mode": self.mode,
            "evidence_quality": self.evidence_quality,
            "signals": {k: v.as_dict() for k, v in self.signals.items()},
            "fusion": self.fusion.as_dict() if self.fusion else None,
            "top_evidence": self.top_evidence(),
            "duration_us": self.duration_us,
        }


class DetectionEngine:
    """Runs the detector ensemble and the fusion layer over normalized events."""

    def __init__(
        self,
        profiles: Optional[ProfileStore] = None,
        fusion: Optional[FusionModel] = None,
        use_confidence_features: bool = True,
    ):
        self.features = FeatureExtractor(
            profiles=profiles, use_confidence_features=use_confidence_features
        )
        self.rules = RuleDetector()
        self.behaviour = BehaviourDetector()
        self.temporal = TemporalDetector()
        self.novelty = NoveltyDetector(feature_names=self.features.feature_names)
        self.fusion = fusion or FusionModel(
            feature_names=self.features.feature_names,
            detector_order=DETECTOR_ORDER,
        )
        self._observed: List[List[float]] = []
        self._novelty_fit_cap = 20_000

    # -- single event --------------------------------------------------------

    def analyse(self, norm: Any, *, update_profiles: bool = True) -> Verdict:
        t0 = time.perf_counter_ns()

        vector, named = self.features.extract(norm, update_profiles=update_profiles)
        context = {"epoch": _epoch_of(norm)}

        signals: Dict[str, Signal] = {
            "rules": self.rules.analyse(named, norm, context),
            "behaviour": self.behaviour.analyse(named, norm, context),
            "temporal": self.temporal.analyse(named, norm, context),
            "novelty": self.novelty.analyse(named, norm, context),
        }
        fusion = self.fusion.fuse(named, signals)

        if update_profiles and len(self._observed) < self._novelty_fit_cap:
            self._observed.append(vector)

        quality = _evidence_quality(norm, named)
        probability = fusion.probability
        # USP-1 applied at the verdict, not just as a model input: a conclusion
        # resting on fields the parser was unsure about is reported as degraded
        # rather than presented with the same authority as a clean one.
        if quality["degraded"]:
            probability *= quality["reliability"]

        duration_us = (time.perf_counter_ns() - t0) // 1000
        return Verdict(
            event_id=getattr(norm, "event_id", ""),
            probability=probability,
            is_anomalous=probability >= self.fusion.threshold,
            risk_level=_risk_level(probability),
            mode=fusion.mode,
            signals=signals,
            fusion=fusion,
            evidence_quality=quality,
            duration_us=duration_us,
        )

    # -- unsupervised warm-up ------------------------------------------------

    def fit_novelty(self, vectors: Optional[Sequence[Sequence[float]]] = None) -> bool:
        """Fit the unsupervised layer on observed traffic.

        Separate from fusion training because it needs no labels: in a live
        deployment this is the part that keeps adapting to the network, while
        the fusion weights stay as shipped.
        """
        data = np.asarray(vectors if vectors is not None else self._observed,
                          dtype=float)
        if data.ndim != 2 or len(data) < self.novelty.min_fit_samples:
            return False
        self.novelty.fit(data)
        return self.novelty.fitted

    def stats(self) -> Dict[str, Any]:
        return {
            "features": self.features.describe(),
            "profiles": self.features.profiles.stats(),
            "novelty_fitted": self.novelty.fitted,
            "observations_buffered": len(self._observed),
            "fusion": self.fusion.describe(),
        }


def _evidence_quality(norm: Any, features: Dict[str, float]) -> Dict[str, Any]:
    """How much the fields this verdict rests on can be trusted (USP-1).

    `reliability` is deliberately floored: degraded parse quality should
    discount a conclusion, never erase it. An event we parsed badly is still an
    event that happened, and suppressing it entirely would turn a parsing gap
    into a blind spot - the opposite of what this mechanism is for.
    """
    quality = norm.parse_quality() if hasattr(norm, "parse_quality") else {}
    evidence_conf = features.get("evidence_field_confidence", 1.0)
    low_fields = quality.get("low_confidence_fields", [])
    degraded = bool(low_fields) or evidence_conf < 0.7
    return {
        "degraded": degraded,
        "reliability": round(max(0.6, evidence_conf), 4),
        "evidence_field_confidence": round(evidence_conf, 4),
        "low_confidence_fields": low_fields,
        "mean_field_confidence": quality.get("mean_confidence", 1.0),
        "unmapped_field_count": quality.get("fields_unmapped", 0),
    }


def _epoch_of(norm: Any) -> float:
    from backend.ml.features import _timestamp_parts
    try:
        return _timestamp_parts(norm)[0]
    except Exception:
        return 0.0


def _risk_level(p: float) -> str:
    if p >= 0.80:
        return "CRITICAL"
    if p >= 0.60:
        return "HIGH"
    if p >= 0.35:
        return "MEDIUM"
    return "LOW"
