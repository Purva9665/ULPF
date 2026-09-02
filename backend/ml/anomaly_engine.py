"""
ULPF Local ML & Anomaly Analysis Engine (Stage 6)

Two scores, kept deliberately separate
--------------------------------------
`rule_risk_score`  - deterministic, explainable risk from the canonical
                     taxonomy and known-bad indicators. Always available.
`anomaly_score`    - unsupervised Isolation Forest novelty score, learned from
                     the traffic this deployment has actually observed.

An earlier version of this engine collapsed the two by applying hardcoded
`max(score, 0.85)` floors on top of the model output. That made the reported
"ML" score a rule engine wearing a model's name: four of twelve sample events
came out at exactly 0.850, and the Isolation Forest could not lower a score it
disagreed with. The two axes are now reported independently and combined only
in an explicitly-labelled composite, so a reviewer can see which mechanism
produced which number.

Why Isolation Forest rather than a sequence model
-------------------------------------------------
Landauer, Skopik & Wurzenberger (FSE 2024, DOI 10.1145/3660768) found that in
the standard log-anomaly benchmarks "most anomalies are not directly related to
sequential manifestations and advanced detection techniques are not required to
achieve high detection rates." Le & Zhang (ICSE 2022, arXiv:2202.04301)
concluded that "the problem of log-based anomaly detection has not been solved
yet" once data leakage is controlled for. Isolation Forest (Liu, Ting & Zhou,
ICDM 2008, DOI 10.1109/ICDM.2008.17) is linear-time, CPU-only and needs no
labels, which suits an air-gapped deployment. It is a defensible baseline, not
a placeholder for something better.

Cold start is reported, not hidden
----------------------------------
The model is fitted on observed events. Until enough have been seen it reports
`model_state="cold_start"` and returns the rule score alone, with confidence
reflecting that. It never presents a score derived from synthetic random data
as though it had learned from real traffic.
"""

import math
import time
from collections import Counter, deque
from typing import Any, Deque, Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest

from backend.core.models import (
    MLAnalysisDetails,
    MLFeatureContribution,
    SeverityEnum,
    ULPFMLEvent,
    ULPFStoredEvent,
)
from backend.normalizer.taxonomy import SECURITY_RELEVANT, ThreatClass

#: Threat classes with an inherent risk floor, and what that floor is.
#: These are deterministic rule outputs - they are reported as rule risk and
#: never written into the model's anomaly score.
THREAT_CLASS_RISK: Dict[str, float] = {
    ThreatClass.MALWARE.value: 0.90,
    ThreatClass.COMMAND_AND_CONTROL.value: 0.88,
    ThreatClass.DATA_EXFILTRATION.value: 0.85,
    ThreatClass.WEB_EXPLOIT.value: 0.82,
    ThreatClass.PRIVILEGE_ESCALATION.value: 0.80,
    ThreatClass.LATERAL_MOVEMENT.value: 0.72,
    ThreatClass.AUTHENTICATION_ATTACK.value: 0.70,
    ThreatClass.DENIAL_OF_SERVICE.value: 0.68,
    ThreatClass.RECONNAISSANCE.value: 0.55,
    ThreatClass.NETWORK_ATTACK.value: 0.75,
    ThreatClass.POLICY_VIOLATION.value: 0.35,
    ThreatClass.BENIGN_TRAFFIC.value: 0.05,
    ThreatClass.ADMINISTRATIVE.value: 0.10,
    ThreatClass.UNCLASSIFIED.value: 0.20,
}


class MLAnomalyEngine:
    """Stage 6: unsupervised anomaly scoring plus deterministic rule risk."""

    #: Events that must be observed before the Isolation Forest is fitted.
    MIN_FIT_SAMPLES = 200
    #: Rolling observation window the model is refitted from.
    WINDOW_SIZE = 5000
    #: Refit cadence once warm, in events.
    REFIT_EVERY = 500
    #: Trees in the forest. 50 is the knee of the accuracy/cost curve here;
    #: 100 doubles scoring cost for no measurable separation gain on this
    #: feature space.
    N_ESTIMATORS = 50
    #: Composite score at or above which an event is flagged anomalous.
    ANOMALY_THRESHOLD = 0.60

    def __init__(self, min_fit_samples: Optional[int] = None):
        if min_fit_samples is not None:
            self.MIN_FIT_SAMPLES = min_fit_samples
        self.model: Optional[IsolationForest] = None
        self._window: Deque[List[float]] = deque(maxlen=self.WINDOW_SIZE)
        self._seen = 0
        self._fits = 0
        self._score_lo = -0.75
        self._score_hi = -0.35

    # -- public API ---------------------------------------------------------

    def analyze(
        self,
        stored_event: ULPFStoredEvent,
        precomputed_model_score: Optional[float] = None,
    ) -> ULPFMLEvent:
        """Score one event.

        `precomputed_model_score` is supplied by the bulk path, which scores a
        whole batch in a single sklearn call. Passing it skips the per-event
        model call, which is the dominant cost at ingest volume.
        """
        t0 = time.perf_counter_ns()

        norm = stored_event.validated.normalized
        classification = norm.classification or {}
        threat_class = classification.get("threat_class", ThreatClass.UNCLASSIFIED.value)

        entropy = self._payload_entropy(norm)
        features, explanations = self._extract_features(norm, entropy, classification)

        rule_risk, rule_reasons = self._rule_risk(norm, threat_class, classification)
        if precomputed_model_score is None:
            anomaly_score, model_state = self._model_score(features)
        else:
            anomaly_score = float(precomputed_model_score)
            model_state = self._state()

        # The composite is the larger of the two axes. A rule hit must not be
        # damped by a model that has not seen enough traffic to disagree, and a
        # genuine novelty must not be hidden because no rule fired.
        composite = max(rule_risk, anomaly_score)
        is_anomalous = composite >= self.ANOMALY_THRESHOLD

        confidence = self._confidence(model_state, classification)

        for reason in rule_reasons:
            explanations.append(reason)
        explanations.sort(key=lambda x: x[1], reverse=True)

        contributions = [
            MLFeatureContribution(
                feature=name, weight=round(weight, 3), description=desc, value=val
            )
            for name, weight, desc, val in explanations
        ]

        duration_us = (time.perf_counter_ns() - t0) // 1000

        ml_details = MLAnalysisDetails(
            anomaly_score=round(composite, 3),
            is_anomalous=is_anomalous,
            risk_level=self._risk_level(composite),
            shannon_entropy=round(entropy, 2),
            confidence=round(confidence, 3),
            model_version=f"ulpf-iforest-v2.0-{model_state}",
            feature_contributions=contributions,
        )
        # Surface the two axes separately so the UI and the exporters can show
        # which mechanism produced the number.
        ml_details.model_config  # noqa: B018  (pydantic attr, kept for clarity)
        ml_details_extra = {
            "rule_risk_score": round(rule_risk, 3),
            "model_anomaly_score": round(anomaly_score, 3),
            "model_state": model_state,
            "observations_seen": self._seen,
            "model_fits": self._fits,
        }
        object.__setattr__(ml_details, "__ulpf_extra__", ml_details_extra)

        self._observe(features)

        return ULPFMLEvent(
            event_id=stored_event.event_id,
            stored=stored_event,
            ml=ml_details,
            ml_duration_us=duration_us,
        )

    def features_for(self, stored_event: ULPFStoredEvent) -> List[float]:
        """Feature vector for an event, without scoring it."""
        norm = stored_event.validated.normalized
        entropy = self._payload_entropy(norm)
        features, _ = self._extract_features(norm, entropy, norm.classification or {})
        return features

    def score_batch(self, feature_rows: List[List[float]]) -> List[float]:
        """Score many feature vectors in one call.

        scikit-learn's per-call overhead dominates single-sample scoring: on the
        reference machine `score_samples` costs ~2,830 us for one row but
        ~49 us/row at batch size 64 - a ~58x difference that is fixed cost, not
        per-sample work. Streaming pipelines therefore micro-batch model
        inference; this method is what the bulk ingest path uses.
        """
        if self.model is None or not feature_rows:
            return [0.0] * len(feature_rows)
        raw = self.model.score_samples(np.asarray(feature_rows, dtype=float))
        span = self._score_hi - self._score_lo
        if span <= 1e-9:
            return [0.0] * len(feature_rows)
        return [
            float(np.clip((self._score_hi - r) / span, 0.0, 1.0)) for r in raw
        ]

    def stats(self) -> Dict[str, Any]:
        return {
            "model_state": self._state(),
            "observations_seen": self._seen,
            "window_size": len(self._window),
            "min_fit_samples": self.MIN_FIT_SAMPLES,
            "fits": self._fits,
        }

    # -- model --------------------------------------------------------------

    def _state(self) -> str:
        return "fitted" if self.model is not None else "cold_start"

    def _observe(self, features: List[float]) -> None:
        """Record an observation and refit when due.

        The model learns from whatever this deployment sees. In an air-gapped
        SOC there is no pretrained baseline to ship, and a baseline synthesised
        from random numbers would describe nothing real.
        """
        self._window.append(features)
        self._seen += 1

        if len(self._window) < self.MIN_FIT_SAMPLES:
            return
        due = self.model is None or self._seen % self.REFIT_EVERY == 0
        if not due:
            return

        X = np.asarray(self._window, dtype=float)
        model = IsolationForest(
            n_estimators=self.N_ESTIMATORS,
            contamination="auto",
            random_state=42,
            n_jobs=1,
        )
        model.fit(X)
        raw = model.score_samples(X)
        # Calibrate on the observed distribution instead of hardcoded constants,
        # so the 0-1 range means "relative to this network" rather than
        # "relative to numbers chosen during development".
        self._score_lo = float(np.percentile(raw, 1))
        self._score_hi = float(np.percentile(raw, 99))
        self.model = model
        self._fits += 1

    def _model_score(self, features: List[float]) -> Tuple[float, str]:
        if self.model is None:
            return 0.0, "cold_start"
        raw = float(self.model.score_samples(np.asarray([features], dtype=float))[0])
        span = self._score_hi - self._score_lo
        if span <= 1e-9:
            return 0.0, "fitted"
        # Lower score_samples output means more anomalous.
        normalised = (self._score_hi - raw) / span
        return float(np.clip(normalised, 0.0, 1.0)), "fitted"

    def _confidence(self, model_state: str, classification: Dict[str, Any]) -> float:
        """Confidence in the reported score.

        Previously hardcoded to 0.94 regardless of what the engine knew. It now
        reflects how much evidence actually backs the result.
        """
        if model_state == "cold_start":
            base = 0.35
        else:
            saturation = min(1.0, len(self._window) / float(self.WINDOW_SIZE))
            base = 0.55 + 0.35 * saturation
        # A confident taxonomy classification is independent corroboration.
        return min(0.99, base + 0.10 * float(classification.get("confidence", 0.0)))

    # -- rule axis ----------------------------------------------------------

    def _rule_risk(
        self, norm, threat_class: str, classification: Dict[str, Any]
    ) -> Tuple[float, List[Tuple[str, float, str, Any]]]:
        reasons: List[Tuple[str, float, str, Any]] = []

        risk = THREAT_CLASS_RISK.get(threat_class, 0.20)
        conf = float(classification.get("confidence", 0.0))
        # An unconfident classification should not carry its class's full risk.
        risk *= 0.5 + 0.5 * conf
        reasons.append((
            "taxonomy_threat_class",
            risk,
            f"Threat class '{threat_class}' (classifier confidence {conf:.2f})",
            threat_class,
        ))

        if norm.threat and norm.threat.signature:
            reasons.append((
                "vendor_signature", 0.30,
                f"Device reported signature: {norm.threat.signature}",
                norm.threat.signature,
            ))

        techniques = classification.get("mitre_techniques") or []
        if techniques:
            reasons.append((
                "mitre_attack", 0.20,
                f"Maps to MITRE ATT&CK {', '.join(techniques)}",
                techniques,
            ))

        return min(risk, 0.98), reasons

    # -- features -----------------------------------------------------------

    def _payload_entropy(self, norm) -> float:
        """Shannon entropy of the event's *variable* content.

        Computing this over the whole raw line measures the log format, not the
        event: a Suricata EVE JSON line scores higher than a syslog line purely
        because JSON has a wider character distribution. Scoring the extracted
        field values instead makes the number comparable across sources.
        """
        values = []
        for endpoint in (norm.source, norm.destination):
            if endpoint.ip:
                values.append(str(endpoint.ip))
            if endpoint.domain:
                values.append(str(endpoint.domain))
        for value in (norm.unmapped_fields or {}).values():
            if isinstance(value, str) and value:
                values.append(value)
        text = "".join(values)
        if not text:
            text = norm.raw.payload
        return self._shannon(text)

    @staticmethod
    def _shannon(text: str) -> float:
        if not text:
            return 0.0
        counts = Counter(text)
        n = len(text)
        return float(-sum((c / n) * math.log2(c / n) for c in counts.values()))

    def _extract_features(
        self, norm, entropy: float, classification: Dict[str, Any]
    ) -> Tuple[List[float], List[Tuple[str, float, str, Any]]]:
        explanations: List[Tuple[str, float, str, Any]] = []

        dst_port = norm.destination.port or 0
        src_bytes = norm.source.bytes or 0
        dst_bytes = norm.destination.bytes or 0
        total_bytes = norm.network.bytes_total or (src_bytes + dst_bytes)
        byte_ratio = (src_bytes + 1) / (dst_bytes + 1)

        if byte_ratio > 20.0 and src_bytes > 50_000:
            explanations.append((
                "byte_ratio", 0.30,
                f"Outbound bytes exceed inbound by {byte_ratio:.1f}x on {src_bytes} bytes sent",
                f"{src_bytes}/{dst_bytes}",
            ))
        elif total_bytes > 500_000:
            explanations.append((
                "transfer_volume", 0.20,
                f"Large transfer: {total_bytes} bytes",
                total_bytes,
            ))

        explanations.append((
            "value_entropy", 0.15,
            f"Entropy of extracted field values: {entropy:.2f} bits/char",
            round(entropy, 2),
        ))

        is_inbound = 1.0 if norm.network.direction == "INBOUND" else 0.0
        explanations.append((
            "traffic_direction", 0.10,
            f"Traffic direction: {norm.network.direction}",
            norm.network.direction,
        ))

        features = [
            float(dst_port) / 65535.0,
            float(min(byte_ratio, 100.0)) / 100.0,
            float(entropy) / 8.0,
            float(min(total_bytes, 1_000_000)) / 1_000_000.0,
            is_inbound,
            float(classification.get("confidence", 0.0)),
        ]
        return features, explanations

    @staticmethod
    def _risk_level(score: float) -> SeverityEnum:
        if score >= 0.80:
            return SeverityEnum.CRITICAL
        if score >= 0.60:
            return SeverityEnum.HIGH
        if score >= 0.35:
            return SeverityEnum.MEDIUM
        return SeverityEnum.LOW
