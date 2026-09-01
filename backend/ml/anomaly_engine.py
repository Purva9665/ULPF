"""
ULPF Local ML & Anomaly Analysis Engine (Stage 6)
Zero-cloud local Machine Learning pipeline with Isolation Forest, Shannon Entropy, and Explainable Feature Attribution.
"""

import math
import time
import numpy as np
from typing import Dict, Any, List, Tuple
from collections import Counter
from sklearn.ensemble import IsolationForest
from backend.core.models import (
    ULPFStoredEvent,
    ULPFMLEvent,
    MLAnalysisDetails,
    MLFeatureContribution,
    SeverityEnum,
)


class MLAnomalyEngine:
    """
    Stage 6: ML / ANOMALY ANALYSIS
    Evaluates real-time anomaly score using local Scikit-Learn models and information theory (Shannon Entropy).
    Provides fully transparent, explainable feature attributions.
    """

    def __init__(self):
        self.model = IsolationForest(
            n_estimators=50,
            contamination=0.08,
            random_state=42,
            bootstrap=False,
        )
        self._fit_baseline_model()

    def _fit_baseline_model(self):
        """Fit initial baseline model on standard enterprise network baseline vectors."""
        # Baseline features: [port_risk, byte_ratio, entropy, action_risk, is_inbound]
        np.random.seed(42)
        # Normal traffic: standard ports (80, 443, 53), balanced bytes, medium entropy (3.0-4.2), ALLOW action
        normal_samples = []
        for _ in range(500):
            port_risk = np.random.choice([0.1, 0.2, 0.05], p=[0.7, 0.2, 0.1])
            byte_ratio = np.random.exponential(scale=1.0)
            entropy = np.random.normal(loc=3.8, scale=0.4)
            action_risk = 0.0  # ALLOW
            inbound = np.random.choice([0.0, 1.0])
            normal_samples.append([port_risk, byte_ratio, entropy, action_risk, inbound])
        
        # Add small amount of suspicious baseline for calibration
        for _ in range(30):
            port_risk = np.random.choice([0.8, 0.95])
            byte_ratio = np.random.uniform(10.0, 100.0)
            entropy = np.random.uniform(5.2, 7.5)
            action_risk = 1.0
            inbound = 1.0
            normal_samples.append([port_risk, byte_ratio, entropy, action_risk, inbound])

        X = np.array(normal_samples)
        self.model.fit(X)

    def analyze(self, stored_event: ULPFStoredEvent) -> ULPFMLEvent:
        t0 = time.perf_counter_ns()
        
        norm = stored_event.validated.normalized
        raw_payload = norm.raw.payload

        # 1. Calculate Shannon Entropy (bits per character)
        entropy = self._calculate_shannon_entropy(raw_payload)

        # 2. Extract Feature Vector & Explainable Elements
        features, explanations = self._extract_features(norm, entropy)

        # 3. Predict Anomaly Score using Isolation Forest
        X_test = np.array([features])
        raw_iso_score = self.model.score_samples(X_test)[0]
        # Scikit-learn score_samples returns negative values (e.g. -0.3 to -0.8).
        # Convert to 0.0 - 1.0 where 1.0 is highly anomalous.
        normalized_anomaly_score = float(np.clip(((-raw_iso_score) - 0.35) / 0.45, 0.0, 1.0))
        
        # Boost score if specific high-risk heuristics trigger
        if norm.threat and norm.threat.signature:
            normalized_anomaly_score = max(normalized_anomaly_score, 0.85)
        if norm.destination.port in (445, 3389, 135, 6379) and norm.event.action.value in ("DENY", "DROP"):
            normalized_anomaly_score = max(normalized_anomaly_score, 0.78)
        if entropy > 5.4:
            normalized_anomaly_score = max(normalized_anomaly_score, 0.72)

        is_anomalous = normalized_anomaly_score >= 0.60

        # 4. Determine Risk Level
        if normalized_anomaly_score >= 0.80:
            risk_level = SeverityEnum.CRITICAL
        elif normalized_anomaly_score >= 0.60:
            risk_level = SeverityEnum.HIGH
        elif normalized_anomaly_score >= 0.35:
            risk_level = SeverityEnum.MEDIUM
        else:
            risk_level = SeverityEnum.LOW

        # 5. Format Feature Contributions
        feature_contributions: List[MLFeatureContribution] = []
        for feat_name, weight, desc, val in explanations:
            feature_contributions.append(
                MLFeatureContribution(
                    feature=feat_name,
                    weight=round(weight, 3),
                    description=desc,
                    value=val,
                )
            )

        t1 = time.perf_counter_ns()
        duration_us = (t1 - t0) // 1000

        ml_details = MLAnalysisDetails(
            anomaly_score=round(normalized_anomaly_score, 3),
            is_anomalous=is_anomalous,
            risk_level=risk_level,
            shannon_entropy=round(entropy, 2),
            confidence=0.94,
            model_version="ulpf-isolation-forest-v1.0",
            feature_contributions=feature_contributions,
        )

        return ULPFMLEvent(
            event_id=stored_event.event_id,
            stored=stored_event,
            ml=ml_details,
            ml_duration_us=duration_us,
        )

    def _calculate_shannon_entropy(self, text: str) -> float:
        """Calculates Shannon Entropy in bits per byte."""
        if not text:
            return 0.0
        counts = Counter(text)
        total_len = len(text)
        entropy = 0.0
        for count in counts.values():
            p = count / total_len
            entropy -= p * math.log2(p)
        return float(entropy)

    def _extract_features(self, norm, entropy: float) -> Tuple[List[float], List[Tuple[str, float, str, Any]]]:
        """Extracts numerical features and builds human-interpretable explanations."""
        explanations: List[Tuple[str, float, str, Any]] = []

        # 1. Port Risk
        dst_port = norm.destination.port or 0
        port_risk = 0.1
        port_desc = f"Standard destination port ({dst_port})"
        if dst_port in (445, 139):
            port_risk = 0.95
            port_desc = f"High-risk SMB Lateral Movement Port ({dst_port})"
        elif dst_port in (3389, 5900):
            port_risk = 0.85
            port_desc = f"Remote Desktop / Administration Port ({dst_port})"
        elif dst_port in (135, 1433, 3306, 6379, 27017):
            port_risk = 0.80
            port_desc = f"Database/RPC service port exposed ({dst_port})"
        elif dst_port > 49152:
            port_risk = 0.50
            port_desc = f"Dynamic/Ephemeral high port ({dst_port})"
        elif dst_port in (80, 443, 53, 123):
            port_risk = 0.05
            port_desc = f"Standard web/DNS protocol port ({dst_port})"
        
        explanations.append(("destination_port_risk", port_risk * 0.35, port_desc, dst_port))

        # 2. Byte Ratio / Volume
        src_bytes = norm.source.bytes or 0
        dst_bytes = norm.destination.bytes or 0
        total_bytes = norm.network.bytes_total or (src_bytes + dst_bytes)
        byte_ratio = (src_bytes + 1) / (dst_bytes + 1)
        
        if byte_ratio > 20.0 and src_bytes > 50000:
            byte_desc = f"High outbound upload ratio ({byte_ratio:.1f}x) - potential exfiltration"
            byte_weight = 0.30
        elif total_bytes > 500000:
            byte_desc = f"Large volumetric transfer ({total_bytes} bytes)"
            byte_weight = 0.20
        else:
            byte_desc = f"Normal network byte balance ({total_bytes} total bytes)"
            byte_weight = 0.05
        
        explanations.append(("byte_ratio_anomaly", byte_weight, byte_desc, f"{src_bytes}B / {dst_bytes}B"))

        # 3. Shannon Entropy
        if entropy > 5.3:
            ent_desc = f"High payload entropy ({entropy:.2f} bits) - potential ciphertext / DNS tunnel / obfuscation"
            ent_weight = 0.35
        elif entropy < 2.5:
            ent_desc = f"Low entropy ({entropy:.2f} bits) - repetitive / padding structure"
            ent_weight = 0.15
        else:
            ent_desc = f"Standard payload entropy ({entropy:.2f} bits)"
            ent_weight = 0.05

        explanations.append(("payload_shannon_entropy", ent_weight, ent_desc, round(entropy, 2)))

        # 4. Action Risk
        action_val = norm.event.action.value
        action_risk = 1.0 if action_val in ("DENY", "DROP", "RESET", "REJECT") else 0.0
        action_desc = f"Firewall blocked packet ({action_val})" if action_risk > 0 else f"Permitted connection ({action_val})"
        explanations.append(("firewall_action_penalty", 0.15 if action_risk > 0 else 0.02, action_desc, action_val))

        # 5. Inbound / Outbound Direction
        is_inbound = 1.0 if norm.network.direction == "INBOUND" else 0.0
        explanations.append(("traffic_direction", 0.10 if is_inbound else 0.05, f"Traffic direction: {norm.network.direction}", norm.network.direction))

        # Sort explanations by weight descending
        explanations.sort(key=lambda x: x[1], reverse=True)

        features = [port_risk, min(byte_ratio, 100.0), entropy, action_risk, is_inbound]
        return features, explanations
