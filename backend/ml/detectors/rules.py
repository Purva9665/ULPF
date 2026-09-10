"""
Deterministic rule detector.

The floor of the system. It needs no training, no baseline and no warm-up, so
it works on the first event after deployment - which matters, because an
air-gapped SOC does not get to wait 5,000 events before the product does
anything.

It is deliberately kept *separate* from the learned layers rather than blended
into them. An earlier version of this codebase applied hardcoded
`max(score, 0.85)` floors on top of the model output, which made the reported
"ML score" a rule engine wearing a model's name and left the model unable to
lower a score it disagreed with. Keeping the axes separate means a reviewer can
always see which mechanism produced which number.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from backend.ml.detectors.base import Evidence, Signal
from backend.normalizer.taxonomy import ThreatClass

#: Inherent risk of a threat class, before any evidence about this event.
#: These are priors about what a class *means*, not learned quantities.
THREAT_CLASS_RISK: Dict[str, float] = {
    ThreatClass.MALWARE.value: 0.90,
    ThreatClass.COMMAND_AND_CONTROL.value: 0.88,
    ThreatClass.DATA_EXFILTRATION.value: 0.85,
    ThreatClass.WEB_EXPLOIT.value: 0.82,
    ThreatClass.PRIVILEGE_ESCALATION.value: 0.80,
    ThreatClass.NETWORK_ATTACK.value: 0.75,
    ThreatClass.LATERAL_MOVEMENT.value: 0.72,
    ThreatClass.AUTHENTICATION_ATTACK.value: 0.70,
    ThreatClass.DENIAL_OF_SERVICE.value: 0.68,
    ThreatClass.RECONNAISSANCE.value: 0.55,
    ThreatClass.POLICY_VIOLATION.value: 0.35,
    ThreatClass.UNCLASSIFIED.value: 0.20,
    ThreatClass.ADMINISTRATIVE.value: 0.10,
    ThreatClass.BENIGN_TRAFFIC.value: 0.05,
}


class RuleDetector:
    """Deterministic risk from the canonical taxonomy and known indicators."""

    name = "rules"

    def analyse(
        self,
        features: Dict[str, float],
        norm: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Signal:
        classification = getattr(norm, "classification", None) or {}
        threat_class = classification.get("threat_class", ThreatClass.UNCLASSIFIED.value)
        class_confidence = float(classification.get("confidence", 0.0))

        evidence = []
        base = THREAT_CLASS_RISK.get(threat_class, 0.20)
        # An unconfident classification should not carry its class's full risk.
        score = base * (0.5 + 0.5 * class_confidence)
        evidence.append(Evidence(
            signal="taxonomy_threat_class",
            observed=threat_class,
            argues=f"Classified as '{threat_class}' with classifier confidence "
                   f"{class_confidence:.2f}",
            weight=score,
        ))

        threat = getattr(norm, "threat", None)
        if threat is not None and getattr(threat, "signature", None):
            score = max(score, 0.75)
            evidence.append(Evidence(
                signal="vendor_signature",
                observed=threat.signature,
                argues="The device itself reported a matching threat signature",
                weight=0.30,
            ))

        techniques = classification.get("mitre_techniques") or []
        if techniques:
            evidence.append(Evidence(
                signal="mitre_attack",
                observed=techniques,
                argues=f"Maps to MITRE ATT&CK {', '.join(techniques)}",
                weight=0.20,
            ))

        if features.get("action_is_denied", 0.0) >= 1.0:
            evidence.append(Evidence(
                signal="device_action",
                observed="denied",
                argues="The perimeter device refused this connection",
                weight=0.15,
            ))
            score = min(1.0, score + 0.05)

        if features.get("dst_port_is_sensitive", 0.0) >= 1.0:
            port = getattr(getattr(norm, "destination", None), "port", None)
            evidence.append(Evidence(
                signal="sensitive_port",
                observed=port,
                argues=f"Port {port} is a common remote-access or database service",
                weight=0.10,
            ))

        # Evidence against, reported as such.
        if threat_class == ThreatClass.BENIGN_TRAFFIC.value and class_confidence > 0.7:
            evidence.append(Evidence(
                signal="benign_classification",
                observed=round(class_confidence, 2),
                argues="Confidently classified as ordinary traffic",
                weight=-0.30,
            ))

        # Rules are certain about what they encode, but what they encode is a
        # prior about a class - not knowledge about this specific event. The
        # confidence reported reflects how strongly the classifier committed.
        confidence = 0.55 + 0.40 * class_confidence

        return Signal(
            detector=self.name,
            score=score,
            confidence=confidence,
            evidence=evidence,
            state={"threat_class": threat_class},
        )
