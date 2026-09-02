"""ULPF Event Router - SIEM vs Data Lake classification logic.

Routing criteria (any match -> SIEM):
  1. ML anomaly score >= 0.60
  2. Security event category (network_attack, auth_attack, etc.)
  3. Block/Deny action
  4. High-risk destination port (22, 445, 3389, etc.)
  5. HIGH or CRITICAL severity

All events always go to Data Lake regardless of SIEM routing.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from backend.normalizer.taxonomy import SECURITY_RELEVANT, ThreatClass


@dataclass
class RoutingDecision:
    """Result of classifying one processed event."""
    siem: bool
    data_lake: bool = True
    reasons: List[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return "SIEM + Data Lake" if self.siem else "Data Lake only"


class EventRouter:
    """
    Routes each processed event to SIEM and/or Data Lake.
    Data Lake always receives ALL events.
    SIEM receives only security-relevant events.
    """

    ANOMALY_THRESHOLD: float = 0.60

    #: Derived from the canonical taxonomy so the router and the classifier can
    #: never drift apart. Previously this was a hand-maintained string list that
    #: matched nothing the normalizer actually emitted.
    SIEM_CATEGORIES: frozenset = frozenset(t.value for t in SECURITY_RELEVANT)

    SIEM_ACTIONS: frozenset = frozenset({
        "deny", "denied", "block", "blocked",
        "drop", "dropped", "reject", "rejected",
        "alert", "alerted", "quarantine", "reset",
    })

    HIGH_RISK_PORTS: frozenset = frozenset({
        22, 23, 445, 3389, 6379, 1433, 3306, 5432,
        27017, 2375, 4444,
    })

    def classify(
        self,
        anomaly_score: float,
        category: str = "",
        action: str = "",
        dst_port: Optional[int] = None,
        severity: str = "",
    ) -> RoutingDecision:
        """Classify a single event and return a routing decision."""
        reasons: List[str] = []
        to_siem = False

        if anomaly_score >= self.ANOMALY_THRESHOLD:
            to_siem = True
            reasons.append(
                "ML anomaly score {:.3f} >= threshold {:.2f}".format(
                    anomaly_score, self.ANOMALY_THRESHOLD
                )
            )

        cat_lower = (category or "").lower().replace(" ", "_").replace("-", "_")
        if cat_lower in self.SIEM_CATEGORIES:
            to_siem = True
            reasons.append("Threat class '{}' is security-relevant".format(cat_lower))

        action_lower = (action or "").lower()
        if action_lower in self.SIEM_ACTIONS:
            to_siem = True
            reasons.append("Action '{}' is a security enforcement action".format(action))

        classified_benign = cat_lower in (
            ThreatClass.BENIGN_TRAFFIC.value, ThreatClass.UNCLASSIFIED.value
        )
        if dst_port is not None and dst_port in self.HIGH_RISK_PORTS and not classified_benign:
            to_siem = True
            reasons.append("Destination port {} is a high-risk service port".format(dst_port))

        if (severity or "").upper() in ("HIGH", "CRITICAL"):
            to_siem = True
            reasons.append("Severity '{}' meets SIEM threshold".format(severity))

        return RoutingDecision(siem=to_siem, data_lake=True, reasons=reasons)


default_router = EventRouter()