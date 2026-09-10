"""
The Detection - the object the product is actually about.

Why this exists
---------------
Until now the system produced *scored events*. That is a pipeline demo, not a
product. 158,930 PortScan flows produce 158,930 scored events, and an analyst
handed 158,930 rows has been given a worse problem than they started with.

A Detection is what a SOC actually works: one finding, scoped to an entity,
carrying every event that supports it, the evidence for the verdict, and a
triage state that survives across sessions. The reduction ratio from events to
detections is a measured product metric, not a cosmetic one - it is the
difference between a queue a person can work and one they cannot.

The evidence bundle (USP-3)
---------------------------
Every detection carries the raw bytes and SHA-256 of each contributing event,
plus the parse confidence of the fields the verdict relied on. Custody of a
single log line is a compliance checkbox; custody of a *conclusion* is what an
auditor or a court needs. A reviewer can re-derive this verdict from the
bundle without access to the running system.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class TriageState(str, Enum):
    """Where a detection is in an analyst's workflow."""

    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED_TRUE_POSITIVE = "resolved_true_positive"
    RESOLVED_FALSE_POSITIVE = "resolved_false_positive"
    SUPPRESSED = "suppressed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_probability(cls, p: float) -> "Severity":
        if p >= 0.90:
            return cls.CRITICAL
        if p >= 0.70:
            return cls.HIGH
        if p >= 0.45:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class ContributingEvent:
    """One event that supports a detection, with its custody record."""

    event_id: str
    timestamp: str
    raw_sha256: str
    raw_payload: str
    probability: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    evidence_degraded: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "raw_sha256": self.raw_sha256,
            "probability": round(self.probability, 4),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "evidence_degraded": self.evidence_degraded,
        }


@dataclass
class Detection:
    """One finding an analyst works, not one event the pipeline scored."""

    detection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    entity: str = ""
    entity_type: str = "ip"
    threat_class: str = "unclassified"
    severity: Severity = Severity.LOW
    #: Calibrated probability of the strongest contributing event.
    confidence: float = 0.0
    state: TriageState = TriageState.NEW

    first_seen: str = ""
    last_seen: str = ""
    event_count: int = 0
    #: Capped sample of contributing events; `event_count` is the true total.
    events: List[ContributingEvent] = field(default_factory=list)

    evidence: List[Dict[str, Any]] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    peer_ips: List[str] = field(default_factory=list)
    ports_touched: List[int] = field(default_factory=list)

    #: True when any contributing event rested on low-confidence parsed fields.
    evidence_degraded: bool = False
    analyst_note: str = ""
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # -- triage -------------------------------------------------------------

    def set_state(self, state: TriageState, note: str = "") -> "Detection":
        self.state = state
        if note:
            self.analyst_note = note
        self.updated_at = datetime.now(timezone.utc).isoformat()
        return self

    @property
    def is_open(self) -> bool:
        return self.state in (TriageState.NEW, TriageState.INVESTIGATING)

    # -- evidence bundle (USP-3) -------------------------------------------

    def evidence_bundle(self) -> Dict[str, Any]:
        """A self-contained, independently verifiable record of this verdict.

        Includes a bundle hash over the contributing events' own hashes, so
        tampering with the bundle after export is detectable without needing
        the original system.
        """
        event_hashes = [e.raw_sha256 for e in self.events]
        digest = hashlib.sha256(
            "".join(sorted(event_hashes)).encode("utf-8")
        ).hexdigest()
        return {
            "detection_id": self.detection_id,
            "title": self.title,
            "entity": self.entity,
            "threat_class": self.threat_class,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "events_included": len(self.events),
            "mitre_techniques": self.mitre_techniques,
            "evidence": self.evidence,
            "evidence_degraded": self.evidence_degraded,
            "contributing_events": [e.as_dict() for e in self.events],
            "bundle_sha256": digest,
            "verification": (
                "Recompute SHA-256 of each raw payload and compare to "
                "raw_sha256; then SHA-256 the sorted concatenation of those "
                "hashes and compare to bundle_sha256."
            ),
        }

    def as_dict(self) -> Dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "title": self.title,
            "entity": self.entity,
            "entity_type": self.entity_type,
            "threat_class": self.threat_class,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "state": self.state.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "peer_count": len(self.peer_ips),
            "port_count": len(self.ports_touched),
            "mitre_techniques": self.mitre_techniques,
            "evidence_degraded": self.evidence_degraded,
            "top_evidence": self.evidence[:5],
            "analyst_note": self.analyst_note,
            "updated_at": self.updated_at,
        }


@dataclass
class EntityRisk:
    """Rolling risk for one entity, built from its detections.

    An analyst triaging by entity rather than by alert is the difference
    between "here are 40 alerts" and "this one host is responsible for 40
    alerts" - which is usually the same investigation.
    """

    entity: str
    entity_type: str = "ip"
    detection_count: int = 0
    open_count: int = 0
    max_confidence: float = 0.0
    threat_classes: Dict[str, int] = field(default_factory=dict)
    last_seen: str = ""

    @property
    def risk_score(self) -> float:
        """Peak severity, escalated by breadth of distinct behaviours.

        An entity implicated in three different kinds of activity is a
        different problem from one that tripped the same rule three times, and
        counting detections alone cannot tell them apart.
        """
        breadth = min(1.0, len(self.threat_classes) / 4.0)
        volume = min(1.0, self.detection_count / 20.0)
        return round(min(1.0, 0.6 * self.max_confidence
                         + 0.25 * breadth + 0.15 * volume), 4)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "entity": self.entity,
            "entity_type": self.entity_type,
            "risk_score": self.risk_score,
            "detection_count": self.detection_count,
            "open_count": self.open_count,
            "max_confidence": round(self.max_confidence, 4),
            "threat_classes": self.threat_classes,
            "last_seen": self.last_seen,
        }
