"""
Correlation - turning scored events into detections an analyst can work.

The problem being solved
------------------------
A port scan is one thing that happened. It produces tens of thousands of
events. Presenting those as tens of thousands of alerts is not a detection
system; it is a denial-of-service attack on the analyst. Alert fatigue is the
best-documented failure mode in security operations, and it is caused by
exactly this.

Grouping rule
-------------
Events group into a detection by **(entity, threat class)**, held open while
events keep arriving and closed after a quiet gap. That key is chosen because
it matches how an investigation is actually scoped: an analyst asks "what is
10.0.0.5 doing" and "is this a scan or an exfil", not "tell me about event
8a3f-...". Two different behaviours from one host stay separate, which is
right - they may have different causes and different responses.

What is deliberately not done
-----------------------------
No grouping across entities. It is tempting to merge "many hosts scanning" into
one campaign detection, and sometimes that is correct - but it also hides the
scope of a compromise behind a single row, and getting it wrong costs more than
the extra rows save. Campaign-level grouping belongs above this layer, with an
analyst in the loop.

Per-class recall is measured **after** correlation, not before, because
grouping that quietly swallowed a real attack would otherwise look like a win.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from backend.detections.models import (
    ContributingEvent,
    Detection,
    EntityRisk,
    Severity,
    TriageState,
)

#: Quiet period after which an open detection is considered finished. Chosen
#: to be longer than a typical scan burst but short enough that two unrelated
#: incidents hours apart do not merge into one row.
DEFAULT_GAP_SECONDS = 1800.0

#: Contributing events retained per detection. The true total is kept in
#: `event_count`; this bounds the evidence bundle so one flood cannot produce a
#: gigabyte-scale detection.
MAX_EVENTS_RETAINED = 50

#: Human-readable titles per threat class.
TITLES: Dict[str, str] = {
    "reconnaissance": "Port scanning activity from {entity}",
    "network_attack": "Network attack traffic from {entity}",
    "authentication_attack": "Repeated authentication failures from {entity}",
    "web_exploit": "Web exploitation attempts from {entity}",
    "malware": "Malware-associated traffic from {entity}",
    "data_exfiltration": "Possible data exfiltration from {entity}",
    "lateral_movement": "Lateral movement from {entity}",
    "privilege_escalation": "Privilege escalation attempt from {entity}",
    "command_and_control": "Command-and-control beaconing from {entity}",
    "dos": "Denial-of-service traffic involving {entity}",
    "policy_violation": "Policy violation from {entity}",
    "unclassified": "Anomalous activity from {entity}",
}


@dataclass
class CorrelationStats:
    """The alert-volume reduction, as a measured number."""

    events_seen: int = 0
    events_anomalous: int = 0
    detections_opened: int = 0

    @property
    def reduction_ratio(self) -> float:
        """Anomalous events per detection. Higher means more consolidation."""
        if self.detections_opened == 0:
            return 0.0
        return round(self.events_anomalous / self.detections_opened, 2)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "events_seen": self.events_seen,
            "events_anomalous": self.events_anomalous,
            "detections_opened": self.detections_opened,
            "events_per_detection": self.reduction_ratio,
            "alert_volume_reduction_pct": round(
                (1 - self.detections_opened / self.events_anomalous) * 100, 2
            ) if self.events_anomalous else 0.0,
        }


class Correlator:
    """Groups anomalous events into detections, scoped by entity and behaviour."""

    def __init__(
        self,
        gap_seconds: float = DEFAULT_GAP_SECONDS,
        max_events: int = MAX_EVENTS_RETAINED,
    ):
        self.gap_seconds = gap_seconds
        self.max_events = max_events
        self.stats = CorrelationStats()
        self._open: Dict[Tuple[str, str], Detection] = {}
        self._open_last_epoch: Dict[Tuple[str, str], float] = {}
        self._closed: List[Detection] = []

    # -- ingestion ----------------------------------------------------------

    def observe(self, norm: Any, verdict: Any, epoch: float = 0.0) -> Optional[Detection]:
        """Feed one scored event. Returns the detection it joined, if any."""
        self.stats.events_seen += 1
        if not getattr(verdict, "is_anomalous", False):
            return None
        self.stats.events_anomalous += 1

        entity = (getattr(getattr(norm, "source", None), "ip", None) or "unknown")
        classification = getattr(norm, "classification", None) or {}
        threat_class = classification.get("threat_class", "unclassified")
        key = (entity, threat_class)

        self._expire(epoch)

        detection = self._open.get(key)
        if detection is None:
            detection = self._open_detection(entity, threat_class, verdict)
            self._open[key] = detection
            self.stats.detections_opened += 1

        self._append(detection, norm, verdict, epoch)
        self._open_last_epoch[key] = epoch
        return detection

    def _open_detection(self, entity: str, threat_class: str, verdict: Any) -> Detection:
        return Detection(
            title=TITLES.get(threat_class, TITLES["unclassified"]).format(entity=entity),
            entity=entity,
            entity_type="ip",
            threat_class=threat_class,
            severity=Severity.from_probability(getattr(verdict, "probability", 0.0)),
            confidence=getattr(verdict, "probability", 0.0),
            state=TriageState.NEW,
        )

    def _append(self, detection: Detection, norm: Any, verdict: Any,
                epoch: float) -> None:
        probability = float(getattr(verdict, "probability", 0.0))
        timestamp = getattr(getattr(norm, "event", None), "timestamp", "") or ""

        detection.event_count += 1
        if not detection.first_seen:
            detection.first_seen = timestamp
        detection.last_seen = timestamp

        # The detection's confidence is its strongest event, not its average.
        # Averaging would let a long tail of weak events bury the one that
        # matters, which is the wrong direction for a security queue.
        if probability > detection.confidence:
            detection.confidence = probability
            detection.severity = Severity.from_probability(probability)

        quality = getattr(verdict, "evidence_quality", None) or {}
        degraded = bool(quality.get("degraded"))
        if degraded:
            detection.evidence_degraded = True

        dst_ip = getattr(getattr(norm, "destination", None), "ip", None)
        dst_port = getattr(getattr(norm, "destination", None), "port", None)
        if dst_ip and dst_ip not in detection.peer_ips:
            detection.peer_ips.append(dst_ip)
        if dst_port and dst_port not in detection.ports_touched:
            detection.ports_touched.append(dst_port)

        techniques = (getattr(norm, "classification", None) or {}).get(
            "mitre_techniques") or []
        for technique in techniques:
            if technique not in detection.mitre_techniques:
                detection.mitre_techniques.append(technique)

        if len(detection.events) < self.max_events:
            raw = getattr(norm, "raw", None)
            detection.events.append(ContributingEvent(
                event_id=getattr(norm, "event_id", ""),
                timestamp=timestamp,
                raw_sha256=getattr(raw, "sha256_hash", "") if raw else "",
                raw_payload=getattr(raw, "payload", "") if raw else "",
                probability=probability,
                src_ip=getattr(getattr(norm, "source", None), "ip", None),
                dst_ip=dst_ip,
                dst_port=dst_port,
                evidence_degraded=degraded,
            ))

        # Keep the strongest evidence seen across the whole detection.
        if hasattr(verdict, "top_evidence"):
            merged = {(e.get("detector"), e.get("signal")): e
                      for e in detection.evidence}
            for item in verdict.top_evidence(5):
                merged[(item.get("detector"), item.get("signal"))] = item
            detection.evidence = sorted(
                merged.values(), key=lambda e: abs(e.get("weight", 0.0)),
                reverse=True)[:10]

    def _expire(self, epoch: float) -> None:
        if not epoch:
            return
        stale = [k for k, last in self._open_last_epoch.items()
                 if epoch - last > self.gap_seconds]
        for key in stale:
            detection = self._open.pop(key, None)
            self._open_last_epoch.pop(key, None)
            if detection is not None:
                self._closed.append(detection)

    # -- output -------------------------------------------------------------

    def detections(self) -> List[Detection]:
        """All detections, most severe first, then most recent."""
        everything = self._closed + list(self._open.values())
        return sorted(
            everything,
            key=lambda d: (d.confidence, d.event_count),
            reverse=True,
        )

    def open_detections(self) -> List[Detection]:
        return [d for d in self.detections() if d.is_open]

    def entity_risks(self) -> List[EntityRisk]:
        risks: Dict[str, EntityRisk] = {}
        for detection in self.detections():
            risk = risks.setdefault(
                detection.entity,
                EntityRisk(entity=detection.entity, entity_type=detection.entity_type),
            )
            risk.detection_count += 1
            if detection.is_open:
                risk.open_count += 1
            risk.max_confidence = max(risk.max_confidence, detection.confidence)
            risk.threat_classes[detection.threat_class] = (
                risk.threat_classes.get(detection.threat_class, 0) + 1
            )
            if detection.last_seen > risk.last_seen:
                risk.last_seen = detection.last_seen
        return sorted(risks.values(), key=lambda r: r.risk_score, reverse=True)

    def summary(self) -> Dict[str, Any]:
        detections = self.detections()
        by_severity: Dict[str, int] = {}
        for d in detections:
            by_severity[d.severity.value] = by_severity.get(d.severity.value, 0) + 1
        return {
            **self.stats.as_dict(),
            "detections_total": len(detections),
            "detections_open": sum(1 for d in detections if d.is_open),
            "by_severity": by_severity,
            "entities_implicated": len({d.entity for d in detections}),
            "degraded_evidence_detections": sum(
                1 for d in detections if d.evidence_degraded),
        }
