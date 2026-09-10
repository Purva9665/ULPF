"""
Phase 5 acceptance tests - correlation and the detection object.

The claim under test: many scored events become few workable findings, without
losing anything an analyst needs.
"""

import hashlib

import pytest

from backend.detections import (
    Correlator,
    Detection,
    Severity,
    TriageState,
)


class _Verdict:
    def __init__(self, probability=0.9, anomalous=True, degraded=False):
        self.probability = probability
        self.is_anomalous = anomalous
        self.evidence_quality = {"degraded": degraded}

    def top_evidence(self, limit=5):
        return [{"detector": "behaviour", "signal": "port_fanout",
                 "observed": 0.9, "argues": "wide port fan-out", "weight": 0.5}]


class _Norm:
    def __init__(self, src="10.0.0.5", dst="10.0.0.9", port=445,
                 threat_class="reconnaissance", payload="raw log line",
                 timestamp="2017-07-05T10:00:00Z", techniques=("T1046",)):
        self.event_id = f"{src}-{dst}-{port}-{timestamp}"
        self.classification = {"threat_class": threat_class,
                               "mitre_techniques": list(techniques)}
        self.source = type("S", (), {"ip": src, "port": 5555})()
        self.destination = type("D", (), {"ip": dst, "port": port})()
        self.event = type("E", (), {"timestamp": timestamp})()
        self.raw = type("R", (), {
            "payload": payload,
            "sha256_hash": hashlib.sha256(payload.encode()).hexdigest(),
        })()


class TestCorrelation:
    def test_many_events_become_one_detection(self):
        """The core product claim: a scan is one finding, not 5,000 alerts."""
        c = Correlator()
        for i in range(5000):
            c.observe(_Norm(port=1000 + i), _Verdict(), epoch=1000.0 + i)
        assert len(c.detections()) == 1
        assert c.detections()[0].event_count == 5000

    def test_reduction_ratio_is_measured(self):
        c = Correlator()
        for i in range(500):
            c.observe(_Norm(port=1000 + i), _Verdict(), epoch=1000.0 + i)
        summary = c.summary()
        assert summary["events_per_detection"] == 500.0
        assert summary["alert_volume_reduction_pct"] > 99.0

    def test_benign_events_open_nothing(self):
        c = Correlator()
        for i in range(100):
            c.observe(_Norm(), _Verdict(anomalous=False), epoch=1000.0 + i)
        assert c.detections() == []
        assert c.stats.events_seen == 100
        assert c.stats.events_anomalous == 0

    def test_different_behaviours_stay_separate(self):
        """Two different activities from one host are two investigations."""
        c = Correlator()
        c.observe(_Norm(threat_class="reconnaissance"), _Verdict(), epoch=1000.0)
        c.observe(_Norm(threat_class="data_exfiltration"), _Verdict(), epoch=1001.0)
        assert len(c.detections()) == 2

    def test_different_entities_stay_separate(self):
        """Campaign-level merging would hide the scope of a compromise."""
        c = Correlator()
        c.observe(_Norm(src="10.0.0.1"), _Verdict(), epoch=1000.0)
        c.observe(_Norm(src="10.0.0.2"), _Verdict(), epoch=1001.0)
        assert len(c.detections()) == 2

    def test_quiet_gap_closes_a_detection(self):
        """Two incidents hours apart must not merge into one row."""
        c = Correlator(gap_seconds=600.0)
        c.observe(_Norm(), _Verdict(), epoch=1000.0)
        c.observe(_Norm(), _Verdict(), epoch=1000.0 + 5000.0)
        assert len(c.detections()) == 2

    def test_confidence_tracks_the_strongest_event(self):
        """Averaging would let a long tail of weak events bury the one that
        matters."""
        c = Correlator()
        c.observe(_Norm(port=1), _Verdict(probability=0.55), epoch=1000.0)
        c.observe(_Norm(port=2), _Verdict(probability=0.97), epoch=1001.0)
        for i in range(50):
            c.observe(_Norm(port=100 + i), _Verdict(probability=0.51),
                      epoch=1002.0 + i)
        detection = c.detections()[0]
        assert detection.confidence == pytest.approx(0.97)
        assert detection.severity is Severity.CRITICAL

    def test_retained_events_are_capped_but_count_is_not(self):
        """One flood must not produce a gigabyte-scale detection, and the true
        total must survive the cap."""
        c = Correlator(max_events=25)
        for i in range(4000):
            c.observe(_Norm(port=i), _Verdict(), epoch=1000.0 + i)
        detection = c.detections()[0]
        assert len(detection.events) == 25
        assert detection.event_count == 4000

    def test_degraded_evidence_propagates_to_the_detection(self):
        c = Correlator()
        c.observe(_Norm(port=1), _Verdict(degraded=False), epoch=1000.0)
        c.observe(_Norm(port=2), _Verdict(degraded=True), epoch=1001.0)
        assert c.detections()[0].evidence_degraded is True

    def test_mitre_techniques_accumulate_without_duplicates(self):
        c = Correlator()
        c.observe(_Norm(port=1, techniques=("T1046",)), _Verdict(), epoch=1000.0)
        c.observe(_Norm(port=2, techniques=("T1046", "T1110")), _Verdict(), epoch=1001.0)
        assert sorted(c.detections()[0].mitre_techniques) == ["T1046", "T1110"]


class TestEvidenceBundle:
    def test_bundle_is_independently_verifiable(self):
        """USP-3: a reviewer must be able to re-derive the verdict without
        access to the running system."""
        c = Correlator()
        payloads = [f"log line {i}" for i in range(5)]
        for i, payload in enumerate(payloads):
            c.observe(_Norm(port=i, payload=payload), _Verdict(), epoch=1000.0 + i)
        bundle = c.detections()[0].evidence_bundle()

        # Each event's hash must match its raw payload.
        for event, payload in zip(bundle["contributing_events"], payloads):
            assert event["raw_sha256"] == hashlib.sha256(payload.encode()).hexdigest()

        # And the bundle hash must match the sorted concatenation of those.
        expected = hashlib.sha256(
            "".join(sorted(e["raw_sha256"]
                           for e in bundle["contributing_events"])).encode()
        ).hexdigest()
        assert bundle["bundle_sha256"] == expected

    def test_bundle_carries_verification_instructions(self):
        c = Correlator()
        c.observe(_Norm(), _Verdict(), epoch=1000.0)
        assert "SHA-256" in c.detections()[0].evidence_bundle()["verification"]

    def test_tampering_changes_the_bundle_hash(self):
        c = Correlator()
        for i in range(3):
            c.observe(_Norm(port=i, payload=f"line {i}"), _Verdict(), epoch=1000.0 + i)
        detection = c.detections()[0]
        original = detection.evidence_bundle()["bundle_sha256"]
        detection.events[0].raw_sha256 = "0" * 64
        assert detection.evidence_bundle()["bundle_sha256"] != original


class TestTriage:
    def test_new_detections_are_open(self):
        assert Detection().is_open

    def test_resolution_closes_a_detection(self):
        d = Detection().set_state(TriageState.RESOLVED_FALSE_POSITIVE, "known scanner")
        assert not d.is_open
        assert d.analyst_note == "known scanner"

    def test_severity_bands_are_ordered(self):
        assert Severity.from_probability(0.95) is Severity.CRITICAL
        assert Severity.from_probability(0.75) is Severity.HIGH
        assert Severity.from_probability(0.50) is Severity.MEDIUM
        assert Severity.from_probability(0.10) is Severity.LOW


class TestEntityRisk:
    def test_breadth_of_behaviour_raises_risk(self):
        """Three different behaviours from one host is a different problem
        from tripping the same rule three times."""
        broad = Correlator()
        for i, cls in enumerate(("reconnaissance", "malware", "data_exfiltration")):
            broad.observe(_Norm(threat_class=cls), _Verdict(probability=0.8),
                          epoch=1000.0 + i)
        narrow = Correlator()
        for i in range(3):
            narrow.observe(_Norm(threat_class="reconnaissance", port=i),
                           _Verdict(probability=0.8), epoch=1000.0 + i * 5000.0)
        assert broad.entity_risks()[0].risk_score > narrow.entity_risks()[0].risk_score

    def test_risk_is_bounded(self):
        c = Correlator()
        for i in range(200):
            c.observe(_Norm(threat_class="malware", port=i),
                      _Verdict(probability=1.0), epoch=1000.0 + i * 5000.0)
        assert all(0.0 <= r.risk_score <= 1.0 for r in c.entity_risks())
