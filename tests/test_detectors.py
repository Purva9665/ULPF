"""
Phase 3 acceptance tests - each detector against known positives.

Every detector is tested in isolation on traffic whose nature is known by
construction, so a failure points at one component rather than at "the model".
"""

import math

import numpy as np
import pytest

from backend.ml.detectors import (
    ECOD,
    BehaviourDetector,
    NoveltyDetector,
    RuleDetector,
    Signal,
    TemporalDetector,
)
from backend.ml.detectors.base import Evidence
from backend.ml.fusion import FusionModel


# -- ECOD ------------------------------------------------------------------


class TestECOD:
    @pytest.fixture(scope="class")
    def fitted(self):
        rng = np.random.default_rng(0)
        return ECOD().fit(rng.normal(0, 1, (2000, 6))), rng

    def test_outlier_scores_above_inlier(self, fitted):
        model, _ = fitted
        inlier = model.decision_scores(np.zeros((1, 6)))[0]
        outlier = model.decision_scores(np.array([[6.0, 6.0, 0, 0, 0, 0]]))[0]
        assert outlier > inlier * 2

    def test_attribution_identifies_the_anomalous_dimensions(self, fitted):
        """The per-dimension score is the actual decomposition of the total,
        not a post-hoc approximation - so attribution must land on the axes
        that were actually extreme."""
        model, _ = fitted
        point = np.array([[6.0, 6.0, 0.0, 0.0, 0.0, 0.0]])
        per_dim = model.per_dimension_scores(point)[0]
        top_two = set(np.argsort(per_dim)[::-1][:2].tolist())
        assert top_two == {0, 1}

    def test_attribution_sums_to_the_score(self, fitted):
        model, _ = fitted
        point = np.array([[3.0, -2.0, 0.5, 0.0, 1.0, -4.0]])
        assert model.per_dimension_scores(point).sum() == pytest.approx(
            model.decision_scores(point)[0], rel=1e-9)

    def test_is_deterministic(self, fitted):
        """Unlike Isolation Forest, the same input must always give the same
        score - a detection has to be reproducible for an auditor."""
        model, _ = fitted
        point = np.array([[1.0, 2.0, 3.0, 0.0, 0.0, 0.0]])
        assert model.decision_scores(point)[0] == model.decision_scores(point)[0]

    def test_probabilities_are_floored(self, fitted):
        """A value beyond anything in the sample must not produce infinite
        surprise; it is capped at the sample's resolution."""
        model, _ = fitted
        extreme = np.array([[1e9] * 6])
        assert math.isfinite(float(model.decision_scores(extreme)[0]))

    def test_rejects_unfitted_use(self):
        with pytest.raises(RuntimeError):
            ECOD().tail_probabilities(np.zeros((1, 3)))


class TestNoveltyDetector:
    def test_cold_start_is_reported_not_faked(self):
        """An unfitted model must return a zero score with LOW confidence -
        'I cannot tell' rather than 'nothing is wrong'."""
        det = NoveltyDetector(feature_names=["a", "b"])
        signal = det.analyse({"a": 99.0, "b": 99.0}, None)
        assert signal.score == 0.0
        assert signal.confidence < 0.2
        assert signal.state["model_state"] == "cold_start"

    def test_does_not_fit_below_minimum_samples(self):
        det = NoveltyDetector(feature_names=["a"], min_fit_samples=500)
        det.fit(np.random.default_rng(0).normal(size=(100, 1)))
        assert not det.fitted

    def test_batch_matches_per_event(self):
        """Backs the optimisation in the evaluation harness, which scores the
        novelty layer in one call instead of per event. If these ever diverge,
        every reported metric was computed on different numbers than
        production would produce."""
        rng = np.random.default_rng(3)
        names = [f"f{i}" for i in range(10)]
        det = NoveltyDetector(feature_names=names).fit(rng.normal(0, 1, (3000, 10)))
        probe = rng.normal(0, 1, (200, 10))
        batch = det.score_batch(probe)
        per_event = np.array([
            det.analyse({n: float(v) for n, v in zip(names, row)}, None).score
            for row in probe
        ])
        assert np.allclose(batch, per_event, atol=1e-9)


# -- rules -----------------------------------------------------------------


class _FakeNorm:
    def __init__(self, threat_class="benign_traffic", confidence=0.9,
                 signature=None, techniques=None, dst_port=443):
        self.classification = {
            "threat_class": threat_class,
            "confidence": confidence,
            "mitre_techniques": techniques or [],
        }
        self.threat = type("T", (), {"signature": signature})() if signature else None
        self.destination = type("D", (), {"port": dst_port, "ip": "10.0.0.1"})()
        self.source = type("S", (), {"port": 5555, "ip": "10.0.0.2"})()

    def parse_quality(self):
        return {"mean_confidence": 1.0, "min_confidence": 1.0, "mapped_ratio": 1.0,
                "low_confidence_fields": [], "fields_unmapped": 0, "by_method": {}}


class TestRuleDetector:
    def test_malware_scores_above_benign(self):
        det = RuleDetector()
        malware = det.analyse({}, _FakeNorm("malware", 0.9))
        benign = det.analyse({}, _FakeNorm("benign_traffic", 0.9))
        assert malware.score > benign.score

    def test_unconfident_classification_carries_less_risk(self):
        det = RuleDetector()
        sure = det.analyse({}, _FakeNorm("malware", 1.0))
        unsure = det.analyse({}, _FakeNorm("malware", 0.1))
        assert sure.score > unsure.score

    def test_vendor_signature_raises_the_floor(self):
        det = RuleDetector()
        with_sig = det.analyse({}, _FakeNorm("unclassified", 0.5, signature="ET SCAN"))
        without = det.analyse({}, _FakeNorm("unclassified", 0.5))
        assert with_sig.score > without.score

    def test_reports_evidence_against(self):
        """A detector that only ever reports supporting evidence is advocating,
        not explaining."""
        det = RuleDetector()
        signal = det.analyse({}, _FakeNorm("benign_traffic", 0.95))
        assert any(e.weight < 0 for e in signal.evidence)

    def test_every_signal_carries_evidence(self):
        det = RuleDetector()
        for cls in ("malware", "reconnaissance", "benign_traffic"):
            assert det.analyse({}, _FakeNorm(cls, 0.8)).evidence


# -- behaviour -------------------------------------------------------------


class TestBehaviourDetector:
    def test_wide_port_fanout_is_flagged(self):
        """The defining shape of a port scan."""
        det = BehaviourDetector()
        scanning = det.analyse(
            {"src_fanout_ports": 0.95, "src_baseline_cold": 0.0,
             "src_activity": 0.8}, None)
        quiet = det.analyse(
            {"src_fanout_ports": 0.05, "src_baseline_cold": 0.0,
             "src_activity": 0.8}, None)
        assert scanning.score > quiet.score
        assert any("fanout" in e.signal for e in scanning.evidence)

    def test_high_refusal_ratio_is_flagged(self):
        det = BehaviourDetector()
        probing = det.analyse(
            {"src_deny_ratio": 0.95, "src_baseline_cold": 0.0,
             "src_activity": 0.8}, None)
        assert probing.score > 0.2

    def test_fanin_catches_convergence_on_one_host(self):
        """DDoS is invisible from any single source's profile."""
        det = BehaviourDetector()
        flood = det.analyse(
            {"dst_fanin_peers": 0.95, "src_baseline_cold": 0.0,
             "src_activity": 0.5}, None)
        assert flood.score > 0.2

    def test_cold_baseline_lowers_confidence_not_score(self):
        """'I cannot tell' must be distinguishable from 'nothing is wrong'."""
        det = BehaviourDetector()
        cold = det.analyse({"src_baseline_cold": 1.0}, None)
        warm = det.analyse({"src_baseline_cold": 0.0, "src_activity": 1.0}, None)
        assert cold.confidence < warm.confidence
        assert cold.state["cold_baseline"] is True

    def test_score_never_exceeds_one(self):
        """Several correlated signals are facets of one event and must not sum
        past certainty."""
        det = BehaviourDetector()
        signal = det.analyse({
            "src_fanout_ports": 1.0, "src_fanout_peers": 1.0,
            "dst_fanin_peers": 1.0, "src_deny_ratio": 1.0,
            "src_port_surprisal": 1.0, "src_peer_surprisal": 1.0,
            "src_bytes_out_z": 1.0, "src_baseline_cold": 0.0,
            "src_activity": 1.0,
        }, None)
        assert 0.0 <= signal.score <= 1.0


# -- temporal --------------------------------------------------------------


class _TimedNorm:
    def __init__(self, src="10.0.0.5", dst="10.0.0.9"):
        self.source = type("S", (), {"ip": src, "port": 5555})()
        self.destination = type("D", (), {"ip": dst, "port": 445})()


class TestTemporalDetector:
    def test_burst_is_detected(self):
        det = TemporalDetector()
        norm = _TimedNorm()
        last = None
        for i in range(120):
            last = det.analyse({}, norm, {"epoch": 1000.0 + i * 0.1})
        assert last.score > 0.2
        assert any(e.signal == "event_burst" for e in last.evidence)

    def test_slow_traffic_is_not_a_burst(self):
        det = TemporalDetector()
        norm = _TimedNorm()
        last = None
        for i in range(30):
            last = det.analyse({}, norm, {"epoch": 1000.0 + i * 600.0})
        assert not any(e.signal == "event_burst" for e in last.evidence)

    def test_failure_run_is_detected(self):
        det = TemporalDetector()
        norm = _TimedNorm()
        last = None
        for i in range(12):
            last = det.analyse({"action_is_denied": 1.0}, norm,
                               {"epoch": 1000.0 + i * 30.0})
        assert any(e.signal == "failure_run" for e in last.evidence)

    def test_success_resets_the_failure_run(self):
        det = TemporalDetector()
        norm = _TimedNorm()
        for i in range(12):
            det.analyse({"action_is_denied": 1.0}, norm, {"epoch": 1000.0 + i})
        after = det.analyse({"action_is_denied": 0.0}, norm, {"epoch": 1100.0})
        assert not any(e.signal == "failure_run" for e in after.evidence)

    def test_beacon_signal_is_surfaced(self):
        det = TemporalDetector()
        signal = det.analyse({"src_beacon_score": 0.9}, _TimedNorm(),
                             {"epoch": 1000.0})
        assert signal.score > 0.5
        assert any(e.signal == "periodic_contact" for e in signal.evidence)

    def test_missing_timestamp_lowers_confidence(self):
        """Timing evidence is only as good as the timestamps behind it."""
        det = TemporalDetector()
        timed = det.analyse({}, _TimedNorm(), {"epoch": 1000.0})
        untimed = det.analyse({}, _TimedNorm(), {"epoch": 0.0})
        assert untimed.confidence < timed.confidence


# -- fusion ----------------------------------------------------------------


class TestFusion:
    def _signals(self, rules=0.0, behaviour=0.0, temporal=0.0, novelty=0.0):
        return {
            n: Signal(detector=n, score=s, confidence=0.8)
            for n, s in (("rules", rules), ("behaviour", behaviour),
                         ("temporal", temporal), ("novelty", novelty))
        }

    def test_untrained_model_still_produces_a_verdict(self):
        """The product must do something sensible on its first event."""
        model = FusionModel(feature_names=["a", "b"])
        verdict = model.fuse({"a": 0.0, "b": 0.0}, self._signals(rules=0.9))
        assert verdict.mode == "heuristic"
        assert 0.0 <= verdict.probability <= 1.0

    def test_heuristic_mode_is_labelled_not_disguised(self):
        model = FusionModel(feature_names=["a"])
        assert model.fuse({"a": 0.0}, self._signals()).mode == "heuristic"

    def test_agreement_scores_above_a_single_signal(self):
        model = FusionModel(feature_names=["a"])
        alone = model.fuse({"a": 0.0}, self._signals(rules=0.8))
        agreeing = model.fuse({"a": 0.0}, self._signals(
            rules=0.8, behaviour=0.8, temporal=0.8))
        assert agreeing.probability > alone.probability

    def test_input_layout_matches_assembled_row(self):
        model = FusionModel(feature_names=["a", "b"])
        row = model.assemble({"a": 1.0, "b": 2.0}, self._signals(rules=0.5))
        assert len(row) == len(model.input_names)
        assert row[:2] == [1.0, 2.0]
        assert row[model.input_names.index("det:rules:score")] == 0.5

    def test_trains_and_produces_calibrated_probabilities(self):
        rng = np.random.default_rng(1)
        n = 3000
        X = rng.normal(0, 1, (n, 6))
        y = (X[:, 0] + rng.normal(0, 0.4, n) > 1.0).astype(int)
        model = FusionModel(feature_names=[f"f{i}" for i in range(6)],
                            detector_order=[])
        model.fit(X, y)
        p = model.predict_proba(X)
        assert model.trained
        assert p.min() >= 0.0 and p.max() <= 1.0
        # Predicted positives should actually be enriched in positives.
        assert y[p > 0.7].mean() > y.mean()

    def test_round_trips_through_disk(self, tmp_path):
        rng = np.random.default_rng(2)
        X = rng.normal(0, 1, (1500, 4))
        y = (X[:, 0] > 0.8).astype(int)
        model = FusionModel(feature_names=[f"f{i}" for i in range(4)],
                            detector_order=[])
        model.fit(X, y)
        path = str(tmp_path / "m.pkl")
        model.save(path)
        loaded = FusionModel.load(path)
        assert loaded.trained
        assert np.allclose(loaded.predict_proba(X), model.predict_proba(X))

    def test_refuses_single_class_training(self):
        model = FusionModel(feature_names=["a"], detector_order=[])
        with pytest.raises(ValueError):
            model.fit(np.zeros((100, 1)), np.zeros(100, dtype=int))


# -- evidence contract -----------------------------------------------------


class TestEvidenceContract:
    def test_signals_clamp_out_of_range_scores(self):
        assert Signal(detector="x", score=5.0, confidence=-1.0).score == 1.0
        assert Signal(detector="x", score=5.0, confidence=-1.0).confidence == 0.0

    def test_nan_score_becomes_zero(self):
        """A NaN reaching fusion would poison every downstream comparison."""
        assert Signal(detector="x", score=float("nan"), confidence=0.5).score == 0.0

    def test_evidence_serialises(self):
        e = Evidence(signal="s", observed=42, argues="because", weight=0.5)
        assert e.as_dict()["signal"] == "s"

    def test_top_evidence_ranks_by_absolute_weight(self):
        signal = Signal(detector="x", score=0.5, confidence=0.5, evidence=[
            Evidence("weak", 1, "a", 0.1),
            Evidence("strong_negative", 2, "b", -0.9),
            Evidence("medium", 3, "c", 0.4),
        ])
        assert signal.top_evidence[0].signal == "strong_negative"
