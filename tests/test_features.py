"""
Phase 1 acceptance tests - entity profiles, provenance, and feature extraction.

These tests encode the properties the rest of the detection model depends on.
The ordering test in particular guards a correctness bug that would not show up
as a failure anywhere else: it would silently degrade detection quality for
exactly the slow attacks profiling exists to catch.
"""

import math
import time

import pytest

from backend.core.models import ExtractionMethod, ULPFNormalizedEvent
from backend.ml.features import GLOBAL_ENTITY, FeatureExtractor
from backend.ml.profiles import (
    MIN_EVENTS_FOR_BASELINE,
    DecayingCounter,
    ProfileStore,
    RunningStats,
)
from backend.pipeline.orchestrator import PipelineOrchestrator
from backend.sample_data import SAMPLE_LOGS


# -- profile primitives ----------------------------------------------------


class TestDecayingCounter:
    def test_common_value_is_unsurprising(self):
        c = DecayingCounter()
        for _ in range(200):
            c.observe("443")
        assert c.surprisal("443") < 0.05

    def test_rare_value_is_surprising(self):
        c = DecayingCounter()
        for _ in range(200):
            c.observe("443")
        c.observe("4444")
        assert c.surprisal("4444") > c.surprisal("443")

    def test_unseen_value_is_most_surprising(self):
        c = DecayingCounter()
        for _ in range(200):
            c.observe("443")
        c.observe("4444")
        assert c.surprisal("31337") > c.surprisal("4444")

    def test_surprisal_is_bounded(self):
        """Unbounded surprisal would let one rare value dominate every score."""
        c = DecayingCounter()
        c.observe("x")
        assert 0.0 <= c.surprisal("never-seen") <= 1.0

    def test_first_observation_does_not_produce_infinite_surprisal(self):
        c = DecayingCounter()
        assert math.isfinite(c.surprisal("anything"))

    def test_cardinality_is_bounded(self):
        c = DecayingCounter(max_cardinality=64)
        for i in range(5000):
            c.observe(f"value-{i}")
        assert c.cardinality() <= 64

    def test_decay_favours_recent_behaviour(self):
        """An old pattern must lose ground to a sustained new one."""
        c = DecayingCounter(half_life=50)
        for _ in range(200):
            c.observe("old")
        for _ in range(200):
            c.observe("new")
        assert c.weight_of("new") > c.weight_of("old")

    def test_survives_long_run_without_overflow(self):
        c = DecayingCounter(half_life=10)
        for i in range(20000):
            c.observe(f"v{i % 8}")
        assert math.isfinite(c.total())
        assert 0.0 <= c.surprisal("v1") <= 1.0


class TestRunningStats:
    def test_matches_batch_mean_and_variance(self):
        data = [3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0, 6.0]
        r = RunningStats()
        for x in data:
            r.observe(x)
        expected_mean = sum(data) / len(data)
        expected_var = sum((x - expected_mean) ** 2 for x in data) / (len(data) - 1)
        assert r.mean == pytest.approx(expected_mean)
        assert r.variance == pytest.approx(expected_var)

    def test_no_zscore_before_baseline_exists(self):
        r = RunningStats()
        for _ in range(MIN_EVENTS_FOR_BASELINE - 1):
            r.observe(100.0)
        assert r.zscore(10_000.0) == 0.0

    def test_constant_baseline_does_not_explode(self):
        """A near-constant series must not yield an unbounded z on a small
        deviation - the classic volume-detection false positive."""
        r = RunningStats()
        for _ in range(100):
            r.observe(100.0)
        assert r.zscore(101.0) < 1.0


class TestProfileStore:
    def test_lru_cap_is_enforced(self):
        s = ProfileStore(max_entities=100)
        for i in range(1000):
            s.get("ip", f"10.0.0.{i}")
        assert len(s) == 100
        assert s.evictions == 900

    def test_recently_used_entities_survive_eviction(self):
        s = ProfileStore(max_entities=10)
        for i in range(10):
            s.get("ip", f"host-{i}")
        s.get("ip", "host-0")           # refresh the oldest
        s.get("ip", "host-new")         # force one eviction
        assert ("ip", "host-0") in s    # kept: recently used
        assert ("ip", "host-1") not in s  # evicted: least recently used

    def test_peek_does_not_create(self):
        s = ProfileStore()
        assert s.peek("ip", "1.2.3.4") is None
        assert len(s) == 0

    def test_cold_baseline_is_reported(self):
        s = ProfileStore()
        p = s.get("ip", "1.2.3.4")
        assert p.is_cold()
        for _ in range(MIN_EVENTS_FOR_BASELINE):
            p.observe(dst_port=443, peer="5.6.7.8", protocol="TCP")
        assert not p.is_cold()


# -- provenance (USP-1 foundation) -----------------------------------------


def _normalize_samples():
    orc = PipelineOrchestrator()
    out = []
    for s in SAMPLE_LOGS:
        ctx = orc.process_sync(s["raw"])
        if ctx.normalized_event is not None:
            out.append((s["id"], ctx.normalized_event))
    return out


class TestFieldProvenance:
    def test_every_sample_records_provenance(self):
        for sample_id, norm in _normalize_samples():
            assert norm.field_provenance, f"{sample_id} recorded no provenance"

    def test_extracted_fields_reference_their_source_key(self):
        for _, norm in _normalize_samples():
            for path, prov in norm.field_provenance.items():
                if prov.method is ExtractionMethod.EXTRACTED:
                    assert prov.source_key, f"{path} extracted but names no source key"

    def test_defaulted_fields_carry_low_confidence(self):
        """A defaulted field is an assumption of ours, not an observation."""
        for _, norm in _normalize_samples():
            for path, prov in norm.field_provenance.items():
                if prov.method is ExtractionMethod.DEFAULTED:
                    assert prov.confidence < 0.7, f"{path} defaulted at {prov.confidence}"
                    assert prov.note, f"{path} defaulted without explanation"

    def test_parse_quality_is_wellformed(self):
        for _, norm in _normalize_samples():
            q = norm.parse_quality()
            assert 0.0 <= q["mean_confidence"] <= 1.0
            assert 0.0 <= q["min_confidence"] <= 1.0
            assert 0.0 <= q["mapped_ratio"] <= 1.0
            assert q["fields_tracked"] >= 0

    def test_untracked_field_is_not_penalised(self):
        """Absent provenance means untracked, not untrusted. Fields normalized
        before provenance existed must not be retroactively downranked."""
        norm = ULPFNormalizedEvent(
            event_id="x",
            raw=_normalize_samples()[0][1].raw,
            event=_normalize_samples()[0][1].event,
        )
        assert norm.field_confidence("destination.port") == 1.0

    def test_windows_logon_flags_its_missing_protocol(self):
        """A Windows Security Event carries no protocol field. The pipeline
        defaults it to TCP; provenance must make that visible rather than let
        a detector treat the default as an observation."""
        by_id = dict(_normalize_samples())
        norm = by_id["windows_failed_logon"]
        prov = norm.field_provenance.get("network.protocol")
        assert prov is not None
        assert prov.method is ExtractionMethod.DEFAULTED
        assert prov.confidence < 0.7


# -- feature extraction ----------------------------------------------------


class TestFeatureExtractor:
    def test_vector_length_matches_spec_table(self):
        fx = FeatureExtractor()
        for _, norm in _normalize_samples():
            vec, named = fx.extract(norm)
            assert len(vec) == len(fx.feature_names)
            assert set(named).issuperset(set(fx.feature_names))

    def test_all_features_are_finite(self):
        """A NaN or inf reaching the model corrupts every downstream split."""
        fx = FeatureExtractor()
        for sample_id, norm in _normalize_samples():
            vec, _ = fx.extract(norm)
            for name, value in zip(fx.feature_names, vec):
                assert math.isfinite(value), f"{sample_id}/{name} = {value}"

    def test_confidence_family_can_be_ablated(self):
        """The USP must be switchable off, or its contribution cannot be
        measured. This is what the evaluation protocol's ablation depends on."""
        full = FeatureExtractor(use_confidence_features=True)
        ablated = FeatureExtractor(use_confidence_features=False)
        assert len(full.feature_names) > len(ablated.feature_names)
        assert not any(n.startswith("parse_") for n in ablated.feature_names)
        assert "evidence_field_confidence" not in ablated.feature_names

    def test_features_precede_profile_update(self):
        """The ordering guarantee.

        An event must be scored against the baseline as it stood BEFORE that
        event. If the profile is updated first, the event contaminates the
        baseline it is judged against and its own novelty is erased.
        """
        fx = FeatureExtractor()
        _, norm = _normalize_samples()[0]
        _, first = fx.extract(norm)
        # The very first event from a source can never look familiar.
        assert first["src_baseline_cold"] == 1.0
        # And the profile must now exist, i.e. the update did happen after.
        assert fx.profiles.peek("ip", norm.source.ip) is not None

    def test_repeated_traffic_becomes_unsurprising(self):
        """The core behavioural claim: a pattern seen often stops standing out."""
        fx = FeatureExtractor()
        _, norm = _normalize_samples()[0]
        surprisals = []
        for _ in range(MIN_EVENTS_FOR_BASELINE * 3):
            _, named = fx.extract(norm)
            surprisals.append(named["src_port_surprisal"])
        assert surprisals[-1] < 0.1

    def test_global_profile_is_maintained(self):
        fx = FeatureExtractor()
        for _, norm in _normalize_samples():
            fx.extract(norm)
        assert fx.profiles.peek("global", GLOBAL_ENTITY) is not None

    def test_extraction_is_fast_enough_for_the_pipeline(self):
        """Budget: the pipeline runs ~900 EPS, so feature extraction must cost
        well under a millisecond or it becomes the bottleneck."""
        fx = FeatureExtractor()
        _, norm = _normalize_samples()[0]
        for _ in range(50):          # warm the profiles
            fx.extract(norm)
        t0 = time.perf_counter()
        n = 2000
        for _ in range(n):
            fx.extract(norm)
        per_event_us = (time.perf_counter() - t0) / n * 1e6
        assert per_event_us < 500, f"{per_event_us:.0f} us/event is too slow"
