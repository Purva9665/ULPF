"""
Phase 2 acceptance tests - corpus loading and replay fidelity.

The central claim these defend: **replayed events are parsed by the real
parsers, not injected past them.** If that stops being true, every accuracy
number the project reports becomes a measurement of a classifier on clean
tabular data rather than of this framework on log lines.

Skipped when the corpus is absent so the suite still runs on a fresh checkout
without the 271 MB download.
"""

import os

import pytest

from backend.ml.eval.corpus import (
    DEFAULT_CORPUS,
    LoadStats,
    day_of,
    iter_flows,
    normalise_label,
)
from backend.ml.eval.replay import (
    RENDERERS,
    assign_vendor,
    is_denied,
    preserved_fields,
    render,
    replay,
)
from backend.pipeline.orchestrator import PipelineOrchestrator

corpus_required = pytest.mark.skipif(
    not os.path.exists(DEFAULT_CORPUS),
    reason=f"corpus not present at {DEFAULT_CORPUS}",
)

SAMPLE_SIZE = 1500


@pytest.fixture(scope="module")
def flows():
    """A slice containing both classes.

    A naive `limit=N` returns the first N rows of the alphabetically-first
    file, which is 100% benign. Tests about attack behaviour would then pass
    or fail for reasons unrelated to what they claim to check, so the sample
    is drawn until both classes are represented.
    """
    benign, attack = [], []
    for flow in iter_flows(limit=SAMPLE_SIZE * 40):
        bucket = attack if flow.is_attack else benign
        if len(bucket) < SAMPLE_SIZE // 2:
            bucket.append(flow)
        if len(benign) >= SAMPLE_SIZE // 2 and len(attack) >= SAMPLE_SIZE // 2:
            break
    assert attack, "no attack flows found in the sampled window"
    return benign + attack


# -- loader ----------------------------------------------------------------


class TestCorpusLoader:
    def test_label_encoding_is_normalised(self):
        """The corpus stores an en-dash as Windows-1252 0x96. Left alone it
        splits one class into two whenever a consumer decodes differently."""
        assert normalise_label("Web Attack \x96 Brute Force") == "Web Attack - Brute Force"
        assert normalise_label("  BENIGN  ") == "BENIGN"

    def test_day_is_derived_from_filename(self):
        assert day_of("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv") == "Friday"
        assert day_of("Monday-WorkingHours.pcap_ISCX.csv") == "Monday"

    @corpus_required
    def test_flows_are_wellformed(self, flows):
        assert len(flows) == SAMPLE_SIZE
        for f in flows:
            assert f.src_ip and f.dst_ip
            assert 0 <= f.src_port <= 65535
            assert 0 <= f.dst_port <= 65535
            assert f.total_bytes >= 0
            assert f.day != "Unknown"

    @corpus_required
    def test_loader_accounts_for_every_row(self):
        """Rows must be explained, not silently dropped - the loader is the
        first place a lossless-preservation claim could quietly break."""
        st = LoadStats()
        list(iter_flows(limit=SAMPLE_SIZE, stats=st))
        assert st.rows_read == st.flows_yielded + st.blank_rows + \
            st.malformed_rows + st.unparseable_timestamps

    @corpus_required
    def test_day_filter_selects_only_that_day(self):
        for f in iter_flows(days=["Monday"], limit=200):
            assert f.day == "Monday"

    @corpus_required
    def test_labels_carry_no_control_characters(self, flows):
        for f in flows:
            assert "\x96" not in f.label
            assert f.label == f.label.strip()


# -- replay ----------------------------------------------------------------


class TestReplay:
    @corpus_required
    def test_vendor_assignment_is_deterministic(self, flows):
        """A metric change must be attributable to the model, not to a
        different random vendor mix between runs."""
        vendors = sorted(RENDERERS)
        first = [assign_vendor(f, vendors) for f in flows[:200]]
        second = [assign_vendor(f, vendors) for f in flows[:200]]
        assert first == second

    @corpus_required
    def test_every_renderer_is_exercised(self, flows):
        seen = {assign_vendor(f, sorted(RENDERERS)) for f in flows}
        assert seen == set(RENDERERS)

    @corpus_required
    def test_ground_truth_never_appears_in_the_log_line(self, flows):
        """The label travels beside the log line, never inside it. If an
        attack name leaked into the rendered text, a parser could extract it
        and the model would learn to read the answer."""
        for ev in replay(iter(flows)):
            if ev.label == "BENIGN":
                continue
            assert ev.label.lower() not in ev.raw_log.lower()
            assert "attack" not in ev.raw_log.lower() or ev.vendor == "suricata_eve"

    @corpus_required
    def test_action_is_not_derived_from_the_label(self, flows):
        """Deriving the device action from ground truth would pre-mark every
        attack as denied and let the model learn `action == deny` instead of
        learning anything about traffic. Both classes must appear on both
        sides of the denied/allowed split."""
        rendered = list(replay(iter(flows)))
        denied_attack = sum(1 for e in rendered if e.is_attack and "deny" in e.raw_log.lower())
        allowed_attack = sum(1 for e in rendered if e.is_attack and "deny" not in e.raw_log.lower())
        assert denied_attack > 0 and allowed_attack > 0, (
            "attacks appear on only one side of the action split - the action "
            "is leaking the label"
        )

    @corpus_required
    def test_rendered_lines_reach_the_real_parsers(self, flows):
        """Phase 2's acceptance criterion.

        Each rendered format must be claimed by the parser that actually
        handles that vendor - not by a generic fallback, and not bypassed.
        """
        orc = PipelineOrchestrator()
        expected = {
            "cisco_asa": {"cisco_asa"},
            "suricata_eve": {"suricata_eve"},
            # FortiGate key-value is handled by the generic KV parser, which is
            # correct: that is the parser that owns `key=value` syslog.
            "fortinet_kv": {"generic_keyvalue"},
        }
        for ev in replay(iter(flows[:400])):
            ctx = orc.process_sync(ev.raw_log)
            assert ctx.parsed_event is not None, f"{ev.vendor} line did not parse"
            assert ctx.parsed_event.parser_name in expected[ev.vendor], (
                f"{ev.vendor} line was claimed by "
                f"{ctx.parsed_event.parser_name}, expected one of {expected[ev.vendor]}"
            )

    @corpus_required
    def test_five_tuple_survives_the_round_trip(self, flows):
        """Render -> parse -> normalize must preserve the flow identity
        exactly, or every behavioural feature is computed against the wrong
        entity."""
        orc = PipelineOrchestrator()
        for ev in replay(iter(flows[:400])):
            n = orc.process_sync(ev.raw_log).normalized_event
            assert n is not None
            f = ev.flow
            assert n.source.ip == f.src_ip
            assert n.destination.ip == f.dst_ip
            assert (n.source.port or 0) == f.src_port
            assert (n.destination.port or 0) == f.dst_port
            assert n.network.protocol == f.protocol

    @corpus_required
    def test_each_format_preserves_what_it_claims_to(self, flows):
        """Formats differ in what they can carry, and the contract records it.

        Cisco ASA genuinely cannot express a forward/backward byte split, so
        it is not asserted to. What each format *does* claim in PRESERVES must
        hold.
        """
        orc = PipelineOrchestrator()
        for ev in replay(iter(flows[:400])):
            n = orc.process_sync(ev.raw_log).normalized_event
            assert n is not None
            f = ev.flow
            claims = preserved_fields(ev.vendor, is_denied(f))
            if "total_bytes" in claims and f.total_bytes > 0:
                assert (n.network.bytes_total or 0) == f.total_bytes
            if "fwd_bytes" in claims and f.fwd_bytes > 0:
                assert (n.source.bytes or 0) == f.fwd_bytes
            if "bwd_bytes" in claims and f.bwd_bytes > 0:
                assert (n.destination.bytes or 0) == f.bwd_bytes

    def test_unknown_vendor_is_rejected_loudly(self):
        from backend.ml.eval.corpus import FlowRecord
        from datetime import datetime
        flow = FlowRecord("1.1.1.1", 1, "2.2.2.2", 2, "TCP", datetime(2017, 7, 3),
                          0, 0, 0, 0, 0, "BENIGN", "Monday", "x.csv")
        with pytest.raises(KeyError):
            render(flow, "no_such_vendor")
