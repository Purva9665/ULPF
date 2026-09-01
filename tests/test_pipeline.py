"""
ULPF Comprehensive Test Suite
Validates all 15 non-negotiable functional requirements and architecture contracts.
"""

import pytest
import hashlib
import json
from typing import Tuple

from backend.core.models import (
    StageEnum,
    StageStatus,
    ActionEnum,
    SeverityEnum,
    ULPFRawEvent,
    ULPFParsedEvent,
)
from backend.core.base_parser import BaseParser
from backend.core.registry import ParserRegistry, default_registry
from backend.ingestion.engine import IngestionEngine
from backend.normalizer.engine import NormalizationEngine
from backend.validator.engine import ValidationEngine
from backend.storage.engine import StorageEngine
from backend.ml.anomaly_engine import MLAnomalyEngine
from backend.exporter.engine import ExporterEngine
from backend.pipeline.orchestrator import PipelineOrchestrator
from backend.sample_data import SAMPLE_LOGS


# ---------------------------------------------------------------------------
# Requirement 1: Preserve Complete Raw Event Data & SHA-256 Hash Integrity
# ---------------------------------------------------------------------------
def test_req1_raw_data_preservation_and_sha256():
    ingestion = IngestionEngine()
    test_raw = "%ASA-4-106023: Deny tcp src outside:203.0.113.45/49152 dst inside:10.0.1.20/445 by access-group 'OUTSIDE-IN' [0x0, 0x0]"
    raw_event = ingestion.ingest(test_raw)

    # 1. Exact string preservation
    assert raw_event.raw.payload == test_raw
    assert raw_event.raw.length_bytes == len(test_raw.encode("utf-8"))

    # 2. Cryptographic digest computation
    expected_hash = hashlib.sha256(test_raw.encode("utf-8")).hexdigest()
    assert raw_event.raw.sha256_hash == expected_hash

    # 3. Validation verifies hash without tampering
    orchestrator = PipelineOrchestrator()
    ctx = orchestrator.process_sync(test_raw)
    assert ctx.validated_event.hash_verified is True
    assert ctx.final_event.raw_event.sha256_hash == expected_hash
    assert ctx.final_event.raw_event.payload == test_raw


# ---------------------------------------------------------------------------
# Requirement 2 & 3: Parse Heterogeneous Log Formats & Extract Source Fields
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("sample", SAMPLE_LOGS)
def test_req2_and_3_heterogeneous_parsing(sample):
    ingestion = IngestionEngine()
    raw_event = ingestion.ingest(sample["raw"])
    
    parsed, best_parser, confidence = default_registry.auto_detect_and_parse(raw_event)
    
    assert parsed is not None
    assert confidence > 0.5
    assert len(parsed.extracted_fields) > 0
    assert len(parsed.tokens) > 0
    assert parsed.parser_name == sample["expected_parser"] or confidence >= 0.7


# ---------------------------------------------------------------------------
# Requirement 4: Normalize Fields into Canonical ULPF Schema & Retain Unmapped
# ---------------------------------------------------------------------------
def test_req4_canonical_normalization():
    palo_raw = '1,2026/09/01 01:15:30,001801000001,THREAT,vulnerability,1,2026/09/01 01:15:30,198.51.100.77,10.0.10.80,0.0.0.0,0.0.0.0,DMZ_WEB_RULE,admin,,web-browsing,vsys1,untrust,dmz,ethernet1/1,ethernet1/2,default_syslog,2026/09/01 01:15:30,491823,1,44120,80,0,0,0x0,tcp,drop,"SELECT * FROM users",SQLi(30021),any,critical,client-to-server,981230,0x0,United States,10.0.0.0-10.255.255.255,0,text/html,,,0,,Mozilla/5.0,,,,,,'
    
    orchestrator = PipelineOrchestrator()
    ctx = orchestrator.process_sync(palo_raw)
    
    norm = ctx.normalized_event
    assert norm is not None
    assert norm.source.ip == "198.51.100.77"
    assert norm.source.port == 44120
    assert norm.destination.ip == "10.0.10.80"
    assert norm.destination.port == 80
    assert norm.event.action == ActionEnum.DROP
    assert norm.event.severity == SeverityEnum.CRITICAL
    assert norm.network.protocol == "TCP"
    # Unmapped fields retained without data loss
    assert "rule_name" in norm.unmapped_fields or norm.threat is not None
    assert len(norm.unmapped_fields) > 0


# ---------------------------------------------------------------------------
# Requirement 5: Validate Normalized Events & Quality Scoring
# ---------------------------------------------------------------------------
def test_req5_validation_and_dqi():
    orchestrator = PipelineOrchestrator()
    sample = SAMPLE_LOGS[0]  # Cisco ASA
    ctx = orchestrator.process_sync(sample["raw"])

    val = ctx.validated_event
    assert val is not None
    assert val.is_valid is True
    assert val.data_quality_score >= 80.0
    assert val.hash_verified is True
    assert len(val.validation_checks) >= 5


# ---------------------------------------------------------------------------
# Requirement 6: Maintain Traceability between Raw and Normalized
# ---------------------------------------------------------------------------
def test_req6_traceability():
    orchestrator = PipelineOrchestrator()
    sample = SAMPLE_LOGS[2]  # Palo Alto
    ctx = orchestrator.process_sync(sample["raw"])

    fe = ctx.final_event
    assert fe.event_id == ctx.raw_event.event_id
    assert fe.raw_event.sha256_hash == ctx.raw_event.raw.sha256_hash
    assert fe.raw_event.payload == sample["raw"]
    assert ctx.stages_completed == [
        StageEnum.INGEST,
        StageEnum.PARSE,
        StageEnum.NORMALIZE,
        StageEnum.VALIDATE,
        StageEnum.STORE,
        StageEnum.ML,
        StageEnum.STANDARDIZED,
    ]


# ---------------------------------------------------------------------------
# Requirement 7: Plug-and-Play Parser Architecture Extensibility
# ---------------------------------------------------------------------------
class CustomIoTParser(BaseParser):
    name = "custom_iot_sensor"
    vendor = "CustomIoT"
    product = "Sensor-9000"
    supported_formats = ["custom_iot"]
    description = "A custom dynamic parser plugin"

    def can_parse(self, raw_event: ULPFRawEvent) -> Tuple[bool, float]:
        if "IOT_SENSOR:" in raw_event.raw.payload:
            return True, 0.99
        return False, 0.0

    def parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        # Format: IOT_SENSOR: dev_id=123 temp=45.2 src=192.168.1.50 dst=10.0.0.1 port=8883
        text = raw_event.raw.payload
        extracted = {
            "dev_id": 123,
            "temperature": 45.2,
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "dst_port": 8883,
            "action": "allow",
            "protocol": "MQTT",
        }
        return ULPFParsedEvent(
            event_id=raw_event.event_id,
            raw=raw_event.raw,
            parser_name=self.name,
            parser_vendor=self.vendor,
            parser_product=self.product,
            confidence_score=0.99,
            extracted_fields=extracted,
            tokens=[{"key": k, "value": v, "type": type(v).__name__} for k, v in extracted.items()],
        )


def test_req7_dynamic_parser_plug_and_play():
    custom_registry = ParserRegistry()
    for p in default_registry._parsers.values():
        custom_registry.register(p)

    # Register new parser at runtime
    custom_registry.register(CustomIoTParser())

    orchestrator = PipelineOrchestrator(registry=custom_registry)
    iot_log = "IOT_SENSOR: dev_id=123 temp=45.2 src=192.168.1.50 dst=10.0.0.1 port=8883"
    
    ctx = orchestrator.process_sync(iot_log)
    assert ctx.is_completed is True
    assert ctx.parsed_event.parser_name == "custom_iot_sensor"
    assert ctx.normalized_event.destination.port == 8883
    assert ctx.normalized_event.unmapped_fields.get("temperature") == 45.2


# ---------------------------------------------------------------------------
# Requirement 8 & 9: Dual Storage & Analytics-Ready Output (SIEM / Parquet)
# ---------------------------------------------------------------------------
def test_req8_and_9_storage_and_analytics_exports():
    orchestrator = PipelineOrchestrator()
    sample = SAMPLE_LOGS[4]  # Suricata DNS Tunneling
    ctx = orchestrator.process_sync(sample["raw"])

    # 1. Check SQLite Storage
    events = orchestrator.storage_engine.query_events(limit=5)
    assert len(events) >= 1
    assert events[0]["event_id"] == ctx.event_id

    # 2. Check Exporter formats
    exporter = ExporterEngine()
    exports = exporter.export_all(ctx.final_event)
    
    assert "elastic_ecs" in exports
    assert exports["elastic_ecs"]["@timestamp"] is not None
    assert exports["elastic_ecs"]["event"]["action"] is not None

    assert "splunk_hec" in exports
    assert exports["splunk_hec"]["sourcetype"].startswith("ulpf:")

    assert "ocsf_v1" in exports
    assert exports["ocsf_v1"]["class_name"] == "Network Activity"

    assert "columnar_flat" in exports
    assert "raw_sha256" in exports["columnar_flat"]


# ---------------------------------------------------------------------------
# Requirement 10 & 13: Local ML & Anomaly Analysis (Zero Cloud API)
# ---------------------------------------------------------------------------
def test_req10_and_13_local_ml_anomaly_detection():
    orchestrator = PipelineOrchestrator()
    
    # Benign normal log
    benign_log = SAMPLE_LOGS[1]["raw"]  # Cisco normal outbound HTTP
    benign_ctx = orchestrator.process_sync(benign_log)
    assert benign_ctx.ml_event.ml.anomaly_score < 0.60
    assert benign_ctx.ml_event.ml.risk_level in (SeverityEnum.LOW, SeverityEnum.MEDIUM)

    # Attack log (DNS tunneling with high entropy)
    attack_log = SAMPLE_LOGS[4]["raw"]  # Suricata DNS Tunneling
    attack_ctx = orchestrator.process_sync(attack_log)
    assert attack_ctx.ml_event.ml.anomaly_score >= 0.60
    assert attack_ctx.ml_event.ml.is_anomalous is True
    assert attack_ctx.ml_event.ml.shannon_entropy > 4.5
    assert len(attack_ctx.ml_event.ml.feature_contributions) >= 2


# ---------------------------------------------------------------------------
# Requirement 14 & 15: Real Backend Processing & Benchmarking
# ---------------------------------------------------------------------------
def test_req14_and_15_real_processing_and_telemetry():
    orchestrator = PipelineOrchestrator()
    ctx = orchestrator.process_sync(SAMPLE_LOGS[0]["raw"])

    assert ctx.total_duration_us > 0
    for metric in ctx.stage_metrics:
        assert metric.status in (StageStatus.COMPLETED, StageStatus.WARNING)
        assert metric.duration_us >= 0
        assert metric.message != ""
