"""
ULPF Core Domain Models & Processing Contracts
Strict Pydantic models ensuring complete type safety, validation, and zero data loss.
"""

from enum import Enum
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict
import uuid
import hashlib


class StageEnum(str, Enum):
    INGEST = "INGEST"
    PARSE = "PARSE"
    NORMALIZE = "NORMALIZE"
    VALIDATE = "VALIDATE"
    STORE = "STORE"
    ML = "ML"
    STANDARDIZED = "STANDARDIZED"
    EXPORT = "EXPORT"


class StageStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class ActionEnum(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    DROP = "DROP"
    ALERT = "ALERT"
    RESET = "RESET"
    REJECT = "REJECT"
    UNKNOWN = "UNKNOWN"


class SeverityEnum(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RawPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    payload: str = Field(..., description="Pristine, exact byte/string sequence of the raw event")
    sha256_hash: str = Field(..., description="Cryptographic SHA-256 digest of the raw payload for tamper-evidence")
    encoding: str = Field(default="UTF-8", description="Detected text encoding")
    length_bytes: int = Field(..., description="Byte length of the raw event")
    source_protocol: str = Field(default="SYSLOG_UDP", description="Ingestion protocol (SYSLOG, HTTP, VPC_FLOW, BEAT, FILE)")

    @classmethod
    def from_string(cls, raw_str: str, source_protocol: str = "SYSLOG_UDP") -> "RawPayload":
        raw_bytes = raw_str.encode("utf-8")
        digest = hashlib.sha256(raw_bytes).hexdigest()
        return cls(
            payload=raw_str,
            sha256_hash=digest,
            encoding="UTF-8",
            length_bytes=len(raw_bytes),
            source_protocol=source_protocol
        )


class EventMetadata(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ingested_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    timestamp: Optional[str] = None
    category: str = Field(default="NETWORK_TRAFFIC")
    type: str = Field(default="CONNECTION")
    action: ActionEnum = Field(default=ActionEnum.UNKNOWN)
    severity: SeverityEnum = Field(default=SeverityEnum.INFORMATIONAL)
    status: str = Field(default="INITIALIZED")


class NetworkEndpoint(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    domain: Optional[str] = None
    service: Optional[str] = None
    packets: Optional[int] = None
    bytes: Optional[int] = None
    mac: Optional[str] = None
    geo: Dict[str, Any] = Field(default_factory=dict)


class NetworkDetails(BaseModel):
    protocol: str = Field(default="UNKNOWN")
    transport: str = Field(default="IP")
    direction: str = Field(default="UNKNOWN")  # INBOUND, OUTBOUND, INTERNAL
    bytes_total: Optional[int] = None
    packets_total: Optional[int] = None
    session_id: Optional[str] = None
    flags: Optional[str] = None


class ThreatDetails(BaseModel):
    indicator: Optional[str] = None
    signature: Optional[str] = None
    category: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    confidence: Optional[float] = None
    severity: Optional[str] = None


class ObserverDetails(BaseModel):
    vendor: str = Field(default="GENERIC")
    product: str = Field(default="UNKNOWN")
    version: Optional[str] = None
    hostname: Optional[str] = None
    interface: Optional[str] = None


class MLFeatureContribution(BaseModel):
    feature: str
    weight: float
    description: str
    value: Any = None


class MLAnalysisDetails(BaseModel):
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    is_anomalous: bool = Field(default=False)
    risk_level: SeverityEnum = Field(default=SeverityEnum.LOW)
    shannon_entropy: float = Field(default=0.0)
    confidence: float = Field(default=0.95)
    model_version: str = Field(default="ulpf-isolation-forest-v1.0")
    feature_contributions: List[MLFeatureContribution] = Field(default_factory=list)


class StageExecutionMetrics(BaseModel):
    stage: StageEnum
    status: StageStatus
    start_time_us: int
    duration_us: int
    message: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)


class ULPFRawEvent(BaseModel):
    """Stage 1: Pristine Ingested Event"""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ingested_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw: RawPayload
    source_metadata: Dict[str, Any] = Field(default_factory=dict)


class ULPFParsedEvent(BaseModel):
    """Stage 2: Parsed Intermediate AST Event"""
    event_id: str
    raw: RawPayload
    parser_name: str
    parser_vendor: str
    parser_product: str
    confidence_score: float
    extracted_fields: Dict[str, Any] = Field(default_factory=dict)
    tokens: List[Dict[str, Any]] = Field(default_factory=list)
    parsing_duration_us: int = 0


class ULPFNormalizedEvent(BaseModel):
    """Stage 3: Canonical Taxonomy Mapped Event"""
    event_id: str
    raw: RawPayload
    event: EventMetadata
    source: NetworkEndpoint = Field(default_factory=NetworkEndpoint)
    destination: NetworkEndpoint = Field(default_factory=NetworkEndpoint)
    network: NetworkDetails = Field(default_factory=NetworkDetails)
    threat: Optional[ThreatDetails] = None
    observer: ObserverDetails = Field(default_factory=ObserverDetails)
    unmapped_fields: Dict[str, Any] = Field(default_factory=dict)
    mapping_rule_used: str = "default_canonical_v1"
    normalization_duration_us: int = 0


class ValidationCheckResult(BaseModel):
    rule_name: str
    field_checked: str
    passed: bool
    message: str
    severity: str = "INFO"


class ULPFValidatedEvent(BaseModel):
    """Stage 4: Validated & Quality Scored Event"""
    event_id: str
    normalized: ULPFNormalizedEvent
    is_valid: bool
    data_quality_score: float = Field(default=100.0, ge=0.0, le=100.0)
    hash_verified: bool = True
    validation_checks: List[ValidationCheckResult] = Field(default_factory=list)
    validation_duration_us: int = 0


class StorageMetadata(BaseModel):
    storage_engine: str = "SQLite-WAL"
    table_name: str = "ulpf_events"
    row_id: Optional[int] = None
    raw_size_bytes: int
    compressed_size_bytes: int
    compression_ratio: float
    indexed_fields: List[str] = Field(default_factory=list)
    stored_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ULPFStoredEvent(BaseModel):
    """Stage 5: Stored & Indexed Event"""
    event_id: str
    validated: ULPFValidatedEvent
    storage: StorageMetadata
    storage_duration_us: int = 0


class ULPFMLEvent(BaseModel):
    """Stage 6: ML & Anomaly Scored Event"""
    event_id: str
    stored: ULPFStoredEvent
    ml: MLAnalysisDetails
    ml_duration_us: int = 0


class ULPFFinalEvent(BaseModel):
    """Stage 7: Final Analytics & SIEM-Ready Standardized Event"""
    ulpf_version: str = "1.0.0"
    event_id: str
    event: EventMetadata
    source: NetworkEndpoint
    destination: NetworkEndpoint
    network: NetworkDetails
    threat: Optional[ThreatDetails] = None
    observer: ObserverDetails
    raw_event: RawPayload
    unmapped_fields: Dict[str, Any]
    ml_analysis: MLAnalysisDetails
    validation: Dict[str, Any]
    storage: StorageMetadata
    pipeline_telemetry: Dict[str, Any]


class PipelineContext(BaseModel):
    """Complete Execution Context for an event passing through the pipeline"""
    event_id: str
    current_stage: StageEnum = StageEnum.INGEST
    stages_completed: List[StageEnum] = Field(default_factory=list)
    stage_metrics: List[StageExecutionMetrics] = Field(default_factory=list)
    
    # State snapshots at each stage
    raw_event: Optional[ULPFRawEvent] = None
    parsed_event: Optional[ULPFParsedEvent] = None
    normalized_event: Optional[ULPFNormalizedEvent] = None
    validated_event: Optional[ULPFValidatedEvent] = None
    stored_event: Optional[ULPFStoredEvent] = None
    ml_event: Optional[ULPFMLEvent] = None
    final_event: Optional[ULPFFinalEvent] = None
    
    total_duration_us: int = 0
    is_completed: bool = False
    error: Optional[str] = None
