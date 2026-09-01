/**
 * ULPF Frontend Type Definitions
 * Exact mirrors of the backend Python domain models.
 */

export type StageEnum = 'INGEST' | 'PARSE' | 'NORMALIZE' | 'VALIDATE' | 'STORE' | 'ML' | 'STANDARDIZED' | 'EXPORT';

export type StageStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'WARNING' | 'ERROR' | 'SKIPPED';

export type ActionEnum = 'ALLOW' | 'DENY' | 'DROP' | 'ALERT' | 'RESET' | 'REJECT' | 'UNKNOWN';

export type SeverityEnum = 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface RawPayload {
  payload: string;
  sha256_hash: string;
  encoding: string;
  length_bytes: number;
  source_protocol: string;
}

export interface EventMetadata {
  id: string;
  ingested_at: string;
  timestamp?: string;
  category: string;
  type: string;
  action: ActionEnum;
  severity: SeverityEnum;
  status: string;
}

export interface NetworkEndpoint {
  ip?: string;
  port?: number;
  domain?: string;
  service?: string;
  packets?: number;
  bytes?: number;
  mac?: string;
  geo: Record<string, any>;
}

export interface NetworkDetails {
  protocol: string;
  transport: string;
  direction: string;
  bytes_total?: number;
  packets_total?: number;
  session_id?: string;
  flags?: string;
}

export interface ThreatDetails {
  indicator?: string;
  signature?: string;
  category?: string;
  mitre_technique_id?: string;
  confidence?: number;
  severity?: string;
}

export interface ObserverDetails {
  vendor: string;
  product: string;
  version?: string;
  hostname?: string;
  interface?: string;
}

export interface MLFeatureContribution {
  feature: string;
  weight: number;
  description: string;
  value?: any;
}

export interface MLAnalysisDetails {
  anomaly_score: number;
  is_anomalous: boolean;
  risk_level: SeverityEnum;
  shannon_entropy: number;
  confidence: number;
  model_version: string;
  feature_contributions: MLFeatureContribution[];
}

export interface StageExecutionMetrics {
  stage: StageEnum;
  status: StageStatus;
  start_time_us: number;
  duration_us: number;
  message: string;
  details: Record<string, any>;
}

export interface ValidationCheckResult {
  rule_name: string;
  field_checked: string;
  passed: boolean;
  message: string;
  severity: string;
}

export interface StorageMetadata {
  storage_engine: string;
  table_name: string;
  row_id?: number;
  raw_size_bytes: number;
  compressed_size_bytes: number;
  compression_ratio: number;
  indexed_fields: string[];
  stored_at: string;
}

export interface ULPFRawEvent {
  event_id: string;
  ingested_at: string;
  raw: RawPayload;
  source_metadata: Record<string, any>;
}

export interface ULPFParsedEvent {
  event_id: string;
  raw: RawPayload;
  parser_name: string;
  parser_vendor: string;
  parser_product: string;
  confidence_score: number;
  extracted_fields: Record<string, any>;
  tokens: Array<{ key: string; value: any; type: string }>;
  parsing_duration_us: number;
}

export interface ULPFNormalizedEvent {
  event_id: string;
  raw: RawPayload;
  event: EventMetadata;
  source: NetworkEndpoint;
  destination: NetworkEndpoint;
  network: NetworkDetails;
  threat?: ThreatDetails;
  observer: ObserverDetails;
  unmapped_fields: Record<string, any>;
  mapping_rule_used: string;
  normalization_duration_us: number;
}

export interface ULPFValidatedEvent {
  event_id: string;
  normalized: ULPFNormalizedEvent;
  is_valid: boolean;
  data_quality_score: number;
  hash_verified: boolean;
  validation_checks: ValidationCheckResult[];
  validation_duration_us: number;
}

export interface ULPFStoredEvent {
  event_id: string;
  validated: ULPFValidatedEvent;
  storage: StorageMetadata;
  storage_duration_us: number;
}

export interface ULPFMLEvent {
  event_id: string;
  stored: ULPFStoredEvent;
  ml: MLAnalysisDetails;
  ml_duration_us: number;
}

export interface ULPFFinalEvent {
  ulpf_version: string;
  event_id: string;
  event: EventMetadata;
  source: NetworkEndpoint;
  destination: NetworkEndpoint;
  network: NetworkDetails;
  threat?: ThreatDetails;
  observer: ObserverDetails;
  raw_event: RawPayload;
  unmapped_fields: Record<string, any>;
  ml_analysis: MLAnalysisDetails;
  validation: Record<string, any>;
  storage: StorageMetadata;
  pipeline_telemetry: Record<string, any>;
}

export interface PipelineContext {
  event_id: string;
  current_stage: StageEnum;
  stages_completed: StageEnum[];
  stage_metrics: StageExecutionMetrics[];
  raw_event?: ULPFRawEvent;
  parsed_event?: ULPFParsedEvent;
  normalized_event?: ULPFNormalizedEvent;
  validated_event?: ULPFValidatedEvent;
  stored_event?: ULPFStoredEvent;
  ml_event?: ULPFMLEvent;
  final_event?: ULPFFinalEvent;
  total_duration_us: number;
  is_completed: boolean;
  error?: string;
}

export interface SampleLog {
  id: string;
  title: string;
  vendor: string;
  product: string;
  category: string;
  severity: SeverityEnum;
  raw: string;
  description: string;
  expected_parser: string;
}

export interface EngineStats {
  storage: {
    total_events: number;
    total_raw_bytes: number;
    total_compressed_bytes: number;
    overall_compression_ratio: number;
    avg_data_quality_score: number;
    total_anomalies: number;
  };
  is_streaming: boolean;
  current_eps: number;
  parsers_count: number;
  buffered_contexts_count: number;
  avg_duration_us?: number;
  total_processed?: number;
  failed_count?: number;
}

export interface TimelineItem {
  id: string;
  eventId: string;
  stage: StageEnum;
  status: StageStatus;
  timestamp: string;
  title: string;
  subtitle: string;
  metric?: StageExecutionMetrics;
  snapshot?: any;
}

export interface ExportSchemas {
  ulpf_standard: any;
  elastic_ecs: any;
  splunk_hec: any;
  ocsf_v1: any;
  columnar_flat: any;
}

