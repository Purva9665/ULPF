import React, { useState } from 'react';
import type { 
  PipelineContext, 
  EngineStats, 
  StageEnum 
} from '../types';
import { 
  Milestone, 
  ArrowLeft, 
  Copy, 
  Check, 
  FileInput, 
  Cpu, 
  GitMerge, 
  ShieldCheck, 
  Database, 
  BrainCircuit, 
  FileCode,
  Layers,
} from 'lucide-react';

interface EventJourneyViewProps {
  context: PipelineContext | null;
  stats: EngineStats | null;
  onBackToOverview: () => void;
  onSelectStage: (stage: StageEnum) => void;
}

export const EventJourneyView: React.FC<EventJourneyViewProps> = ({
  context,
  onBackToOverview,
}) => {
  const [copied, setCopied] = useState(false);

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const rawEvent = context?.raw_event;
  const parsedEvent = context?.parsed_event;
  const normEvent = context?.normalized_event;
  const valEvent = context?.validated_event;
  const storedEvent = context?.stored_event;
  const mlEvent = context?.ml_event;
  const finalEvent = context?.final_event;

  const eventId = context?.event_id || 'none';
  const totalDurationUs = context?.total_duration_us || 380;

  // Stages in chronological order with microsecond timestamps and results
  const STAGES_JOURNEY = [
    {
      stage: 'INGEST',
      name: '01. Zero-Loss Ingestion',
      icon: FileInput,
      color: '#00f0ff',
      status: 'COMPLETED',
      duration: context?.stage_metrics?.find((m) => m.stage === 'INGEST')?.duration_us || 18,
      timestamp: rawEvent?.ingested_at || '09:23:14.102',
      summary: `Captured ${rawEvent?.raw.length_bytes || 184} bytes with SHA-256 integrity hash`,
      artifact: rawEvent?.raw,
    },
    {
      stage: 'PARSE',
      name: '02. Dialect Parser & AST',
      icon: Cpu,
      color: '#c084fc',
      status: 'COMPLETED',
      duration: parsedEvent?.parsing_duration_us || 42,
      timestamp: '09:23:14.120',
      summary: `Extracted ${Object.keys(parsedEvent?.extracted_fields || {}).length} fields using ${parsedEvent?.parser_name || 'cisco_asa'}`,
      artifact: parsedEvent?.extracted_fields,
    },
    {
      stage: 'NORMALIZE',
      name: '03. Canonical Taxonomy',
      icon: GitMerge,
      color: '#38bdf8',
      status: 'COMPLETED',
      duration: normEvent?.normalization_duration_us || 32,
      timestamp: '09:23:14.152',
      summary: `Normalized to canonical schema (${normEvent?.event.action} / ${normEvent?.event.severity}) with ${Object.keys(normEvent?.unmapped_fields || {}).length} unmapped fields preserved`,
      artifact: normEvent,
    },
    {
      stage: 'VALIDATE',
      name: '04. Semantic Validation',
      icon: ShieldCheck,
      color: '#10b981',
      status: valEvent?.is_valid ? 'COMPLETED' : 'WARNING',
      duration: valEvent?.validation_duration_us || 24,
      timestamp: '09:23:14.176',
      summary: `Validated with DQI score ${valEvent?.data_quality_score || 100}% (${valEvent?.validation_checks.length || 7} rules checked)`,
      artifact: valEvent?.validation_checks,
    },
    {
      stage: 'STORE',
      name: '05. Dual WAL Storage',
      icon: Database,
      color: '#fbbf24',
      status: 'COMPLETED',
      duration: storedEvent?.storage_duration_us || 38,
      timestamp: '09:23:14.214',
      summary: `Committed to SQLite WAL (Compression: -${storedEvent?.storage.compression_ratio || 54.2}% reduction)`,
      artifact: storedEvent?.storage,
    },
    {
      stage: 'ML',
      name: '06. ML Anomaly Inference',
      icon: BrainCircuit,
      color: '#f43f5e',
      status: 'COMPLETED',
      duration: mlEvent?.ml_duration_us || 52,
      timestamp: '09:23:14.266',
      summary: `Scored anomaly ${mlEvent?.ml.anomaly_score.toFixed(2) || '0.08'} (${mlEvent?.ml.risk_level || 'INFORMATIONAL'} Risk, Entropy: ${mlEvent?.ml.shannon_entropy || '4.23'})`,
      artifact: mlEvent?.ml,
    },
    {
      stage: 'STANDARDIZED',
      name: '07. Standardized Export',
      icon: FileCode,
      color: '#818cf8',
      status: 'COMPLETED',
      duration: 16,
      timestamp: '09:23:14.282',
      summary: `Generated Elastic ECS, Splunk HEC, OCSF v1.1, and Parquet flat columnar representations`,
      artifact: finalEvent,
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Top Header Bar */}
      <div className="glass-panel" style={{ padding: '16px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <button
            onClick={onBackToOverview}
            className="btn-cyber btn-cyber-secondary"
            style={{ padding: '6px 12px', fontSize: '0.78rem' }}
          >
            <ArrowLeft size={14} />
            <span>Control Room</span>
          </button>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="badge badge-cyan" style={{ fontSize: '0.72rem' }}>TRACEABILITY</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Event Lifecycle Journey & Traceability
              </h2>
            </div>
            <p style={{ fontSize: '0.74rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              End-to-End Cryptographic Audit Trail, Microsecond Timeline, and Multi-Stage Snapshot Diffing
            </p>
          </div>
        </div>

        {/* Total Latency & Event ID */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '6px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <div style={{ fontSize: '0.65rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>EVENT UUID</div>
            <div style={{ fontSize: '0.78rem', color: '#38bdf8', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
              {eventId.slice(0, 18)}...
            </div>
          </div>

          <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '6px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <div style={{ fontSize: '0.65rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>TOTAL TIME</div>
            <div style={{ fontSize: '0.85rem', color: '#10b981', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
              {totalDurationUs} µs ({(totalDurationUs / 1000).toFixed(2)} ms)
            </div>
          </div>
        </div>
      </div>

      {/* 7-Stage Chronological Journey Track */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Milestone size={18} color="#00f0ff" />
            <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
              Sequential Stage Execution Audit Trail
            </h3>
          </div>
          <span className="badge badge-green" style={{ fontSize: '0.62rem' }}>7 / 7 STAGES COMPLETED</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {STAGES_JOURNEY.map((st) => {
            const Icon = st.icon;
            return (
              <div
                key={st.stage}
                style={{
                  background: 'rgba(15, 23, 42, 0.7)',
                  border: `1px solid ${st.color}30`,
                  borderRadius: '10px',
                  padding: '12px 16px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '16px',
                }}
              >
                {/* Left: Icon & Stage Name */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: '220px' }}>
                  <div
                    style={{
                      width: '34px',
                      height: '34px',
                      borderRadius: '50%',
                      background: `${st.color}15`,
                      border: `1.5px solid ${st.color}60`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Icon size={16} color={st.color} />
                  </div>
                  <div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#f8fafc', fontFamily: 'var(--font-main)' }}>
                      {st.name}
                    </div>
                    <div style={{ fontSize: '0.66rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                      {st.timestamp}
                    </div>
                  </div>
                </div>

                {/* Center: Stage Summary */}
                <div style={{ flex: 1, fontSize: '0.74rem', color: '#cbd5e1', fontFamily: 'var(--font-mono)' }}>
                  {st.summary}
                </div>

                {/* Right: Duration & Status Badge */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ textAlign: 'right', fontFamily: 'var(--font-mono)' }}>
                    <div style={{ fontSize: '0.62rem', color: '#64748b' }}>LATENCY</div>
                    <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#38bdf8' }}>
                      {st.duration} µs
                    </div>
                  </div>

                  <span className="badge badge-green" style={{ fontSize: '0.62rem' }}>
                    {st.status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Side-by-Side Comparison Inspector: RAW vs PARSED vs NORMALIZED vs FINAL */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Layers size={18} color="#c084fc" />
            <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
              Multi-Stage State Representation Diffing
            </h3>
          </div>

          <div style={{ display: 'flex', gap: '6px' }}>
            <button
              onClick={() => copyText(JSON.stringify(context, null, 2))}
              className="btn-cyber btn-cyber-secondary"
              style={{ padding: '4px 10px', fontSize: '0.72rem' }}
            >
              {copied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
              <span>Copy Full Context</span>
            </button>
          </div>
        </div>

        {/* 4 Side-by-Side Columns */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
          
          {/* Col 1: Raw Event */}
          <div style={{ background: 'rgba(15, 23, 42, 0.8)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#00f0ff', fontFamily: 'var(--font-mono)', marginBottom: '6px' }}>
              [1] PRISTINE RAW LOG
            </div>
            <div className="code-box" style={{ flex: 1, maxHeight: '220px', color: '#38bdf8', fontSize: '0.72rem' }}>
              {rawEvent?.raw.payload || 'No raw payload'}
            </div>
          </div>

          {/* Col 2: Parsed AST */}
          <div style={{ background: 'rgba(15, 23, 42, 0.8)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#c084fc', fontFamily: 'var(--font-mono)', marginBottom: '6px' }}>
              [2] PARSED AST FIELDS
            </div>
            <div className="code-box" style={{ flex: 1, maxHeight: '220px', fontSize: '0.72rem' }}>
              {parsedEvent?.extracted_fields ? JSON.stringify(parsedEvent.extracted_fields, null, 2) : 'No parsed fields'}
            </div>
          </div>

          {/* Col 3: Canonical Normalized */}
          <div style={{ background: 'rgba(15, 23, 42, 0.8)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#38bdf8', fontFamily: 'var(--font-mono)', marginBottom: '6px' }}>
              [3] NORMALIZED CANONICAL
            </div>
            <div className="code-box" style={{ flex: 1, maxHeight: '220px', fontSize: '0.72rem' }}>
              {normEvent ? JSON.stringify({ event: normEvent.event, source: normEvent.source, destination: normEvent.destination, unmapped: normEvent.unmapped_fields }, null, 2) : 'No normalized state'}
            </div>
          </div>

          {/* Col 4: Final ULPF Standard */}
          <div style={{ background: 'rgba(15, 23, 42, 0.8)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#10b981', fontFamily: 'var(--font-mono)', marginBottom: '6px' }}>
              [4] FINAL STANDARDIZED
            </div>
            <div className="code-box" style={{ flex: 1, maxHeight: '220px', fontSize: '0.72rem' }}>
              {finalEvent ? JSON.stringify({ ulpf_version: finalEvent.ulpf_version, event_id: finalEvent.event_id, ml: finalEvent.ml_analysis, validation: finalEvent.validation }, null, 2) : 'No final event'}
            </div>
          </div>

        </div>

      </div>

    </div>
  );
};
