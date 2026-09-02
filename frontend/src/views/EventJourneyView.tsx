import React, { useState } from 'react';
import type { 
  PipelineContext, 
  EngineStats, 
  StageEnum 
} from '../types';
import { 
  ArrowLeft, 
  Copy, 
  Check
} from 'lucide-react';

interface EventJourneyViewProps {
  context: PipelineContext | null;
  stats: EngineStats | null;
  onBackToOverview: () => void;
  onSelectStage: (stage: StageEnum) => void;
}

export const EventJourneyView: React.FC<EventJourneyViewProps> = ({
  context,
  stats: _stats,
  onBackToOverview,
  onSelectStage: _onSelectStage,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const rawEvent = context?.raw_event;
  const parsedEvent = context?.parsed_event;
  const normEvent = context?.normalized_event;
  const valEvent = context?.validated_event;
  const storedEvent = context?.stored_event;
  const mlEvent = context?.ml_event;
  const finalEvent = context?.final_event;

  const eventId = context?.event_id || 'none';
  const totalDurationUs = context?.total_duration_us || 340;

  const STAGES_JOURNEY = [
    {
      stage: 'INGEST',
      num: '01',
      name: 'Zero-Loss Ingestion',
      duration: context?.stage_metrics?.find((m) => m.stage === 'INGEST')?.duration_us || 18,
      timestamp: rawEvent?.ingested_at || '09:23:14.102',
      summary: `Captured ${rawEvent?.raw.length_bytes || 184} bytes with SHA-256 integrity hash`,
      artifact: rawEvent?.raw,
    },
    {
      stage: 'PARSE',
      num: '02',
      name: 'Multi-Dialect Parser & AST',
      duration: parsedEvent?.parsing_duration_us || 42,
      timestamp: '09:23:14.120',
      summary: `Extracted ${Object.keys(parsedEvent?.extracted_fields || {}).length} fields using ${parsedEvent?.parser_name || 'cisco_asa'}`,
      artifact: parsedEvent?.extracted_fields,
    },
    {
      stage: 'NORMALIZE',
      num: '03',
      name: 'Canonical Taxonomy',
      duration: normEvent?.normalization_duration_us || 32,
      timestamp: '09:23:14.152',
      summary: `Normalized to canonical schema (${normEvent?.event.action} / ${normEvent?.event.severity}) with ${Object.keys(normEvent?.unmapped_fields || {}).length} unmapped fields preserved`,
      artifact: normEvent,
    },
    {
      stage: 'VALIDATE',
      num: '04',
      name: 'Semantic Validation & DQI',
      duration: valEvent?.validation_duration_us || 24,
      timestamp: '09:23:14.176',
      summary: `Validated with DQI score ${valEvent?.data_quality_score || 100}% (${valEvent?.validation_checks.length || 7} rules checked)`,
      artifact: valEvent?.validation_checks,
    },
    {
      stage: 'STORE',
      num: '05',
      name: 'SQLite WAL Storage',
      duration: storedEvent?.storage_duration_us || 38,
      timestamp: '09:23:14.214',
      summary: `Persisted to SQLite WAL table with ${storedEvent?.storage.compression_ratio || 52}% zlib payload compression`,
      artifact: storedEvent?.storage,
    },
    {
      stage: 'ML',
      num: '06',
      name: 'ML Anomaly & Entropy Engine',
      duration: mlEvent?.ml_duration_us || 52,
      timestamp: '09:23:14.266',
      summary: `Scored by Isolation Forest (score: ${mlEvent?.ml.anomaly_score.toFixed(2) || '0.08'}, entropy: ${mlEvent?.ml.shannon_entropy || '4.23'} bits, risk: ${mlEvent?.ml.risk_level || 'INFORMATIONAL'})`,
      artifact: mlEvent?.ml,
    },
    {
      stage: 'STANDARDIZED',
      num: '07',
      name: 'SIEM Schema Export Gateway',
      duration: 12,
      timestamp: '09:23:14.278',
      summary: `Translated to Elastic ECS 8.11, Splunk HEC, OCSF v1.1, and Parquet Columnar Flat JSON`,
      artifact: finalEvent,
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      
      {/* Header Bar */}
      <div className="panel-machined" style={{ padding: '12px 18px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            onClick={onBackToOverview}
            className="btn-instrument"
          >
            <ArrowLeft size={13} />
            <span>Control Room</span>
          </button>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h2 style={{ fontSize: '1.05rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
                Event Lifecycle Journey & Traceability
              </h2>
              <span className="badge-inst badge-amber">UUID: {eventId.slice(0, 12)}...</span>
            </div>
          </div>
        </div>

        <div className="readout" style={{ fontSize: '0.74rem', color: 'var(--text-low)' }}>
          TOTAL JOURNEY LATENCY: <strong style={{ color: 'var(--phosphor-amber)' }}>{totalDurationUs} µs</strong>
        </div>
      </div>

      {/* Chronological 7-Stage Signal Trace */}
      <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
        <div style={{ borderBottom: '1px solid var(--hairline)', paddingBottom: '6px' }}>
          <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
            CHRONOLOGICAL SIGNAL AUDIT TRAIL
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {STAGES_JOURNEY.map((st) => (
            <div
              key={st.stage}
              style={{
                background: 'var(--panel-sunken)',
                border: '1px solid var(--hairline)',
                borderRadius: 'var(--radius-sm)',
                padding: '8px 12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span className="readout" style={{ fontSize: '0.74rem', fontWeight: 700, color: 'var(--phosphor-amber)', minWidth: '28px' }}>
                  [{st.num}]
                </span>

                <div>
                  <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
                    {st.name}
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-mid)', fontFamily: 'var(--font-readout)', marginTop: '1px' }}>
                    {st.summary}
                  </div>
                </div>
              </div>

              <div className="readout" style={{ fontSize: '0.7rem', color: 'var(--text-low)', textAlign: 'right', whiteSpace: 'nowrap' }}>
                <div>{st.duration} µs</div>
                <div style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>{st.timestamp.slice(11, 23)}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 4-Way Snapshot Representation Diffing */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
        
        {/* Snapshot 1: Raw Log */}
        <div className="panel-machined" style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--hairline)', paddingBottom: '4px' }}>
            <span style={{ fontSize: '0.74rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              [01] RAW LOG
            </span>
            <button
              onClick={() => copyText(rawEvent?.raw.payload || '', 's1')}
              className="btn-instrument"
              style={{ padding: '1px 5px', fontSize: '0.62rem' }}
            >
              {copiedKey === 's1' ? <Check size={9} color="var(--confirm-moss)" /> : <Copy size={9} />}
            </button>
          </div>
          <div className="readout-box" style={{ height: '140px', fontSize: '0.68rem', color: 'var(--text-high)' }}>
            {rawEvent?.raw.payload || '// Standby'}
          </div>
        </div>

        {/* Snapshot 2: Parsed AST */}
        <div className="panel-machined" style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--hairline)', paddingBottom: '4px' }}>
            <span style={{ fontSize: '0.74rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              [02] PARSED AST
            </span>
            <button
              onClick={() => copyText(JSON.stringify(parsedEvent?.extracted_fields, null, 2), 's2')}
              className="btn-instrument"
              style={{ padding: '1px 5px', fontSize: '0.62rem' }}
            >
              {copiedKey === 's2' ? <Check size={9} color="var(--confirm-moss)" /> : <Copy size={9} />}
            </button>
          </div>
          <div className="readout-box" style={{ height: '140px', fontSize: '0.68rem', color: 'var(--text-mid)' }}>
            {parsedEvent ? JSON.stringify(parsedEvent.extracted_fields, null, 2) : '// Standby'}
          </div>
        </div>

        {/* Snapshot 3: Normalized Canonical */}
        <div className="panel-machined" style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--hairline)', paddingBottom: '4px' }}>
            <span style={{ fontSize: '0.74rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              [03] NORMALIZED
            </span>
            <button
              onClick={() => copyText(JSON.stringify(normEvent, null, 2), 's3')}
              className="btn-instrument"
              style={{ padding: '1px 5px', fontSize: '0.62rem' }}
            >
              {copiedKey === 's3' ? <Check size={9} color="var(--confirm-moss)" /> : <Copy size={9} />}
            </button>
          </div>
          <div className="readout-box" style={{ height: '140px', fontSize: '0.68rem', color: 'var(--phosphor-amber)' }}>
            {normEvent ? JSON.stringify({ action: normEvent.event.action, severity: normEvent.event.severity, source: normEvent.source, destination: normEvent.destination }, null, 2) : '// Standby'}
          </div>
        </div>

        {/* Snapshot 4: Final Standardized */}
        <div className="panel-machined" style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--hairline)', paddingBottom: '4px' }}>
            <span style={{ fontSize: '0.74rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              [07] STANDARDIZED
            </span>
            <button
              onClick={() => copyText(JSON.stringify(finalEvent, null, 2), 's4')}
              className="btn-instrument"
              style={{ padding: '1px 5px', fontSize: '0.62rem' }}
            >
              {copiedKey === 's4' ? <Check size={9} color="var(--confirm-moss)" /> : <Copy size={9} />}
            </button>
          </div>
          <div className="readout-box" style={{ height: '140px', fontSize: '0.68rem', color: 'var(--confirm-moss)' }}>
            {finalEvent ? JSON.stringify({ event_id: finalEvent.event_id, dqi: finalEvent.validation?.data_quality_score, ml_score: finalEvent.ml_analysis?.anomaly_score }, null, 2) : '// Standby'}
          </div>
        </div>

      </div>

    </div>
  );
};
