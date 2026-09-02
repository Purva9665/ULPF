import React, { useState } from 'react';
import type { 
  StageEnum, 
  PipelineContext, 
  ExportSchemas 
} from '../types';
import { 
  CheckCircle2, 
  Copy, 
  Check, 
  AlertCircle,
} from 'lucide-react';

interface StageInspectorProps {
  stage: StageEnum;
  context: PipelineContext | null;
  exports?: ExportSchemas | null;
}

export const StageInspector: React.FC<StageInspectorProps> = ({
  stage,
  context,
  exports,
}) => {
  const [copied, setCopied] = useState(false);
  const [exportTab, setExportTab] = useState<'ulpf' | 'elastic' | 'splunk' | 'ocsf' | 'parquet'>('ulpf');

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const generateHexDump = (str: string) => {
    const bytes = new TextEncoder().encode(str);
    const lines: string[] = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const hex = Array.from(chunk)
        .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join(' ');
      const ascii = Array.from(chunk)
        .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
        .join('');
      const offset = i.toString(16).padStart(4, '0').toUpperCase();
      lines.push(`${offset}  ${hex.padEnd(48, ' ')}  |${ascii}|`);
    }
    return lines.join('\n');
  };

  if (!context) {
    return (
      <div className="glass-panel" style={{ margin: '16px 20px', padding: '32px', textAlign: 'center' }}>
        <p style={{ color: '#64748b', fontFamily: 'var(--font-mono)' }}>
          No event in pipeline. Start live stream or step through a log preset to inspect backend state.
        </p>
      </div>
    );
  }

  const rawEvent = context.raw_event;
  const parsedEvent = context.parsed_event;
  const normEvent = context.normalized_event;
  const valEvent = context.validated_event;
  const storedEvent = context.stored_event;
  const mlEvent = context.ml_event;
  const finalEvent = context.final_event;

  return (
    <div className="glass-panel" style={{ margin: '16px 20px', padding: '20px 24px' }}>
      
      {/* Tab/Stage Title Bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="badge badge-cyan" style={{ fontSize: '0.75rem' }}>STAGE {stage}</span>
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
            {stage === 'INGEST' && 'Stage 1: Raw Payload Ingestion & Cryptographic Hashing'}
            {stage === 'PARSE' && 'Stage 2: Heterogeneous Log Dialect Parsing & Token AST'}
            {stage === 'NORMALIZE' && 'Stage 3: Canonical Taxonomy Normalization & Unmapped Retention'}
            {stage === 'VALIDATE' && 'Stage 4: Schema Rules Validation & Data Quality Index'}
            {stage === 'STORE' && 'Stage 5: Dual SQLite WAL & Columnar Storage Engine'}
            {stage === 'ML' && 'Stage 6: Local Scikit-Learn Anomaly Inference & Explainability'}
            {stage === 'STANDARDIZED' && 'Stage 7: Standardized ULPF Event & SIEM/Data Lake Exporter'}
          </h3>
        </div>

        {/* Copy Raw / JSON */}
        <button 
          className="btn-cyber btn-cyber-secondary" 
          onClick={() => copyToClipboard(JSON.stringify(context, null, 2))}
          style={{ fontSize: '0.75rem', padding: '4px 10px' }}
        >
          {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
          <span>{copied ? 'Copied' : 'Copy State JSON'}</span>
        </button>
      </div>

      {/* ================= STAGE 1: INGEST ================= */}
      {stage === 'INGEST' && rawEvent && (
        <div>
          {/* Metadata Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', marginBottom: '16px' }}>
            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(0, 240, 255, 0.2)' }}>
              <div style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Cryptographic SHA-256</div>
              <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: '#00f0ff', wordBreak: 'break-all', marginTop: '2px' }}>
                {rawEvent.raw.sha256_hash}
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <div style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Byte Length / Encoding</div>
              <div style={{ fontSize: '0.9rem', fontFamily: 'var(--font-mono)', color: '#f8fafc', marginTop: '2px', fontWeight: 600 }}>
                {rawEvent.raw.length_bytes} Bytes • {rawEvent.raw.encoding}
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <div style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Source Protocol</div>
              <div style={{ fontSize: '0.9rem', fontFamily: 'var(--font-mono)', color: '#10b981', marginTop: '2px', fontWeight: 600 }}>
                {rawEvent.raw.source_protocol}
              </div>
            </div>
          </div>

          {/* Pristine Raw String */}
          <div style={{ marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#94a3b8', textTransform: 'uppercase' }}>
                Pristine Raw String Payload (Zero Mutation)
              </span>
              <span className="badge badge-green">Zero-Loss Verified</span>
            </div>
            <div className="code-box" style={{ color: '#38bdf8', fontSize: '0.85rem' }}>
              {rawEvent.raw.payload}
            </div>
          </div>

          {/* Hex View */}
          <div>
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#94a3b8', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>
              Hex Byte Inspector
            </span>
            <pre className="hex-dump">{generateHexDump(rawEvent.raw.payload)}</pre>
          </div>
        </div>
      )}

      {/* ================= STAGE 2: PARSE ================= */}
      {stage === 'PARSE' && parsedEvent && (
        <div>
          {/* Parser Info Header */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(168, 85, 247, 0.1)', padding: '12px 16px', borderRadius: '8px', border: '1px solid rgba(168, 85, 247, 0.3)', marginBottom: '16px' }}>
            <div>
              <div style={{ fontSize: '0.7rem', color: '#c084fc', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Selected Parser Plugin</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#f8fafc' }}>
                {parsedEvent.parser_name} <span style={{ color: '#a855f7', fontSize: '0.85rem' }}>({parsedEvent.parser_vendor} • {parsedEvent.parser_product})</span>
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Confidence Score</div>
              <div style={{ fontSize: '1.1rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#10b981' }}>
                {(parsedEvent.confidence_score * 100).toFixed(0)}%
              </div>
            </div>
          </div>

          {/* Extracted Tokens Grid */}
          <div>
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#94a3b8', textTransform: 'uppercase', display: 'block', marginBottom: '8px' }}>
              Extracted AST Token Key-Value Pairs ({Object.keys(parsedEvent.extracted_fields).length} fields extracted)
            </span>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '8px' }}>
              {Object.entries(parsedEvent.extracted_fields).map(([key, val]) => (
                <div 
                  key={key}
                  style={{
                    background: 'rgba(15, 23, 42, 0.7)',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.78rem',
                  }}
                >
                  <div style={{ color: '#a855f7', fontSize: '0.7rem', fontWeight: 600 }}>{key}</div>
                  <div style={{ color: '#e2e8f0', marginTop: '2px', wordBreak: 'break-all' }}>
                    {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ================= STAGE 3: NORMALIZE ================= */}
      {stage === 'NORMALIZE' && normEvent && (
        <div>
          {/* Taxonomy classification summary */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px', marginBottom: '16px' }}>
            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <span style={{ fontSize: '0.65rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Event Action</span>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: normEvent.event.action === 'ALLOW' ? '#10b981' : '#ef4444' }}>
                {normEvent.event.action}
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <span style={{ fontSize: '0.65rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Canonical Severity</span>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: normEvent.event.severity === 'CRITICAL' ? '#ef4444' : '#38bdf8' }}>
                {normEvent.event.severity}
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <span style={{ fontSize: '0.65rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Traffic Direction</span>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#f59e0b' }}>
                {normEvent.network.direction}
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <span style={{ fontSize: '0.65rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Network Protocol</span>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#00f0ff' }}>
                {normEvent.network.protocol} ({normEvent.source.service || normEvent.destination.service || 'PORT ' + (normEvent.destination.port || '')})
              </div>
            </div>
          </div>

          {/* Endpoints */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
            <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(0, 240, 255, 0.2)' }}>
              <span style={{ fontSize: '0.7rem', color: '#00f0ff', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>Source Endpoint</span>
              <div style={{ marginTop: '6px', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                <div>IP: <strong style={{ color: '#f8fafc' }}>{normEvent.source.ip || 'N/A'}</strong></div>
                <div>Port: <strong style={{ color: '#f8fafc' }}>{normEvent.source.port || 'N/A'}</strong></div>
                <div>Private Subnet: <strong style={{ color: normEvent.source.geo?.is_private ? '#10b981' : '#f59e0b' }}>{String(normEvent.source.geo?.is_private)}</strong></div>
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(168, 85, 247, 0.2)' }}>
              <span style={{ fontSize: '0.7rem', color: '#c084fc', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>Destination Endpoint</span>
              <div style={{ marginTop: '6px', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                <div>IP: <strong style={{ color: '#f8fafc' }}>{normEvent.destination.ip || 'N/A'}</strong></div>
                <div>Port: <strong style={{ color: '#f8fafc' }}>{normEvent.destination.port || 'N/A'}</strong> {normEvent.destination.service && <span className="badge badge-purple" style={{ fontSize: '0.6rem' }}>{normEvent.destination.service}</span>}</div>
                <div>Private Subnet: <strong style={{ color: normEvent.destination.geo?.is_private ? '#10b981' : '#f59e0b' }}>{String(normEvent.destination.geo?.is_private)}</strong></div>
              </div>
            </div>
          </div>

          {/* Unmapped Fields (Zero Loss Proof) */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#94a3b8', textTransform: 'uppercase' }}>
                Unmapped Vendor Fields Container (Retained Without Information Loss)
              </span>
              <span className="badge badge-amber">{Object.keys(normEvent.unmapped_fields).length} Custom Fields</span>
            </div>
            <pre className="code-box" style={{ maxHeight: '140px' }}>
              {JSON.stringify(normEvent.unmapped_fields, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {/* ================= STAGE 4: VALIDATE ================= */}
      {stage === 'VALIDATE' && valEvent && (
        <div>
          {/* DQI Score & Hash status */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(16, 185, 129, 0.1)', padding: '14px 18px', borderRadius: '8px', border: '1px solid rgba(16, 185, 129, 0.3)', marginBottom: '16px' }}>
            <div>
              <div style={{ fontSize: '0.7rem', color: '#6ee7b7', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Data Quality Index (DQI)</div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#10b981' }}>
                {valEvent.data_quality_score}%
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>SHA-256 Tamper Verification</div>
              <span className={`badge ${valEvent.hash_verified ? 'badge-green' : 'badge-red'}`} style={{ fontSize: '0.75rem', marginTop: '4px' }}>
                {valEvent.hash_verified ? 'CRYPTOGRAPHIC MATCH' : 'TAMPERED / CORRUPT'}
              </span>
            </div>
          </div>

          {/* Validation Rule Results List */}
          <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#94a3b8', textTransform: 'uppercase', display: 'block', marginBottom: '8px' }}>
            Schema Constraint Verification Checks ({valEvent.validation_checks.length} rules evaluated)
          </span>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {valEvent.validation_checks.map((check, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  background: 'rgba(15, 23, 42, 0.6)',
                  padding: '8px 14px',
                  borderRadius: '6px',
                  border: `1px solid ${check.passed ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.3)'}`,
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.78rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {check.passed ? <CheckCircle2 size={16} color="#10b981" /> : <AlertCircle size={16} color="#ef4444" />}
                  <div>
                    <span style={{ fontWeight: 600, color: '#f8fafc' }}>{check.rule_name}</span>
                    <span style={{ color: '#64748b', marginLeft: '8px' }}>({check.field_checked})</span>
                  </div>
                </div>
                <span style={{ color: check.passed ? '#94a3b8' : '#ef4444' }}>{check.message}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ================= STAGE 5: STORE ================= */}
      {stage === 'STORE' && storedEvent && (
        <div>
          {/* Storage Compression Stats */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', marginBottom: '16px' }}>
            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(245, 158, 11, 0.2)' }}>
              <span style={{ fontSize: '0.65rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Storage Engine</span>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#f59e0b' }}>
                {storedEvent.storage.storage_engine} (Table: {storedEvent.storage.table_name})
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <span style={{ fontSize: '0.65rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Raw vs Compressed Bytes</span>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#f8fafc' }}>
                {storedEvent.storage.raw_size_bytes}B ➔ {storedEvent.storage.compressed_size_bytes}B
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
              <span style={{ fontSize: '0.65rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Footprint Reduction</span>
              <div style={{ fontSize: '1.1rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#10b981' }}>
                {storedEvent.storage.compression_ratio}% reduction
              </div>
            </div>
          </div>

          {/* Database Row Indexing */}
          <div>
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#94a3b8', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>
              Indexed Columns (B-Tree Fast Search in SQLite WAL)
            </span>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '16px' }}>
              {storedEvent.storage.indexed_fields.map((col) => (
                <span key={col} className="badge badge-cyan" style={{ fontSize: '0.7rem' }}>
                  IDX_{col.toUpperCase()}
                </span>
              ))}
            </div>
          </div>

          {/* Columnar Data Model */}
          <div>
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#94a3b8', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>
              Columnar Analytics Memory Representation (Parquet / Arrow Ready)
            </span>
            <pre className="code-box">
              {JSON.stringify(
                {
                  event_id: storedEvent.event_id,
                  timestamp: storedEvent.storage.stored_at,
                  vendor: storedEvent.validated.normalized.observer.vendor,
                  action: storedEvent.validated.normalized.event.action,
                  src_ip: storedEvent.validated.normalized.source.ip,
                  dst_ip: storedEvent.validated.normalized.destination.ip,
                  dst_port: storedEvent.validated.normalized.destination.port,
                  dqi: storedEvent.validated.data_quality_score,
                },
                null,
                2
              )}
            </pre>
          </div>
        </div>
      )}

      {/* ================= STAGE 6: ML ================= */}
      {stage === 'ML' && mlEvent && (
        <div>
          {/* ML Score & Entropy Bar */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', marginBottom: '16px' }}>
            
            {/* Anomaly Score Gauge */}
            <div style={{ background: 'rgba(239, 68, 68, 0.1)', padding: '14px', borderRadius: '8px', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
              <span style={{ fontSize: '0.68rem', color: '#fca5a5', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Isolation Forest Anomaly Score</span>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '4px' }}>
                <span style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: mlEvent.ml.is_anomalous ? '#ef4444' : '#10b981' }}>
                  {mlEvent.ml.anomaly_score.toFixed(2)}
                </span>
                <span className={`badge ${mlEvent.ml.is_anomalous ? 'badge-red anim-pulse-red' : 'badge-green'}`}>
                  {mlEvent.ml.risk_level} RISK
                </span>
              </div>
            </div>

            {/* Shannon Entropy */}
            <div style={{ background: 'rgba(168, 85, 247, 0.1)', padding: '14px', borderRadius: '8px', border: '1px solid rgba(168, 85, 247, 0.3)' }}>
              <span style={{ fontSize: '0.68rem', color: '#d8b4fe', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Shannon Payload Entropy</span>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '4px' }}>
                <span style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#c084fc' }}>
                  {mlEvent.ml.shannon_entropy} bits
                </span>
                <span className="badge badge-purple">
                  {mlEvent.ml.shannon_entropy > 5.0 ? 'HIGH (TUNNEL/CIPHER)' : 'NORMAL'}
                </span>
              </div>
            </div>

            {/* Model Architecture */}
            <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <span style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Inference Architecture</span>
              <div style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)', color: '#38bdf8', marginTop: '6px' }}>
                Local Scikit-Learn IsolationForest
              </div>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                100% Offline • Zero Cloud AI API
              </div>
            </div>
          </div>

          {/* Explainable Feature Attribution Waterfall */}
          <div>
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#94a3b8', textTransform: 'uppercase', display: 'block', marginBottom: '8px' }}>
              Explainable Feature Attribution Waterfall (SHAP-Style Feature Contributions)
            </span>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {mlEvent.ml.feature_contributions.map((feat, idx) => (
                <div
                  key={idx}
                  style={{
                    background: 'rgba(15, 23, 42, 0.7)',
                    padding: '10px 14px',
                    borderRadius: '6px',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#f8fafc' }}>
                      {feat.feature}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: feat.weight > 0.2 ? '#ef4444' : '#38bdf8', fontWeight: 700 }}>
                      Contribution: {(feat.weight * 100).toFixed(1)}%
                    </span>
                  </div>
                  <p style={{ fontSize: '0.74rem', color: '#94a3b8' }}>
                    {feat.description}
                  </p>
                  {/* Visual weight bar */}
                  <div style={{ width: '100%', height: '4px', background: '#1e293b', borderRadius: '2px', marginTop: '6px' }}>
                    <div 
                      style={{
                        width: `${Math.min(feat.weight * 100, 100)}%`,
                        height: '100%',
                        backgroundColor: feat.weight > 0.25 ? '#ef4444' : '#00f0ff',
                        borderRadius: '2px',
                      }} 
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ================= STAGE 7: STANDARDIZED & EXPORT ================= */}
      {stage === 'STANDARDIZED' && (
        <div>
          {/* Target SIEM Format Selector */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '14px', flexWrap: 'wrap' }}>
            <button
              onClick={() => setExportTab('ulpf')}
              className={`btn-cyber ${exportTab === 'ulpf' ? 'btn-cyber-primary' : 'btn-cyber-secondary'}`}
              style={{ fontSize: '0.75rem', padding: '6px 12px' }}
            >
              Canonical ULPF Schema
            </button>
            <button
              onClick={() => setExportTab('elastic')}
              className={`btn-cyber ${exportTab === 'elastic' ? 'btn-cyber-primary' : 'btn-cyber-secondary'}`}
              style={{ fontSize: '0.75rem', padding: '6px 12px' }}
            >
              Elastic ECS 8.x
            </button>
            <button
              onClick={() => setExportTab('splunk')}
              className={`btn-cyber ${exportTab === 'splunk' ? 'btn-cyber-primary' : 'btn-cyber-secondary'}`}
              style={{ fontSize: '0.75rem', padding: '6px 12px' }}
            >
              Splunk HEC JSON
            </button>
            <button
              onClick={() => setExportTab('ocsf')}
              className={`btn-cyber ${exportTab === 'ocsf' ? 'btn-cyber-primary' : 'btn-cyber-secondary'}`}
              style={{ fontSize: '0.75rem', padding: '6px 12px' }}
            >
              OCSF 1.9.0 Activity
            </button>
            <button
              onClick={() => setExportTab('parquet')}
              className={`btn-cyber ${exportTab === 'parquet' ? 'btn-cyber-primary' : 'btn-cyber-secondary'}`}
              style={{ fontSize: '0.75rem', padding: '6px 12px' }}
            >
              Parquet Flat Columnar
            </button>
          </div>

          {/* JSON Payload Display */}
          <div style={{ position: 'relative' }}>
            <button
              className="btn-cyber btn-cyber-secondary"
              onClick={() => {
                let payload = finalEvent;
                if (exports) {
                  if (exportTab === 'elastic') payload = exports.elastic_ecs;
                  else if (exportTab === 'splunk') payload = exports.splunk_hec;
                  else if (exportTab === 'ocsf') payload = exports.ocsf_1_9_0;
                  else if (exportTab === 'parquet') payload = exports.columnar_flat;
                }
                copyToClipboard(JSON.stringify(payload, null, 2));
              }}
              style={{ position: 'absolute', top: '10px', right: '10px', zIndex: 10, fontSize: '0.7rem', padding: '4px 8px' }}
            >
              {copied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
              <span>Copy Schema</span>
            </button>

            <pre className="code-box" style={{ maxHeight: '420px' }}>
              {exportTab === 'ulpf' && JSON.stringify(finalEvent, null, 2)}
              {exportTab === 'elastic' && JSON.stringify(exports?.elastic_ecs || { message: 'Run event to generate Elastic ECS' }, null, 2)}
              {exportTab === 'splunk' && JSON.stringify(exports?.splunk_hec || { message: 'Run event to generate Splunk HEC' }, null, 2)}
              {exportTab === 'ocsf' && JSON.stringify(exports?.ocsf_1_9_0 || { message: 'Run event to generate OCSF 1.9.0' }, null, 2)}
              {exportTab === 'parquet' && JSON.stringify(exports?.columnar_flat || { message: 'Run event to generate Parquet record' }, null, 2)}
            </pre>
          </div>
        </div>
      )}

    </div>
  );
};
