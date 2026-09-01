import React, { useState } from 'react';
import type { 
  PipelineContext, 
  StageEnum, 
  ExportSchemas 
} from '../types';
import { 
  Fingerprint, 
  Copy, 
  Check, 
  ShieldCheck, 
  Database, 
  BrainCircuit, 
  FileCode, 
  Layers, 
  CheckCircle2, 
  AlertTriangle, 
  Terminal,
  Activity,
} from 'lucide-react';

interface CurrentEventCardProps {
  context: PipelineContext | null;
  selectedStage?: StageEnum;
  onSelectStage?: (stage: StageEnum) => void;
  exports: ExportSchemas | null;
}

export const CurrentEventCard: React.FC<CurrentEventCardProps> = ({
  context,
  exports,
}) => {
  const [activeTab, setActiveTab] = useState<'raw' | 'ast' | 'canonical' | 'validation' | 'ml' | 'storage' | 'exports'>('raw');
  const [copied, setCopied] = useState(false);
  const [exportFormat, setExportFormat] = useState<'ulpf' | 'elastic' | 'splunk' | 'ocsf' | 'parquet'>('ulpf');

  const copyText = (text: string) => {
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
      <div className="glass-panel" style={{ padding: '24px', textAlign: 'center' }}>
        <p style={{ color: '#64748b', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
          No active event in pipeline. Inject a log preset or start live streaming to observe telemetry.
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

  // Metadata summary
  const eventId = context.event_id || 'unknown';
  const parserName = parsedEvent?.parser_name || 'auto-detecting...';
  const srcEndpoint = normEvent?.source ? `${normEvent.source.ip || '*'}:${normEvent.source.port || '*'}` : 'N/A';
  const dstEndpoint = normEvent?.destination ? `${normEvent.destination.ip || '*'}:${normEvent.destination.port || '*'}` : 'N/A';

  return (
    <div className="glass-panel" style={{ padding: '20px 24px' }}>
      
      {/* Top Banner: Event ID, Format, Current Stage, and Microsecond Latency */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '14px', flexWrap: 'wrap', gap: '12px' }}>
        
        {/* Left: Event ID & Source */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div 
            style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              background: 'rgba(0, 240, 255, 0.1)',
              border: '1px solid rgba(0, 240, 255, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Fingerprint size={20} color="#00f0ff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '0.82rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#f8fafc' }}>
                Event ID: {eventId.slice(0, 18)}...
              </span>
              <button 
                onClick={() => copyText(eventId)}
                style={{ background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer', padding: '2px' }}
                title="Copy Full UUID"
              >
                {copied ? <Check size={13} color="#10b981" /> : <Copy size={13} />}
              </button>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
              <span>Source: <strong style={{ color: '#38bdf8' }}>{srcEndpoint}</strong></span>
              <span>➔</span>
              <span>Dest: <strong style={{ color: '#c084fc' }}>{dstEndpoint}</strong></span>
              <span>•</span>
              <span>Format: <strong style={{ color: '#34d399' }}>{parserName}</strong></span>
            </div>
          </div>
        </div>

        {/* Right: Stage Badge & Latency */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.65rem', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Current Stage</div>
            <span className="badge badge-cyan" style={{ fontSize: '0.72rem' }}>
              STAGE {context.current_stage}
            </span>
          </div>

          <div style={{ textAlign: 'right', background: 'rgba(15, 23, 42, 0.6)', padding: '6px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <div style={{ fontSize: '0.65rem', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Total Processing</div>
            <div style={{ fontSize: '0.85rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>
              {context.total_duration_us ? `${context.total_duration_us} µs` : 'Processing...'}
            </div>
          </div>
        </div>

      </div>

      {/* Interactive Inspector Tabs */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '8px', marginBottom: '14px', overflowX: 'auto' }}>
        {[
          { id: 'raw', label: 'Raw Payload & SHA-256', icon: Terminal },
          { id: 'ast', label: 'AST Token Matrix', icon: Layers },
          { id: 'canonical', label: 'Canonical Schema', icon: Activity },
          { id: 'validation', label: 'Validation & DQI', icon: ShieldCheck },
          { id: 'storage', label: 'PostgreSQL/SQLite WAL', icon: Database },
          { id: 'ml', label: 'ML Anomaly & Features', icon: BrainCircuit },
          { id: 'exports', label: 'SIEM Export Envelopes', icon: FileCode },
        ].map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 12px',
                borderRadius: '6px',
                border: 'none',
                cursor: 'pointer',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.74rem',
                fontWeight: activeTab === tab.id ? 600 : 400,
                background: activeTab === tab.id ? 'rgba(0, 240, 255, 0.12)' : 'transparent',
                color: activeTab === tab.id ? '#00f0ff' : '#94a3b8',
                borderBottom: activeTab === tab.id ? '2px solid #00f0ff' : '2px solid transparent',
                transition: 'all 0.15s ease',
                whiteSpace: 'nowrap',
              }}
            >
              <Icon size={13} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Content Display */}
      <div style={{ minHeight: '160px', maxHeight: '340px', overflowY: 'auto' }}>
        
        {/* TAB 1: RAW PAYLOAD */}
        {activeTab === 'raw' && rawEvent && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: '#64748b' }}>
                SHA-256 Digest: <strong style={{ color: '#38bdf8' }}>{rawEvent.raw.sha256_hash}</strong> ({rawEvent.raw.length_bytes} bytes)
              </div>
              <button 
                className="btn-cyber btn-cyber-secondary"
                onClick={() => copyText(rawEvent.raw.payload)}
                style={{ padding: '3px 8px', fontSize: '0.7rem' }}
              >
                Copy Raw
              </button>
            </div>
            <div className="code-box" style={{ marginBottom: '10px', color: '#38bdf8' }}>
              {rawEvent.raw.payload}
            </div>
            <div className="hex-dump">
              {generateHexDump(rawEvent.raw.payload)}
            </div>
          </div>
        )}

        {/* TAB 2: AST TOKENS */}
        {activeTab === 'ast' && (
          <div>
            {parsedEvent ? (
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px', fontSize: '0.74rem', fontFamily: 'var(--font-mono)', color: '#94a3b8' }}>
                  <span>Parser: <strong style={{ color: '#c084fc' }}>{parsedEvent.parser_name}</strong> ({parsedEvent.parser_vendor} {parsedEvent.parser_product})</span>
                  <span>Confidence: <strong style={{ color: '#10b981' }}>{parsedEvent.confidence_score * 100}%</strong></span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '8px' }}>
                  {Object.entries(parsedEvent.extracted_fields).map(([key, val]) => (
                    <div 
                      key={key} 
                      style={{ 
                        background: 'rgba(15, 23, 42, 0.7)', 
                        padding: '6px 10px', 
                        borderRadius: '6px', 
                        border: '1px solid rgba(255, 255, 255, 0.06)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.72rem',
                      }}
                    >
                      <div style={{ color: '#64748b', fontSize: '0.65rem' }}>{key}</div>
                      <div style={{ color: '#f8fafc', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {String(val)}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p style={{ color: '#64748b', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>Parsing stage not reached yet.</p>
            )}
          </div>
        )}

        {/* TAB 3: CANONICAL TAXONOMY */}
        {activeTab === 'canonical' && (
          <div>
            {normEvent ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
                <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: '#00f0ff', fontFamily: 'var(--font-mono)', fontWeight: 700, marginBottom: '6px' }}>
                    EVENT & CLASSIFICATION
                  </div>
                  <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: '#cbd5e1', lineHeight: '1.6' }}>
                    <div>Action: <strong style={{ color: '#10b981' }}>{normEvent.event.action}</strong></div>
                    <div>Severity: <strong style={{ color: '#fbbf24' }}>{normEvent.event.severity}</strong></div>
                    <div>Category: {normEvent.event.category}</div>
                    <div>Type: {normEvent.event.type}</div>
                  </div>
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: '#a855f7', fontFamily: 'var(--font-mono)', fontWeight: 700, marginBottom: '6px' }}>
                    NETWORK ENDPOINTS
                  </div>
                  <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: '#cbd5e1', lineHeight: '1.6' }}>
                    <div>Source: <strong style={{ color: '#38bdf8' }}>{normEvent.source.ip}:{normEvent.source.port}</strong></div>
                    <div>Dest: <strong style={{ color: '#c084fc' }}>{normEvent.destination.ip}:{normEvent.destination.port}</strong></div>
                    <div>Protocol: {normEvent.network.protocol}</div>
                    <div>Direction: {normEvent.network.direction}</div>
                  </div>
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: '#10b981', fontFamily: 'var(--font-mono)', fontWeight: 700, marginBottom: '6px' }}>
                    UNMAPPED PRESERVATION ({Object.keys(normEvent.unmapped_fields).length})
                  </div>
                  <div style={{ fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: '#94a3b8', maxHeight: '80px', overflowY: 'auto' }}>
                    {Object.keys(normEvent.unmapped_fields).length === 0 ? (
                      <div>All fields mapped to canonical taxonomy.</div>
                    ) : (
                      Object.entries(normEvent.unmapped_fields).map(([k, v]) => (
                        <div key={k}>{k}: {String(v)}</div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <p style={{ color: '#64748b', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>Normalization stage not reached yet.</p>
            )}
          </div>
        )}

        {/* TAB 4: VALIDATION & DQI */}
        {activeTab === 'validation' && (
          <div>
            {valEvent ? (
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="badge badge-green">DQI QUALITY INDEX: {valEvent.data_quality_score}%</span>
                    <span className="badge badge-cyan">SHA-256 VERIFIED: {valEvent.hash_verified ? 'YES' : 'NO'}</span>
                  </div>
                  <span style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                    {valEvent.validation_checks.filter((c) => c.passed).length} / {valEvent.validation_checks.length} Rules Passed
                  </span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                  {valEvent.validation_checks.map((chk, idx) => (
                    <div 
                      key={idx} 
                      style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '8px', 
                        padding: '6px 10px', 
                        borderRadius: '6px', 
                        background: chk.passed ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                        border: `1px solid ${chk.passed ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.3)'}`,
                        fontSize: '0.72rem',
                        fontFamily: 'var(--font-mono)',
                      }}
                    >
                      {chk.passed ? <CheckCircle2 size={14} color="#10b981" /> : <AlertTriangle size={14} color="#ef4444" />}
                      <div>
                        <div style={{ color: '#f8fafc', fontWeight: 600 }}>{chk.rule_name}</div>
                        <div style={{ color: '#94a3b8', fontSize: '0.65rem' }}>{chk.message}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p style={{ color: '#64748b', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>Validation stage not reached yet.</p>
            )}
          </div>
        )}

        {/* TAB 5: STORAGE */}
        {activeTab === 'storage' && (
          <div>
            {storedEvent ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
                <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <div style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Storage Mode</div>
                  <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>
                    SQLite WAL + Columnar
                  </div>
                  <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '4px' }}>
                    Table: {storedEvent.storage.table_name}
                  </div>
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <div style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Compression Ratio</div>
                  <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#10b981', fontFamily: 'var(--font-mono)' }}>
                    {storedEvent.storage.compression_ratio}% reduction
                  </div>
                  <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '4px' }}>
                    {storedEvent.storage.raw_size_bytes}B ➔ {storedEvent.storage.compressed_size_bytes}B
                  </div>
                </div>

                <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <div style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Write Latency</div>
                  <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#fbbf24', fontFamily: 'var(--font-mono)' }}>
                    {storedEvent.storage_duration_us} µs
                  </div>
                  <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '4px' }}>
                    Dual Indexing Active
                  </div>
                </div>
              </div>
            ) : (
              <p style={{ color: '#64748b', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>Storage stage not reached yet.</p>
            )}
          </div>
        )}

        {/* TAB 6: ML ANOMALY */}
        {activeTab === 'ml' && (
          <div>
            {mlEvent ? (
              <div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '10px', marginBottom: '12px' }}>
                  <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '8px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                    <div style={{ fontSize: '0.65rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>Anomaly Score</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 800, color: mlEvent.ml.is_anomalous ? '#ef4444' : '#10b981', fontFamily: 'var(--font-mono)' }}>
                      {mlEvent.ml.anomaly_score.toFixed(2)}
                    </div>
                  </div>
                  <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '8px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                    <div style={{ fontSize: '0.65rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>Shannon Entropy</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#c084fc', fontFamily: 'var(--font-mono)' }}>
                      {mlEvent.ml.shannon_entropy} bits
                    </div>
                  </div>
                  <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '8px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                    <div style={{ fontSize: '0.65rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>Risk Classification</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 700, color: mlEvent.ml.is_anomalous ? '#f87171' : '#34d399', fontFamily: 'var(--font-mono)' }}>
                      {mlEvent.ml.risk_level}
                    </div>
                  </div>
                </div>

                <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', marginBottom: '6px' }}>
                  Feature Attribution Waterfall:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  {mlEvent.ml.feature_contributions.map((feat, idx) => (
                    <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.7rem', fontFamily: 'var(--font-mono)', background: 'rgba(15, 23, 42, 0.5)', padding: '4px 8px', borderRadius: '4px' }}>
                      <span style={{ color: '#cbd5e1' }}>{feat.feature}: {feat.description}</span>
                      <span style={{ color: '#38bdf8', fontWeight: 600 }}>{feat.weight.toFixed(2)}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p style={{ color: '#64748b', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>ML analysis stage not reached yet.</p>
            )}
          </div>
        )}

        {/* TAB 7: SIEM EXPORTERS */}
        {activeTab === 'exports' && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
              {(['ulpf', 'elastic', 'splunk', 'ocsf', 'parquet'] as const).map((fmt) => (
                <button
                  key={fmt}
                  onClick={() => setExportFormat(fmt)}
                  style={{
                    padding: '3px 8px',
                    borderRadius: '4px',
                    border: 'none',
                    fontSize: '0.7rem',
                    fontFamily: 'var(--font-mono)',
                    cursor: 'pointer',
                    background: exportFormat === fmt ? '#00f0ff' : 'rgba(15, 23, 42, 0.8)',
                    color: exportFormat === fmt ? '#06090f' : '#94a3b8',
                    fontWeight: 600,
                  }}
                >
                  {fmt.toUpperCase()}
                </button>
              ))}
            </div>

            <div className="code-box" style={{ maxHeight: '180px' }}>
              {exports ? (
                JSON.stringify(
                  exportFormat === 'ulpf' ? exports.ulpf_standard :
                  exportFormat === 'elastic' ? exports.elastic_ecs :
                  exportFormat === 'splunk' ? exports.splunk_hec :
                  exportFormat === 'ocsf' ? exports.ocsf_v1 :
                  exports.columnar_flat,
                  null,
                  2
                )
              ) : (
                'Standardized exports ready upon pipeline completion.'
              )}
            </div>
          </div>
        )}

      </div>

    </div>
  );
};
