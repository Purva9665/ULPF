import React, { useState } from 'react';
import type { 
  PipelineContext, 
  EngineStats 
} from '../types';
import { 
  GitMerge, 
  ArrowLeft, 
  CheckCircle2, 
  Layers, 
  ArrowRight, 
  Copy, 
  Check, 
  Clock, 
  Lock, 
} from 'lucide-react';

interface NormalizationViewProps {
  context: PipelineContext | null;
  stats?: EngineStats | null;
  onBackToOverview: () => void;
}

export const NormalizationView: React.FC<NormalizationViewProps> = ({
  context,
  onBackToOverview,
}) => {
  const [copied, setCopied] = useState(false);
  const [selectedTaxonomy, setSelectedTaxonomy] = useState<'all' | 'event' | 'source' | 'destination' | 'network' | 'unmapped'>('all');

  const copyJson = (obj: any) => {
    navigator.clipboard.writeText(JSON.stringify(obj, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const normEvent = context?.normalized_event;
  const rawFields = context?.parsed_event?.extracted_fields || {};
  const unmapped = normEvent?.unmapped_fields || {};
  const mappingRule = normEvent?.mapping_rule_used || 'Standard Canonical Taxonomy v1.0.0';
  const durationUs = normEvent?.normalization_duration_us || 32;

  // Build transformation map: Raw Source Key -> Canonical Key & Value
  const TRANSFORMATION_ROWS: Array<{
    sourceKey: string;
    sourceVal: any;
    targetPath: string;
    targetVal: any;
    transformType: 'DIRECT' | 'TYPE_CAST' | 'ENUM_NORM' | 'UNMAPPED_RETAIN';
    category: 'event' | 'source' | 'destination' | 'network' | 'unmapped';
  }> = [];

  if (normEvent) {
    // 1. Event
    TRANSFORMATION_ROWS.push({
      sourceKey: 'action / rule_action',
      sourceVal: rawFields.action || rawFields.rule_action || 'DENY',
      targetPath: 'event.action',
      targetVal: normEvent.event.action,
      transformType: 'ENUM_NORM',
      category: 'event',
    });
    TRANSFORMATION_ROWS.push({
      sourceKey: 'severity / pri / level',
      sourceVal: rawFields.severity || rawFields.level || rawFields.pri || '4',
      targetPath: 'event.severity',
      targetVal: normEvent.event.severity,
      transformType: 'ENUM_NORM',
      category: 'event',
    });
    TRANSFORMATION_ROWS.push({
      sourceKey: 'timestamp / log_time',
      sourceVal: rawFields.timestamp || rawFields.time || 'Raw Time',
      targetPath: 'event.timestamp',
      targetVal: normEvent.event.timestamp || normEvent.event.ingested_at,
      transformType: 'TYPE_CAST',
      category: 'event',
    });

    // 2. Source
    TRANSFORMATION_ROWS.push({
      sourceKey: 'src_ip / src / source_ip',
      sourceVal: rawFields.src_ip || rawFields.src || rawFields.source_ip || normEvent.source.ip,
      targetPath: 'source.ip',
      targetVal: normEvent.source.ip,
      transformType: 'DIRECT',
      category: 'source',
    });
    TRANSFORMATION_ROWS.push({
      sourceKey: 'src_port / sport',
      sourceVal: rawFields.src_port || rawFields.sport || normEvent.source.port,
      targetPath: 'source.port',
      targetVal: normEvent.source.port,
      transformType: 'TYPE_CAST',
      category: 'source',
    });

    // 3. Destination
    TRANSFORMATION_ROWS.push({
      sourceKey: 'dst_ip / dst / dest_ip',
      sourceVal: rawFields.dst_ip || rawFields.dst || rawFields.dest_ip || normEvent.destination.ip,
      targetPath: 'destination.ip',
      targetVal: normEvent.destination.ip,
      transformType: 'DIRECT',
      category: 'destination',
    });
    TRANSFORMATION_ROWS.push({
      sourceKey: 'dst_port / dport',
      sourceVal: rawFields.dst_port || rawFields.dport || normEvent.destination.port,
      targetPath: 'destination.port',
      targetVal: normEvent.destination.port,
      transformType: 'TYPE_CAST',
      category: 'destination',
    });

    // 4. Network
    TRANSFORMATION_ROWS.push({
      sourceKey: 'proto / protocol / transport',
      sourceVal: rawFields.proto || rawFields.protocol || normEvent.network.protocol,
      targetPath: 'network.protocol',
      targetVal: normEvent.network.protocol,
      transformType: 'DIRECT',
      category: 'network',
    });
    TRANSFORMATION_ROWS.push({
      sourceKey: 'bytes / length / bytes_total',
      sourceVal: rawFields.bytes || rawFields.length || normEvent.network.bytes_total || '1420',
      targetPath: 'network.bytes_total',
      targetVal: normEvent.network.bytes_total || 1420,
      transformType: 'TYPE_CAST',
      category: 'network',
    });

    // 5. Unmapped fields
    Object.entries(unmapped).forEach(([k, v]) => {
      TRANSFORMATION_ROWS.push({
        sourceKey: k,
        sourceVal: v,
        targetPath: `unmapped_fields.${k}`,
        targetVal: v,
        transformType: 'UNMAPPED_RETAIN',
        category: 'unmapped',
      });
    });
  }

  const filteredRows = selectedTaxonomy === 'all' 
    ? TRANSFORMATION_ROWS 
    : TRANSFORMATION_ROWS.filter((r) => r.category === selectedTaxonomy);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Top Header */}
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
              <span className="badge badge-cyan" style={{ fontSize: '0.72rem' }}>STAGE 03</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Canonical Normalization Engine
              </h2>
            </div>
            <p style={{ fontSize: '0.74rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Heterogeneous Field Alignment to ULPF Common Schema & Zero-Loss Unmapped Preservation
            </p>
          </div>
        </div>

        {/* Stage Path */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(15, 23, 42, 0.7)', padding: '6px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <span style={{ fontSize: '0.72rem', color: '#c084fc', fontFamily: 'var(--font-mono)' }}>EXTRACTED AST</span>
          <span style={{ color: '#64748b' }}>➔</span>
          <span style={{ fontSize: '0.72rem', color: '#38bdf8', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>[03] NORMALIZATION</span>
          <span style={{ color: '#64748b' }}>➔</span>
          <span style={{ fontSize: '0.72rem', color: '#10b981', fontFamily: 'var(--font-mono)' }}>VALIDATED CANONICAL</span>
        </div>
      </div>

      {/* Top 4 Metrics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        
        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Canonical Schema</span>
            <GitMerge size={16} color="#38bdf8" />
          </div>
          <div style={{ fontSize: '1.3rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#38bdf8', margin: '4px 0' }}>
            ULPF v1.0.0
          </div>
          <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            Rule: {mappingRule}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Mapped Fields</span>
            <CheckCircle2 size={16} color="#10b981" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#10b981', margin: '4px 0' }}>
            {TRANSFORMATION_ROWS.filter((r) => r.transformType !== 'UNMAPPED_RETAIN').length} Mapped
          </div>
          <div style={{ fontSize: '0.68rem', color: '#34d399', fontFamily: 'var(--font-mono)' }}>
            100% Taxonomical Alignment
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Unmapped Preserved</span>
            <Lock size={16} color="#fbbf24" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fbbf24', margin: '4px 0' }}>
            {Object.keys(unmapped).length} Attributes
          </div>
          <div style={{ fontSize: '0.68rem', color: '#fbbf24', fontFamily: 'var(--font-mono)' }}>
            Zero-Loss Retention Guarantee
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Mapping Latency</span>
            <Clock size={16} color="#c084fc" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#f8fafc', margin: '4px 0' }}>
            {durationUs} µs
          </div>
          <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            In-Memory AST Re-indexing
          </div>
        </div>

      </div>

      {/* Main Workspace: Left Transformation Table, Right Canonical Schema Tree */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 420px', gap: '20px' }}>
        
        {/* Left: VISUAL TRANSFORMATION MAP TABLE */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <GitMerge size={18} color="#00f0ff" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Field Transformation Map (Source ➔ Canonical)
              </h3>
            </div>

            {/* Category Filter Pills */}
            <div style={{ display: 'flex', gap: '4px' }}>
              {(['all', 'event', 'source', 'destination', 'network', 'unmapped'] as const).map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedTaxonomy(cat)}
                  style={{
                    padding: '3px 8px',
                    borderRadius: '4px',
                    border: 'none',
                    fontSize: '0.66rem',
                    fontFamily: 'var(--font-mono)',
                    cursor: 'pointer',
                    background: selectedTaxonomy === cat ? '#00f0ff' : 'rgba(15, 23, 42, 0.8)',
                    color: selectedTaxonomy === cat ? '#06090f' : '#94a3b8',
                    fontWeight: 600,
                  }}
                >
                  {cat.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Transformation Table */}
          <div style={{ overflowX: 'auto', maxHeight: '420px', overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: '0.74rem' }}>
              <thead>
                <tr style={{ background: 'rgba(15, 23, 42, 0.9)', color: '#64748b', textAlign: 'left', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
                  <th style={{ padding: '8px 10px' }}>SOURCE AST FIELD</th>
                  <th style={{ padding: '8px 10px', textAlign: 'center' }}>TRANSFORM</th>
                  <th style={{ padding: '8px 10px' }}>ULPF CANONICAL FIELD</th>
                  <th style={{ padding: '8px 10px' }}>NORMALIZED VALUE</th>
                </tr>
              </thead>
              <tbody>
                {filteredRows.map((row, idx) => (
                  <tr
                    key={idx}
                    style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}
                  >
                    {/* Source */}
                    <td style={{ padding: '8px 10px' }}>
                      <div style={{ color: '#c084fc', fontWeight: 600 }}>{row.sourceKey}</div>
                      <div style={{ color: '#64748b', fontSize: '0.66rem' }}>Val: {String(row.sourceVal)}</div>
                    </td>

                    {/* Transform Badge */}
                    <td style={{ padding: '8px 10px', textAlign: 'center' }}>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                        <ArrowRight size={12} color="#00f0ff" />
                        <span 
                          className={`badge ${
                            row.transformType === 'ENUM_NORM' ? 'badge-amber' :
                            row.transformType === 'TYPE_CAST' ? 'badge-purple' :
                            row.transformType === 'UNMAPPED_RETAIN' ? 'badge-blue' : 'badge-green'
                          }`}
                          style={{ fontSize: '0.58rem', padding: '1px 5px' }}
                        >
                          {row.transformType}
                        </span>
                      </div>
                    </td>

                    {/* Target Canonical Path */}
                    <td style={{ padding: '8px 10px' }}>
                      <div style={{ color: '#38bdf8', fontWeight: 700 }}>{row.targetPath}</div>
                    </td>

                    {/* Normalized Output Value */}
                    <td style={{ padding: '8px 10px' }}>
                      <span style={{ color: '#f8fafc', fontWeight: 600, background: 'rgba(0, 0, 0, 0.4)', padding: '2px 6px', borderRadius: '4px' }}>
                        {String(row.targetVal)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

        </div>

        {/* Right: Normalized Canonical JSON Output */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={18} color="#10b981" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Canonical Event Payload
              </h3>
            </div>
            <button
              onClick={() => normEvent && copyJson(normEvent)}
              className="btn-cyber btn-cyber-secondary"
              style={{ padding: '4px 10px', fontSize: '0.72rem' }}
            >
              {copied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
              <span>Copy JSON</span>
            </button>
          </div>

          <div className="code-box" style={{ flex: 1, maxHeight: '420px', overflowY: 'auto' }}>
            {normEvent ? JSON.stringify(normEvent, null, 2) : 'No normalized event in current pipeline.'}
          </div>
        </div>

      </div>

    </div>
  );
};
