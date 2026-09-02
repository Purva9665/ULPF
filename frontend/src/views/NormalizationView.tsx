import React, { useState } from 'react';
import type { 
  PipelineContext, 
  EngineStats 
} from '../types';
import { 
  ArrowLeft 
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
  const [selectedTaxonomy, setSelectedTaxonomy] = useState<'all' | 'event' | 'source' | 'destination' | 'network' | 'unmapped'>('all');

  const normEvent = context?.normalized_event;
  const rawFields = context?.parsed_event?.extracted_fields || {};
  const unmapped = normEvent?.unmapped_fields || {};
  const mappingRule = normEvent?.mapping_rule_used || 'Standard Canonical Taxonomy v1.0';
  const durationUs = normEvent?.normalization_duration_us || 32;

  const TRANSFORMATION_ROWS: Array<{
    sourceKey: string;
    sourceVal: any;
    targetPath: string;
    targetVal: any;
    transformType: 'DIRECT' | 'TYPE_CAST' | 'ENUM_NORM' | 'UNMAPPED_RETAIN';
    category: 'event' | 'source' | 'destination' | 'network' | 'unmapped';
  }> = [];

  if (normEvent) {
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
    TRANSFORMATION_ROWS.push({
      sourceKey: 'proto / protocol',
      sourceVal: rawFields.proto || rawFields.protocol || normEvent.network.protocol,
      targetPath: 'network.protocol',
      targetVal: normEvent.network.protocol,
      transformType: 'DIRECT',
      category: 'network',
    });
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span className="badge-inst badge-amber">STAGE [03]</span>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
              Schema Normalization & Canonical Taxonomy
            </h2>
          </div>
        </div>

        <div className="readout" style={{ fontSize: '0.74rem', color: 'var(--text-low)' }}>
          STAGE LATENCY: <strong style={{ color: 'var(--phosphor-amber)' }}>{durationUs} µs</strong>
        </div>
      </div>

      {/* 4 Readout Metric Tiles */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>NORMALIZED ACTION</div>
          <div className="readout" style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--confirm-moss)', margin: '2px 0' }}>
            {normEvent?.event.action || 'ALLOW'}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Canonical Enum</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>SEVERITY LEVEL</div>
          <div className="readout" style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--phosphor-amber)', margin: '2px 0' }}>
            {normEvent?.event.severity || 'INFORMATIONAL'}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Normalized Scale</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>UNMAPPED FIELDS RETAINED</div>
          <div className="readout" style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--signal-teal)', margin: '2px 0' }}>
            {Object.keys(unmapped).length} <span style={{ fontSize: '0.75rem', color: 'var(--text-low)' }}>keys</span>
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--confirm-moss)' }}>Zero-Loss Container</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>TAXONOMY SPEC</div>
          <div className="readout" style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-high)', margin: '4px 0' }}>
            {mappingRule}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Deterministic Mapping</div>
        </div>
      </div>

      {/* Main Transformation Matrix */}
      <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
          <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
            SOURCE FIELD ➔ CANONICAL FIELD TRANSFORMATION MATRIX
          </span>

          {/* Filter Pills */}
          <div style={{ display: 'flex', gap: '4px' }}>
            {['all', 'event', 'source', 'destination', 'network', 'unmapped'].map((tax) => (
              <button
                key={tax}
                onClick={() => setSelectedTaxonomy(tax as any)}
                style={{
                  background: selectedTaxonomy === tax ? 'var(--phosphor-amber-dim)' : 'var(--panel-sunken)',
                  color: selectedTaxonomy === tax ? 'var(--phosphor-amber)' : 'var(--text-mid)',
                  border: `1px solid ${selectedTaxonomy === tax ? 'var(--phosphor-amber)' : 'var(--hairline)'}`,
                  borderRadius: 'var(--radius-sm)',
                  padding: '2px 8px',
                  fontSize: '0.66rem',
                  fontFamily: 'var(--font-readout)',
                  fontWeight: 600,
                  cursor: 'pointer',
                  textTransform: 'uppercase',
                }}
              >
                {tax}
              </button>
            ))}
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontFamily: 'var(--font-readout)', fontSize: '0.72rem' }}>
            <thead>
              <tr style={{ background: 'var(--panel-sunken)', borderBottom: '1px solid var(--hairline)', color: 'var(--text-low)', textTransform: 'uppercase', fontSize: '0.64rem' }}>
                <th style={{ padding: '6px 10px' }}>Source Field (Raw)</th>
                <th style={{ padding: '6px 10px' }}>Raw Value</th>
                <th style={{ padding: '6px 10px' }}>Transform Mode</th>
                <th style={{ padding: '6px 10px' }}>Canonical Target Path</th>
                <th style={{ padding: '6px 10px' }}>Normalized Value</th>
              </tr>
            </thead>
            <tbody>
              {filteredRows.map((row, idx) => (
                <tr 
                  key={idx}
                  style={{ 
                    borderBottom: '1px solid var(--hairline)',
                    background: idx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.01)'
                  }}
                >
                  <td style={{ padding: '6px 10px', color: 'var(--text-mid)' }}>
                    {row.sourceKey}
                  </td>
                  <td style={{ padding: '6px 10px', color: 'var(--text-high)' }}>
                    {String(row.sourceVal)}
                  </td>
                  <td style={{ padding: '6px 10px' }}>
                    <span className={`badge-inst ${row.transformType === 'UNMAPPED_RETAIN' ? 'badge-teal' : 'badge-hairline'}`}>
                      {row.transformType}
                    </span>
                  </td>
                  <td style={{ padding: '6px 10px', color: 'var(--phosphor-amber)', fontWeight: 600 }}>
                    {row.targetPath}
                  </td>
                  <td style={{ padding: '6px 10px', color: 'var(--confirm-moss)', fontWeight: 600 }}>
                    {String(row.targetVal)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

      </div>

    </div>
  );
};
