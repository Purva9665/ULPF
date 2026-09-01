import React from 'react';
import type { PipelineContext } from '../types';
import { ShieldCheck, GitCompare, CheckCircle2 } from 'lucide-react';

interface RawVsNormalizedDiffProps {
  context: PipelineContext | null;
}

export const RawVsNormalizedDiff: React.FC<RawVsNormalizedDiffProps> = ({ context }) => {
  if (!context || !context.raw_event || !context.normalized_event) {
    return null;
  }

  const raw = context.raw_event;
  const norm = context.normalized_event;

  return (
    <div className="glass-panel" style={{ margin: '0 20px 20px 20px', padding: '20px 24px' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <GitCompare size={18} color="#00f0ff" />
          <h3 style={{ fontSize: '0.95rem', fontWeight: 700, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', color: '#f8fafc' }}>
            Zero-Loss Equivalence & Canonical Schema Diff
          </h3>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="badge badge-green" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <ShieldCheck size={12} />
            <span>SHA-256 Tamper-Proof</span>
          </span>
          <span className="badge badge-cyan">
            {Object.keys(norm.unmapped_fields).length} Custom Fields Retained
          </span>
        </div>
      </div>

      {/* Side-by-Side Comparison */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        
        {/* Left Column: Pristine Raw Payload */}
        <div style={{ background: 'rgba(2, 6, 23, 0.7)', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '14px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px', borderBottom: '1px solid rgba(255, 255, 255, 0.06)', paddingBottom: '6px' }}>
            <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: '#00f0ff', fontWeight: 700, textTransform: 'uppercase' }}>
              Original Heterogeneous Raw Event
            </span>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              {raw.raw.length_bytes} Bytes • UTF-8
            </span>
          </div>

          <div 
            className="code-box" 
            style={{ 
              color: '#38bdf8', 
              fontSize: '0.8rem', 
              flex: 1, 
              backgroundColor: '#030712',
              minHeight: '180px',
              border: '1px solid rgba(0, 240, 255, 0.15)'
            }}
          >
            {raw.raw.payload}
          </div>

          <div style={{ marginTop: '10px', fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: '#64748b', wordBreak: 'break-all' }}>
            SHA-256: <span style={{ color: '#00f0ff' }}>{raw.raw.sha256_hash}</span>
          </div>
        </div>

        {/* Right Column: Standardized ULPF Representation */}
        <div style={{ background: 'rgba(2, 6, 23, 0.7)', borderRadius: '8px', border: '1px solid rgba(16, 185, 129, 0.2)', padding: '14px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px', borderBottom: '1px solid rgba(255, 255, 255, 0.06)', paddingBottom: '6px' }}>
            <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: '#10b981', fontWeight: 700, textTransform: 'uppercase' }}>
              Canonical ULPF Standard Representation
            </span>
            <span className="badge badge-green" style={{ fontSize: '0.62rem' }}>
              TAXONOMY ALIGNED
            </span>
          </div>

          <pre 
            className="code-box" 
            style={{ 
              fontSize: '0.75rem', 
              flex: 1, 
              backgroundColor: '#030712',
              maxHeight: '220px',
              border: '1px solid rgba(16, 185, 129, 0.15)',
              color: '#a7f3d0'
            }}
          >
            {JSON.stringify(
              {
                event: norm.event,
                source: norm.source,
                destination: norm.destination,
                network: norm.network,
                threat: norm.threat,
                observer: norm.observer,
                unmapped_fields: norm.unmapped_fields,
              },
              null,
              2
            )}
          </pre>

          <div style={{ marginTop: '10px', fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: '#10b981', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <CheckCircle2 size={13} color="#10b981" />
            <span>Complete semantic validation and zero loss unmapped preservation</span>
          </div>
        </div>

      </div>

    </div>
  );
};
