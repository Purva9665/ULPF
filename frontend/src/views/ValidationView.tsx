import React, { useState } from 'react';
import type { 
  PipelineContext, 
  EngineStats 
} from '../types';
import { 
  ArrowLeft 
} from 'lucide-react';

interface ValidationViewProps {
  context: PipelineContext | null;
  stats?: EngineStats | null;
  onBackToOverview: () => void;
}

export const ValidationView: React.FC<ValidationViewProps> = ({
  context,
  onBackToOverview,
}) => {
  const [filterPassed, setFilterPassed] = useState<'all' | 'passed' | 'failed'>('all');

  const valEvent = context?.validated_event;
  const dqi = valEvent ? valEvent.data_quality_score : 100;
  const hashVerified = valEvent ? valEvent.hash_verified : true;
  const checks = valEvent?.validation_checks || [];
  const durationUs = valEvent?.validation_duration_us || 24;

  const passedCount = checks.filter((c) => c.passed).length;
  const failedCount = checks.filter((c) => !c.passed).length;

  const filteredChecks = filterPassed === 'all' 
    ? checks 
    : filterPassed === 'passed' 
    ? checks.filter((c) => c.passed) 
    : checks.filter((c) => !c.passed);

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
            <span className="badge-inst badge-amber">STAGE [04]</span>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
              Validation & Data Quality Index (DQI)
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
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>DATA QUALITY SCORE (DQI)</div>
          <div className="readout" style={{ fontSize: '1.4rem', fontWeight: 700, color: dqi >= 90 ? 'var(--confirm-moss)' : 'var(--alert-coral)', margin: '2px 0' }}>
            {dqi}%
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Deterministic Index</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>HASH TAMPER INTEGRITY</div>
          <div className="readout" style={{ fontSize: '1.1rem', fontWeight: 700, color: hashVerified ? 'var(--confirm-moss)' : 'var(--alert-coral)', margin: '2px 0' }}>
            {hashVerified ? 'VERIFIED OK' : 'TAMPER DETECTED'}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>SHA-256 Checksum</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>PASSED RULES</div>
          <div className="readout" style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--confirm-moss)', margin: '2px 0' }}>
            {passedCount} / {checks.length}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Semantic Invariants</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>VIOLATIONS DETECTED</div>
          <div className="readout" style={{ fontSize: '1.3rem', fontWeight: 700, color: failedCount > 0 ? 'var(--alert-coral)' : 'var(--text-mid)', margin: '2px 0' }}>
            {failedCount}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Non-Conforming Fields</div>
        </div>
      </div>

      {/* Validation Rules Checklist */}
      <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
          <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
            DETERMINISTIC SEMANTIC RULES EVALUATION
          </span>

          <div style={{ display: 'flex', gap: '4px' }}>
            {['all', 'passed', 'failed'].map((mode) => (
              <button
                key={mode}
                onClick={() => setFilterPassed(mode as any)}
                style={{
                  background: filterPassed === mode ? 'var(--phosphor-amber-dim)' : 'var(--panel-sunken)',
                  color: filterPassed === mode ? 'var(--phosphor-amber)' : 'var(--text-mid)',
                  border: `1px solid ${filterPassed === mode ? 'var(--phosphor-amber)' : 'var(--hairline)'}`,
                  borderRadius: 'var(--radius-sm)',
                  padding: '2px 8px',
                  fontSize: '0.66rem',
                  fontFamily: 'var(--font-readout)',
                  fontWeight: 600,
                  cursor: 'pointer',
                  textTransform: 'uppercase',
                }}
              >
                {mode}
              </button>
            ))}
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontFamily: 'var(--font-readout)', fontSize: '0.72rem' }}>
            <thead>
              <tr style={{ background: 'var(--panel-sunken)', borderBottom: '1px solid var(--hairline)', color: 'var(--text-low)', textTransform: 'uppercase', fontSize: '0.64rem' }}>
                <th style={{ padding: '6px 10px' }}>Status</th>
                <th style={{ padding: '6px 10px' }}>Semantic Rule Name</th>
                <th style={{ padding: '6px 10px' }}>Field Inspected</th>
                <th style={{ padding: '6px 10px' }}>Validation Message / Assertion</th>
              </tr>
            </thead>
            <tbody>
              {filteredChecks.map((c, idx) => (
                <tr 
                  key={idx}
                  style={{ 
                    borderBottom: '1px solid var(--hairline)',
                    background: idx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.01)'
                  }}
                >
                  <td style={{ padding: '6px 10px' }}>
                    <span className={`badge-inst ${c.passed ? 'badge-moss' : 'badge-coral'}`}>
                      {c.passed ? 'PASS' : 'FAIL'}
                    </span>
                  </td>
                  <td style={{ padding: '6px 10px', color: 'var(--text-high)', fontWeight: 600 }}>
                    {c.rule_name}
                  </td>
                  <td style={{ padding: '6px 10px', color: 'var(--phosphor-amber)' }}>
                    {c.field_checked}
                  </td>
                  <td style={{ padding: '6px 10px', color: c.passed ? 'var(--text-mid)' : 'var(--alert-coral)' }}>
                    {c.message || 'Invariant satisfied'}
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
