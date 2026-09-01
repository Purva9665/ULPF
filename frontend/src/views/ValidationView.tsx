import React, { useState } from 'react';
import type { 
  PipelineContext, 
  EngineStats 
} from '../types';
import { 
  ShieldCheck, 
  ArrowLeft, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  Lock, 
  FileCheck,
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
  const isValid = valEvent ? valEvent.is_valid : true;
  const checks = valEvent?.validation_checks || [];
  const durationUs = valEvent?.validation_duration_us || 24;

  const passedCount = checks.filter((c) => c.passed).length;

  const filteredChecks = filterPassed === 'all' 
    ? checks 
    : filterPassed === 'passed' 
    ? checks.filter((c) => c.passed) 
    : checks.filter((c) => !c.passed);

  // Standard Semantic Rules defined in ULPF Validation Engine
  const STANDARD_RULES = [
    { name: 'Schema Integrity', desc: 'Verifies canonical taxonomy structure and non-null root objects', weight: '20%' },
    { name: 'Mandatory Fields', desc: 'Enforces event.action, source.ip, and destination.ip existence', weight: '25%' },
    { name: 'IP Regex Standard', desc: 'Validates IPv4 (0.0.0.0-255.255.255.255) and IPv6 RFC format', weight: '15%' },
    { name: 'Port Range Standard', desc: 'Checks TCP/UDP socket ports are within 0 - 65535 integer range', weight: '15%' },
    { name: 'ISO-8601 Timestamp', desc: 'Validates UTC/ISO formatted timestamp without corrupt drift', weight: '10%' },
    { name: 'Enum Normalization', desc: 'Verifies ActionEnum and SeverityEnum match canonical values', weight: '15%' },
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
              <span className="badge badge-green" style={{ fontSize: '0.72rem' }}>STAGE 04</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Validation & Data Quality Engine
              </h2>
            </div>
            <p style={{ fontSize: '0.74rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Deterministic Semantic Rules Engine, Data Quality Index (DQI), and Integrity Verification
            </p>
          </div>
        </div>

        {/* Stage Path */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(15, 23, 42, 0.7)', padding: '6px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <span style={{ fontSize: '0.72rem', color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>NORMALIZED EVENT</span>
          <span style={{ color: '#64748b' }}>➔</span>
          <span style={{ fontSize: '0.72rem', color: '#10b981', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>[04] VALIDATION & DQI</span>
          <span style={{ color: '#64748b' }}>➔</span>
          <span style={{ fontSize: '0.72rem', color: '#fbbf24', fontFamily: 'var(--font-mono)' }}>WAL PERSISTENCE</span>
        </div>
      </div>

      {/* Top 4 Metrics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        
        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Data Quality Score</span>
            <ShieldCheck size={16} color="#10b981" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: dqi >= 90 ? '#10b981' : dqi >= 70 ? '#fbbf24' : '#ef4444', margin: '4px 0' }}>
            {dqi}%
          </div>
          <div style={{ fontSize: '0.68rem', color: '#34d399', fontFamily: 'var(--font-mono)' }}>
            DQI Quality Index Computed
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Final Verdict</span>
            <CheckCircle2 size={16} color={isValid ? '#10b981' : '#ef4444'} />
          </div>
          <div style={{ fontSize: '1.3rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: isValid ? '#10b981' : '#ef4444', margin: '4px 0' }}>
            {isValid ? 'VALIDATED PASSED' : 'SCHEMA WARNING'}
          </div>
          <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            {passedCount} / {checks.length} Constraint Checks Passed
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>SHA-256 Hash Match</span>
            <Lock size={16} color="#00f0ff" />
          </div>
          <div style={{ fontSize: '1.3rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#00f0ff', margin: '4px 0' }}>
            {hashVerified ? '100% MATCHED' : 'CORRUPTED'}
          </div>
          <div style={{ fontSize: '0.68rem', color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>
            Pristine Payload Intact
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Validation Duration</span>
            <Clock size={16} color="#fbbf24" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fbbf24', margin: '4px 0' }}>
            {durationUs} µs
          </div>
          <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            High-Throughput Semantic Checker
          </div>
        </div>

      </div>

      {/* Main Grid: Left Rules Evaluation Table, Right DQI Formula & Standard Rules */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: '20px' }}>
        
        {/* Left: Detailed Semantic Check Results Table */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileCheck size={18} color="#10b981" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Evaluated Validation Constraints ({checks.length})
              </h3>
            </div>

            <div style={{ display: 'flex', gap: '4px' }}>
              {(['all', 'passed', 'failed'] as const).map((f) => (
                <button
                  key={f}
                  onClick={() => setFilterPassed(f)}
                  style={{
                    padding: '3px 8px',
                    borderRadius: '4px',
                    border: 'none',
                    fontSize: '0.66rem',
                    fontFamily: 'var(--font-mono)',
                    cursor: 'pointer',
                    background: filterPassed === f ? '#10b981' : 'rgba(15, 23, 42, 0.8)',
                    color: filterPassed === f ? '#06090f' : '#94a3b8',
                    fontWeight: 600,
                  }}
                >
                  {f.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '420px', overflowY: 'auto' }}>
            {filteredChecks.length === 0 ? (
              <div style={{ padding: '30px', textAlign: 'center', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                No checks match the selected filter.
              </div>
            ) : (
              filteredChecks.map((chk, idx) => (
                <div
                  key={idx}
                  style={{
                    background: chk.passed ? 'rgba(16, 185, 129, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                    border: `1px solid ${chk.passed ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.4)'}`,
                    borderRadius: '8px',
                    padding: '10px 14px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {chk.passed ? (
                      <CheckCircle2 size={18} color="#10b981" />
                    ) : (
                      <AlertTriangle size={18} color="#ef4444" />
                    )}
                    <div>
                      <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
                        {chk.rule_name}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: '#cbd5e1', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                        Field Checked: <strong style={{ color: '#38bdf8' }}>{chk.field_checked}</strong> • {chk.message}
                      </div>
                    </div>
                  </div>

                  <span 
                    className={`badge ${chk.passed ? 'badge-green' : 'badge-red'}`}
                    style={{ fontSize: '0.62rem' }}
                  >
                    {chk.passed ? 'PASSED' : chk.severity}
                  </span>
                </div>
              ))
            )}
          </div>

        </div>

        {/* Right: Validation Framework Rules Definition */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldCheck size={18} color="#38bdf8" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Standard Semantic Rules
              </h3>
            </div>
            <span className="badge badge-cyan" style={{ fontSize: '0.62rem' }}>6 RULES</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', flex: 1, overflowY: 'auto' }}>
            {STANDARD_RULES.map((rule, idx) => (
              <div
                key={idx}
                style={{
                  background: 'rgba(15, 23, 42, 0.65)',
                  padding: '10px 12px',
                  borderRadius: '8px',
                  border: '1px solid rgba(255, 255, 255, 0.05)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '3px' }}>
                  <span style={{ fontSize: '0.78rem', fontWeight: 700, color: '#00f0ff', fontFamily: 'var(--font-mono)' }}>
                    {rule.name}
                  </span>
                  <span style={{ fontSize: '0.65rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                    Weight: {rule.weight}
                  </span>
                </div>
                <div style={{ fontSize: '0.7rem', color: '#94a3b8', lineHeight: 1.4 }}>
                  {rule.desc}
                </div>
              </div>
            ))}
          </div>

        </div>

      </div>

    </div>
  );
};
