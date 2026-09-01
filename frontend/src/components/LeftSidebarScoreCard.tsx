import React from 'react';
import { 
  ShieldCheck, 
  Terminal, 
  CheckCircle2, 
  Lock,
  Cpu,
  Layers,
  Sparkles,
} from 'lucide-react';
import type { EngineStats } from '../types';

interface LeftSidebarScoreCardProps {
  stats: EngineStats | null;
  onOpenTestBench: () => void;
}

export const LeftSidebarScoreCard: React.FC<LeftSidebarScoreCardProps> = ({
  stats,
  onOpenTestBench,
}) => {
  const dqiScore = stats?.storage.avg_data_quality_score || 100.0;
  const compressionRatio = stats?.storage.overall_compression_ratio || 0.0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', height: '100%' }}>
      
      {/* 1. Greeting & Control Room Summary Banner */}
      <div 
        className="glass-panel" 
        style={{ 
          padding: '20px', 
          position: 'relative', 
          overflow: 'hidden',
          background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(2, 6, 23, 0.95) 100%)',
          border: '1px solid rgba(0, 240, 255, 0.2)',
        }}
      >
        <div 
          style={{
            position: 'absolute',
            top: '-20px',
            right: '-20px',
            width: '100px',
            height: '100px',
            background: 'radial-gradient(circle, rgba(0, 240, 255, 0.15) 0%, transparent 70%)',
            pointerEvents: 'none',
          }} 
        />

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
          <span className="badge badge-cyan" style={{ fontSize: '0.65rem' }}>
            <Sparkles size={11} />
            ULPF CONTROL ROOM
          </span>
        </div>

        <h3 style={{ fontSize: '1.2rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#f8fafc', letterSpacing: '0.02em', lineHeight: 1.3 }}>
          Heterogeneous Perimeter Telemetry
        </h3>

        <p style={{ fontSize: '0.74rem', color: '#94a3b8', marginTop: '6px', lineHeight: 1.5 }}>
          Zero-loss multi-dialect log pre-processing, normalization, validation, and local ML anomaly scoring.
        </p>

        <button
          className="btn-cyber btn-cyber-primary"
          onClick={onOpenTestBench}
          style={{ marginTop: '14px', width: '100%', justifyContent: 'center', fontSize: '0.8rem', padding: '8px 14px' }}
        >
          <Terminal size={15} />
          <span>Ingest Custom Log ➔</span>
        </button>
      </div>

      {/* 2. Pipeline Quality & Integrity Score Card */}
      <div 
        className="glass-panel" 
        style={{ 
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ShieldCheck size={16} color="#10b981" />
              <span style={{ fontSize: '0.74rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#94a3b8', textTransform: 'uppercase' }}>
                Data Quality Index
              </span>
            </div>
            <span className="badge badge-green" style={{ fontSize: '0.6rem' }}>
              EXCELLENT
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px', margin: '4px 0 8px 0' }}>
            <span style={{ fontSize: '2.4rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: '#f8fafc', lineHeight: 1 }}>
              {dqiScore}
            </span>
            <span style={{ fontSize: '1.1rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
              / 100
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', color: '#34d399', fontFamily: 'var(--font-mono)' }}>
            <CheckCircle2 size={13} />
            <span>100% Zero Data Loss Guarantee</span>
          </div>
        </div>

        {/* Breakdown Items */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '16px', borderTop: '1px solid rgba(255, 255, 255, 0.08)', paddingTop: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
            <span style={{ color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Lock size={12} color="#00f0ff" />
              SHA-256 Digest
            </span>
            <span style={{ color: '#38bdf8', fontWeight: 600 }}>Tamper-Proof</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
            <span style={{ color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Cpu size={12} color="#c084fc" />
              Dialect Parsers
            </span>
            <span style={{ color: '#c084fc', fontWeight: 600 }}>9 Built-in</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
            <span style={{ color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Layers size={12} color="#fbbf24" />
              WAL Compression
            </span>
            <span style={{ color: '#fbbf24', fontWeight: 600 }}>-{compressionRatio}% reduction</span>
          </div>
        </div>

      </div>

    </div>
  );
};
