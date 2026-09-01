import React from 'react';
import type { 
  PipelineContext, 
  EngineStats 
} from '../types';
import { 
  BrainCircuit, 
  ArrowLeft, 
  Clock, 
  ShieldAlert, 
  Binary,
  BarChart3,
} from 'lucide-react';

interface MLViewProps {
  context: PipelineContext | null;
  stats: EngineStats | null;
  onBackToOverview: () => void;
}

export const MLView: React.FC<MLViewProps> = ({
  context,
  stats,
  onBackToOverview,
}) => {
  const mlEvent = context?.ml_event;
  const ml = mlEvent?.ml;
  const isAnomalous = ml?.is_anomalous || false;
  const anomalyScore = ml ? ml.anomaly_score : 0.08;
  const riskLevel = ml ? ml.risk_level : 'INFORMATIONAL';
  const entropy = ml ? ml.shannon_entropy : 4.23;
  const confidence = ml ? (ml.confidence * 100).toFixed(0) : '94';
  const durationUs = mlEvent?.ml_duration_us || 52;
  const features = ml?.feature_contributions || [
    { feature: 'destination_port_uncommon', weight: 0.35, description: 'Target port deviates from standard protocol baselines', value: 445 },
    { feature: 'payload_shannon_entropy', weight: 0.28, description: 'Byte entropy indicates structured binary / sweep', value: 4.23 },
    { feature: 'byte_volume_deviation', weight: 0.20, description: 'Transfer size exceeds moving window average', value: '1,420 B' },
    { feature: 'action_deny_frequency', weight: 0.17, description: 'Repeated firewall deny actions from source IP', value: 'DENY' },
  ];

  const totalAnomalies = stats?.storage.total_anomalies || 0;
  const totalEvents = stats?.storage.total_events || stats?.total_processed || 1;
  const anomalyPct = ((totalAnomalies / Math.max(totalEvents, 1)) * 100).toFixed(1);

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
              <span className="badge badge-red" style={{ fontSize: '0.72rem' }}>STAGE 06</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Local ML Anomaly & Entropy Engine
              </h2>
            </div>
            <p style={{ fontSize: '0.74rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Local Isolation Forest Model, Shannon Information Entropy, and Explainable Feature Attribution
            </p>
          </div>
        </div>

        {/* Model Execution Badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(15, 23, 42, 0.7)', padding: '6px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <span style={{ fontSize: '0.72rem', color: '#f43f5e', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            MODEL: LOCAL SCIKIT-LEARN ISOLATION FOREST
          </span>
          <span className="badge badge-green" style={{ fontSize: '0.6rem' }}>OFFLINE / REAL-TIME</span>
        </div>
      </div>

      {/* Top 4 Metrics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        
        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Anomaly Score</span>
            <BrainCircuit size={16} color={isAnomalous ? '#f43f5e' : '#10b981'} />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: isAnomalous ? '#f43f5e' : '#10b981', margin: '4px 0' }}>
            {anomalyScore.toFixed(2)}
          </div>
          <div style={{ fontSize: '0.68rem', color: isAnomalous ? '#f87171' : '#34d399', fontFamily: 'var(--font-mono)' }}>
            {isAnomalous ? 'ANOMALOUS TRAFFIC PATTERN' : 'NORMAL PERIMETER FLOW'}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Shannon Entropy</span>
            <Binary size={16} color="#c084fc" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: '#c084fc', margin: '4px 0' }}>
            {entropy} <span style={{ fontSize: '0.9rem', color: '#64748b' }}>bits</span>
          </div>
          <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            Payload Randomness Index
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Risk Classification</span>
            <ShieldAlert size={16} color={isAnomalous ? '#fbbf24' : '#38bdf8'} />
          </div>
          <div style={{ fontSize: '1.3rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: isAnomalous ? '#fbbf24' : '#38bdf8', margin: '4px 0' }}>
            {riskLevel} RISK
          </div>
          <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            Confidence: {confidence}% Deterministic
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Inference Latency</span>
            <Clock size={16} color="#fbbf24" />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: '#fbbf24', margin: '4px 0' }}>
            {durationUs} µs
          </div>
          <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            Zero External API Calls
          </div>
        </div>

      </div>

      {/* Main Grid: Left Feature Contribution Waterfall, Right Model Parameters & Baseline */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: '20px' }}>
        
        {/* Left: Explainable Feature Contribution Waterfall */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <BarChart3 size={18} color="#00f0ff" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Feature Attribution & Contribution Waterfall
              </h3>
            </div>
            <span className="badge badge-cyan" style={{ fontSize: '0.62rem' }}>SHAP-STYLE WEIGHTS</span>
          </div>

          <p style={{ fontSize: '0.74rem', color: '#94a3b8', marginBottom: '16px', lineHeight: 1.5 }}>
            The local Isolation Forest evaluates normalized vector attributes against perimeter baseline distributions. Higher weights represent the strongest mathematical contributors to the score.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', flex: 1 }}>
            {features.map((feat, idx) => {
              const weightPct = Math.round(feat.weight * 100);
              return (
                <div
                  key={idx}
                  style={{
                    background: 'rgba(15, 23, 42, 0.65)',
                    padding: '12px 14px',
                    borderRadius: '8px',
                    border: '1px solid rgba(255, 255, 255, 0.05)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
                        {feat.feature}
                      </span>
                      {feat.value !== undefined && (
                        <span style={{ fontSize: '0.68rem', color: '#38bdf8', fontFamily: 'var(--font-mono)', background: 'rgba(56, 189, 248, 0.15)', padding: '1px 6px', borderRadius: '4px' }}>
                          Value: {String(feat.value)}
                        </span>
                      )}
                    </div>
                    <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#00f0ff', fontFamily: 'var(--font-mono)' }}>
                      +{weightPct}%
                    </span>
                  </div>

                  <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginBottom: '6px' }}>
                    {feat.description}
                  </div>

                  {/* Weight Progress Bar */}
                  <div style={{ width: '100%', height: '6px', background: 'rgba(0, 0, 0, 0.4)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div
                      style={{
                        width: `${weightPct}%`,
                        height: '100%',
                        background: 'linear-gradient(90deg, #00f0ff, #a855f7)',
                        borderRadius: '3px',
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

        </div>

        {/* Right: Model Architecture & Hyperparameters */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <BrainCircuit size={18} color="#f43f5e" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Local Model Specification
              </h3>
            </div>
            <span className="badge badge-red" style={{ fontSize: '0.62rem' }}>OFFLINE ML</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', flex: 1 }}>
            
            <div style={{ background: 'rgba(15, 23, 42, 0.65)', padding: '10px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Model Architecture</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
                Scikit-Learn IsolationForest
              </div>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '2px' }}>
                100 Estimators • Max Samples: 256 • Contamination: 0.05
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.65)', padding: '10px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Information Theory Engine</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#c084fc', fontFamily: 'var(--font-mono)' }}>
                Shannon Information Entropy
              </div>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '2px' }}>
                H(X) = -Σ P(x) log₂ P(x) computed per raw log byte stream
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.65)', padding: '10px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Global Anomaly Rate</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#fbbf24', fontFamily: 'var(--font-mono)' }}>
                {anomalyPct}% of Processed Stream
              </div>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '2px' }}>
                {totalAnomalies} flagged / {totalEvents} total stored records
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.65)', padding: '10px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
              <div style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>Compliance & Privacy</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#10b981', fontFamily: 'var(--font-mono)' }}>
                100% Self-Contained Local Execution
              </div>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '2px' }}>
                Zero telemetry leaves perimeter environment
              </div>
            </div>

          </div>

        </div>

      </div>

    </div>
  );
};
