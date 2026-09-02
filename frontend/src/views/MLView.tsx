import React from 'react';
import type { 
  PipelineContext, 
  EngineStats 
} from '../types';
import { 
  ArrowLeft
} from 'lucide-react';

interface MLViewProps {
  context: PipelineContext | null;
  stats: EngineStats | null;
  onBackToOverview: () => void;
}

export const MLView: React.FC<MLViewProps> = ({
  context,
  stats: _stats,
  onBackToOverview,
}) => {
  const mlEvent = context?.ml_event;
  const ml = mlEvent?.ml;
  const isAnomalous = ml?.is_anomalous || false;
  const anomalyScore = ml ? ml.anomaly_score : 0.08;
  const riskLevel = ml ? ml.risk_level : 'INFORMATIONAL';
  const entropy = ml ? ml.shannon_entropy : 4.23;
  const durationUs = mlEvent?.ml_duration_us || 52;
  const features = ml?.feature_contributions || [
    { feature: 'destination_port_uncommon', weight: 0.35, description: 'Target port deviates from standard protocol baselines', value: 445 },
    { feature: 'payload_shannon_entropy', weight: 0.28, description: 'Byte entropy indicates structured binary / sweep', value: 4.23 },
    { feature: 'byte_volume_deviation', weight: 0.20, description: 'Transfer size exceeds moving window average', value: '1,420 B' },
    { feature: 'action_deny_frequency', weight: 0.17, description: 'Repeated firewall deny actions from source IP', value: 'DENY' },
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
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span className="badge-inst badge-amber">STAGE [06]</span>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
              Local Isolation Forest & Shannon Entropy
            </h2>
          </div>
        </div>

        <div className="readout" style={{ fontSize: '0.74rem', color: 'var(--text-low)' }}>
          INFERENCE LATENCY: <strong style={{ color: 'var(--phosphor-amber)' }}>{durationUs} µs</strong>
        </div>
      </div>

      {/* 4 Readout Metric Tiles */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>ANOMALY SCORE</div>
          <div className="readout" style={{ fontSize: '1.4rem', fontWeight: 700, color: isAnomalous ? 'var(--alert-coral)' : 'var(--confirm-moss)', margin: '2px 0' }}>
            {anomalyScore.toFixed(2)}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>
            {isAnomalous ? 'ANOMALOUS TRAFFIC' : 'NORMAL PERIMETER FLOW'}
          </div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>SHANNON ENTROPY</div>
          <div className="readout" style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--signal-teal)', margin: '2px 0' }}>
            {entropy} <span style={{ fontSize: '0.8rem', color: 'var(--text-low)' }}>bits</span>
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Payload Randomness</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>RISK CLASSIFICATION</div>
          <div className="readout" style={{ fontSize: '1.2rem', fontWeight: 700, color: isAnomalous ? 'var(--alert-coral)' : 'var(--phosphor-amber)', margin: '2px 0' }}>
            {riskLevel}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Threshold: 0.60 Score</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>LOCAL MODEL SPEC</div>
          <div className="readout" style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-high)', margin: '4px 0' }}>
            Scikit-Learn IsolationForest
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--confirm-moss)' }}>Offline / 0ms Network</div>
        </div>
      </div>

      {/* Feature Attribution Waterfall */}
      <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
        <div style={{ borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
          <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
            EXPLAINABLE FEATURE ATTRIBUTION WATERFALL
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {features.map((feat, idx) => {
            const pct = Math.round(feat.weight * 100);
            return (
              <div
                key={idx}
                style={{
                  background: 'var(--panel-sunken)',
                  border: '1px solid var(--hairline)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '10px 12px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="readout" style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-high)' }}>
                      {feat.feature}
                    </span>
                    {feat.value !== undefined && (
                      <span className="badge-inst badge-hairline" style={{ fontSize: '0.62rem' }}>
                        val: {String(feat.value)}
                      </span>
                    )}
                  </div>

                  <span className="readout" style={{ fontSize: '0.74rem', color: 'var(--phosphor-amber)', fontWeight: 700 }}>
                    WEIGHT: {pct}%
                  </span>
                </div>

                <div style={{ fontSize: '0.7rem', color: 'var(--text-mid)', fontFamily: 'var(--font-chrome)' }}>
                  {feat.description}
                </div>

                {/* Progress Bar */}
                <div style={{ width: '100%', height: '4px', background: 'var(--ink)', borderRadius: '2px', overflow: 'hidden' }}>
                  <div 
                    style={{ 
                      width: `${pct}%`, 
                      height: '100%', 
                      backgroundColor: isAnomalous ? 'var(--alert-coral)' : 'var(--phosphor-amber)',
                      borderRadius: '2px',
                    }} 
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};
