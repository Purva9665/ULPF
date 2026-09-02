import React from 'react';
import type { 
  StageEnum, 
  PipelineContext, 
  StageExecutionMetrics, 
  SampleLog 
} from '../types';
import { 
  Play,
  Pause,
  RotateCcw,
  StepForward,
  FastForward,
  Zap,
  ArrowRight
} from 'lucide-react';

interface PipelineTopologyProps {
  context: PipelineContext | null;
  selectedStage: StageEnum;
  onSelectStage: (stage: StageEnum) => void;
  activeTransitionStage?: StageEnum | null;
  mode: 'STREAM' | 'DEBUG';
  onSetMode: (mode: 'STREAM' | 'DEBUG') => void;
  isStreaming: boolean;
  onToggleStream: () => void;
  eps: number;
  onSetEps: (eps: number) => void;
  samples: SampleLog[];
  selectedSampleId: string;
  onSelectSample: (sampleId: string) => void;
  onTriggerSingleEvent: () => void;
  onStepForward: () => void;
  onResetStepper: () => void;
  onFastForward: () => void;
  canStepForward: boolean;
  isProcessing: boolean;
}

interface StageNodeDef {
  id: StageEnum;
  number: string;
  title: string;
  sub: string;
}

const STAGES: StageNodeDef[] = [
  { id: 'INGEST', number: '01', title: 'INGEST', sub: 'Zero-Loss Capture' },
  { id: 'PARSE', number: '02', title: 'PARSE', sub: 'Multi-Dialect AST' },
  { id: 'NORMALIZE', number: '03', title: 'NORMALIZE', sub: 'Canonical Model' },
  { id: 'VALIDATE', number: '04', title: 'VALIDATE', sub: 'Semantic DQI' },
  { id: 'STORE', number: '05', title: 'STORE', sub: 'SQLite WAL' },
  { id: 'ML', number: '06', title: 'ML ANOMALY', sub: 'Isolation Forest' },
  { id: 'STANDARDIZED', number: '07', title: 'EXPORT', sub: 'SIEM Envelopes' },
];

export const PipelineTopology: React.FC<PipelineTopologyProps> = ({
  context,
  selectedStage,
  onSelectStage,
  activeTransitionStage,
  mode,
  onSetMode,
  isStreaming,
  onToggleStream,
  eps,
  onSetEps,
  samples,
  selectedSampleId,
  onSelectSample,
  onTriggerSingleEvent,
  onStepForward,
  onResetStepper,
  onFastForward,
  canStepForward: _canStepForward,
  isProcessing,
}) => {
  const getStageMetric = (stageId: StageEnum): StageExecutionMetrics | undefined => {
    return context?.stage_metrics?.find((m) => m.stage === stageId);
  };

  const getStageStatus = (stageId: StageEnum) => {
    if (!context) return { isCompleted: false, isCurrent: false, isTransit: false };
    const isCompleted = context.stages_completed?.includes(stageId) || false;
    const isCurrent = context.current_stage === stageId || activeTransitionStage === stageId;
    const isTransit = activeTransitionStage === stageId;
    return { isCompleted, isCurrent, isTransit };
  };

  const getStageLiveSnippet = (stageId: StageEnum): string => {
    if (!context) return 'Standby';
    const isCompleted = context.stages_completed?.includes(stageId);
    if (!isCompleted && context.current_stage !== stageId) return 'Pending';

    if (stageId === 'INGEST' && context.raw_event) return `${context.raw_event.raw.length_bytes}B payload`;
    if (stageId === 'PARSE' && context.parsed_event) return `${context.parsed_event.parser_name} (${Object.keys(context.parsed_event.extracted_fields).length} keys)`;
    if (stageId === 'NORMALIZE' && context.normalized_event) return `${context.normalized_event.event.action} / ${context.normalized_event.event.severity}`;
    if (stageId === 'VALIDATE' && context.validated_event) return `DQI ${context.validated_event.data_quality_score}%`;
    if (stageId === 'STORE' && context.stored_event) return `-${context.stored_event.storage.compression_ratio}% reduction`;
    if (stageId === 'ML' && context.ml_event) return `Score ${context.ml_event.ml.anomaly_score.toFixed(2)} (${context.ml_event.ml.risk_level})`;
    if (stageId === 'STANDARDIZED' && context.final_event) return `ECS/HEC/OCSF`;
    return isCompleted ? 'Completed' : 'Pending';
  };

  return (
    <div className="panel-machined" style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
      
      {/* Instrument Chain Controls Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', borderBottom: '1px solid var(--hairline)', paddingBottom: '12px' }}>
        
        {/* Left: Chain Title & Mode Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '0.88rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
              PIPELINE SIGNAL CHAIN
            </span>
          </div>

          <div style={{ display: 'flex', background: 'var(--panel-sunken)', padding: '2px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--hairline)' }}>
            <button
              onClick={() => onSetMode('STREAM')}
              style={{
                padding: '3px 8px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.72rem',
                fontFamily: 'var(--font-chrome)',
                fontWeight: mode === 'STREAM' ? 600 : 500,
                border: 'none',
                cursor: 'pointer',
                background: mode === 'STREAM' ? 'var(--panel)' : 'transparent',
                color: mode === 'STREAM' ? 'var(--phosphor-amber)' : 'var(--text-mid)',
              }}
            >
              Live Stream
            </button>
            <button
              onClick={() => onSetMode('DEBUG')}
              style={{
                padding: '3px 8px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.72rem',
                fontFamily: 'var(--font-chrome)',
                fontWeight: mode === 'DEBUG' ? 600 : 500,
                border: 'none',
                cursor: 'pointer',
                background: mode === 'DEBUG' ? 'var(--panel)' : 'transparent',
                color: mode === 'DEBUG' ? 'var(--phosphor-amber)' : 'var(--text-mid)',
              }}
            >
              Step Debug
            </button>
          </div>
        </div>

        {/* Right: Signal Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          
          {/* Sample Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-low)', fontFamily: 'var(--font-readout)' }}>SAMPLE:</span>
            <select
              value={selectedSampleId}
              onChange={(e) => onSelectSample(e.target.value)}
              style={{
                background: 'var(--panel-sunken)',
                border: '1px solid var(--hairline)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontSize: '0.72rem',
                fontFamily: 'var(--font-readout)',
                padding: '4px 8px',
                outline: 'none',
              }}
            >
              {samples.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.vendor} • {s.title}
                </option>
              ))}
            </select>
          </div>

          {/* STREAM Mode Controls */}
          {mode === 'STREAM' && (
            <>
              {/* EPS Slider */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--panel-sunken)', padding: '3px 8px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--hairline)' }}>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-low)', fontFamily: 'var(--font-readout)' }}>EPS:</span>
                <input
                  type="range"
                  min="1"
                  max="20"
                  step="1"
                  value={eps}
                  onChange={(e) => onSetEps(parseFloat(e.target.value))}
                  style={{ width: '60px', accentColor: 'var(--phosphor-amber)', cursor: 'pointer' }}
                />
                <span className="readout" style={{ fontSize: '0.72rem', color: 'var(--phosphor-amber)', fontWeight: 600, minWidth: '32px' }}>
                  {eps}
                </span>
              </div>

              {/* Single Trigger */}
              <button
                onClick={onTriggerSingleEvent}
                disabled={isProcessing}
                className="btn-instrument"
                title="Send single log through chain"
              >
                <Zap size={11} color="var(--phosphor-amber)" />
                <span>Single</span>
              </button>

              {/* Toggle Live Stream */}
              <button
                onClick={onToggleStream}
                className={isStreaming ? 'btn-instrument btn-instrument-danger' : 'btn-instrument btn-instrument-primary'}
              >
                {isStreaming ? <Pause size={11} /> : <Play size={11} />}
                <span>{isStreaming ? 'Halt' : 'Stream'}</span>
              </button>
            </>
          )}

          {/* DEBUG Mode Controls */}
          {mode === 'DEBUG' && (
            <>
              <button
                onClick={onStepForward}
                disabled={isProcessing}
                className="btn-instrument btn-instrument-primary"
                title="Advance pipeline by exactly one stage"
              >
                <StepForward size={11} />
                <span>
                  {(!context || context.is_completed || (context.stages_completed?.length || 0) === 0)
                    ? 'Step [01]'
                    : (context.stages_completed?.length || 0) < 7
                    ? `Step [0${(context.stages_completed?.length || 0) + 1}]`
                    : 'Restart [01]'}
                </span>
              </button>

              <button
                onClick={onFastForward}
                disabled={isProcessing}
                className="btn-instrument"
                title="Execute all remaining stages"
              >
                <FastForward size={11} />
                <span>Run Full</span>
              </button>

              <button
                onClick={onResetStepper}
                className="btn-instrument"
                title="Reset pipeline debugger"
              >
                <RotateCcw size={11} />
                <span>Reset</span>
              </button>
            </>
          )}

        </div>

      </div>

      {/* 7 Connected Stage Jacks */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: '8px', alignItems: 'stretch' }}>
        {STAGES.map((st, idx) => {
          const { isCompleted, isCurrent, isTransit } = getStageStatus(st.id);
          const metric = getStageMetric(st.id);
          const liveText = getStageLiveSnippet(st.id);
          const isSelected = selectedStage === st.id;

          let borderCol = 'var(--hairline)';
          let bgCol = 'var(--panel-sunken)';
          let statusLabel = 'STANDBY';
          let statusColor = 'var(--text-low)';

          if (isCurrent) {
            borderCol = 'var(--phosphor-amber)';
            bgCol = 'rgba(232, 163, 61, 0.08)';
            statusLabel = 'ACTIVE';
            statusColor = 'var(--phosphor-amber)';
          } else if (isCompleted) {
            borderCol = 'rgba(127, 166, 107, 0.4)';
            bgCol = 'rgba(127, 166, 107, 0.06)';
            statusLabel = 'DONE';
            statusColor = 'var(--confirm-moss)';
          }

          return (
            <div
              key={st.id}
              onClick={() => onSelectStage(st.id)}
              style={{
                background: bgCol,
                border: `1px solid ${borderCol}`,
                borderRadius: 'var(--radius-sm)',
                padding: '10px 10px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                cursor: 'pointer',
                transition: 'border-color 0.15s ease',
                position: 'relative',
                boxShadow: isSelected ? '0 0 0 1px var(--phosphor-amber)' : 'none',
              }}
            >
              {/* Connector Arrow Indicator between stages */}
              {idx < STAGES.length - 1 && (
                <div 
                  style={{
                    position: 'absolute',
                    right: '-7px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    zIndex: 10,
                    width: '14px',
                    height: '14px',
                    borderRadius: '2px',
                    background: 'var(--panel)',
                    border: '1px solid var(--hairline)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <ArrowRight size={8} color={isCompleted ? 'var(--confirm-moss)' : isTransit ? 'var(--phosphor-amber)' : 'var(--text-low)'} />
                </div>
              )}

              {/* Stage Header */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span className="readout" style={{ fontSize: '0.68rem', fontWeight: 700, color: isCurrent ? 'var(--phosphor-amber)' : 'var(--text-mid)' }}>
                  [{st.number}]
                </span>
                
                <span className="readout" style={{ fontSize: '0.62rem', fontWeight: 600, color: statusColor }}>
                  {statusLabel}
                </span>
              </div>

              {/* Stage Title */}
              <div style={{ marginBottom: '8px' }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)', letterSpacing: '0.02em' }}>
                  {st.title}
                </div>
                <div style={{ fontSize: '0.64rem', color: 'var(--text-low)', fontFamily: 'var(--font-readout)', marginTop: '1px' }}>
                  {st.sub}
                </div>
              </div>

              {/* Live Readout Data */}
              <div 
                style={{
                  background: 'var(--ink)',
                  border: '1px solid var(--hairline)',
                  borderRadius: '2px',
                  padding: '5px 6px',
                  fontSize: '0.66rem',
                  color: 'var(--text-mid)',
                  fontFamily: 'var(--font-readout)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '2px',
                }}
              >
                <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={liveText}>
                  {liveText}
                </div>
                {metric && (
                  <div style={{ color: 'var(--phosphor-amber)', fontSize: '0.6rem', textAlign: 'right' }}>
                    {metric.duration_us} µs
                  </div>
                )}
              </div>

            </div>
          );
        })}
      </div>

      {/* Footer Info Strip */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-low)', fontFamily: 'var(--font-readout)', borderTop: '1px solid var(--hairline)', paddingTop: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span>TOTAL PIPELINE LATENCY: <strong style={{ color: 'var(--phosphor-amber)' }}>{context?.total_duration_us ?? 340} µs</strong></span>
          <span>•</span>
          <span>STAGES: {context?.stages_completed?.length ?? 0}/7</span>
        </div>
        <div>
          Click any jack to open inspector
        </div>
      </div>

    </div>
  );
};
