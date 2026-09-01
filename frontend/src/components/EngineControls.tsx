import React from 'react';
import { 
  Play, 
  Pause, 
  RotateCcw, 
  StepForward, 
  FastForward, 
  Layers, 
  Radio, 
  FileText,
  Sparkles,
} from 'lucide-react';
import type { SampleLog, StageEnum } from '../types';

interface EngineControlsProps {
  mode: 'STREAM' | 'DEBUG';
  onSetMode: (mode: 'STREAM' | 'DEBUG') => void;
  isStreaming: boolean;
  onToggleStream: () => void;
  eps: number;
  onSetEps: (eps: number) => void;
  stageDelayMs: number;
  onSetStageDelayMs: (ms: number) => void;
  onStepForward: () => void;
  onResetStepper: () => void;
  onFastForward: () => void;
  canStepForward: boolean;
  samples: SampleLog[];
  selectedSampleId: string;
  onSelectSample: (sampleId: string) => void;
  onTriggerSingleEvent: () => void;
  isProcessing: boolean;
  currentStage: StageEnum;
}

export const EngineControls: React.FC<EngineControlsProps> = ({
  mode,
  onSetMode,
  isStreaming,
  onToggleStream,
  eps,
  onSetEps,
  stageDelayMs,
  onSetStageDelayMs,
  onStepForward,
  onResetStepper,
  onFastForward,
  canStepForward,
  samples,
  selectedSampleId,
  onSelectSample,
  onTriggerSingleEvent,
  isProcessing,
  currentStage,
}) => {
  const selectedSample = samples.find((s) => s.id === selectedSampleId) || samples[0];

  return (
    <div className="glass-panel" style={{ margin: '0 20px', padding: '16px 24px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        
        {/* Left Section: Mode Selector & Sample Dropdown */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          
          {/* Mode Switcher Pills */}
          <div style={{ display: 'flex', background: 'rgba(2, 6, 23, 0.7)', borderRadius: '8px', padding: '3px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <button
              onClick={() => onSetMode('STREAM')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 14px',
                borderRadius: '6px',
                border: 'none',
                cursor: 'pointer',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.78rem',
                fontWeight: 600,
                background: mode === 'STREAM' ? 'linear-gradient(135deg, #00f0ff, #0077ff)' : 'transparent',
                color: mode === 'STREAM' ? '#06090f' : '#94a3b8',
                boxShadow: mode === 'STREAM' ? '0 0 12px rgba(0, 240, 255, 0.4)' : 'none',
                transition: 'all 0.2s ease',
              }}
            >
              <Radio size={14} />
              <span>LIVE STREAM</span>
            </button>

            <button
              onClick={() => onSetMode('DEBUG')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 14px',
                borderRadius: '6px',
                border: 'none',
                cursor: 'pointer',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.78rem',
                fontWeight: 600,
                background: mode === 'DEBUG' ? 'linear-gradient(135deg, #a855f7, #6366f1)' : 'transparent',
                color: mode === 'DEBUG' ? '#fff' : '#94a3b8',
                boxShadow: mode === 'DEBUG' ? '0 0 12px rgba(168, 85, 247, 0.4)' : 'none',
                transition: 'all 0.2s ease',
              }}
            >
              <Layers size={14} />
              <span>STEP DEBUGGER</span>
            </button>
          </div>

          {/* Sample Preset Picker */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileText size={16} color="#00f0ff" />
            <select
              value={selectedSampleId}
              onChange={(e) => onSelectSample(e.target.value)}
              style={{
                background: 'rgba(15, 23, 42, 0.9)',
                color: '#f8fafc',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                padding: '7px 12px',
                borderRadius: '6px',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.8rem',
                outline: 'none',
                cursor: 'pointer',
                maxWidth: '280px',
              }}
            >
              {samples.map((s) => (
                <option key={s.id} value={s.id}>
                  [{s.vendor}] {s.title}
                </option>
              ))}
            </select>
            {selectedSample && (
              <span className={`badge ${selectedSample.severity === 'CRITICAL' || selectedSample.severity === 'HIGH' ? 'badge-red' : 'badge-green'}`} style={{ fontSize: '0.65rem' }}>
                {selectedSample.category}
              </span>
            )}
          </div>

        </div>

        {/* Right Section: Stream or Stepper Action Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
          
          {mode === 'STREAM' ? (
            /* Streaming Controls */
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              {/* EPS Speed Slider */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: '#94a3b8' }}>Speed:</span>
                <input
                  type="range"
                  min="0.5"
                  max="10"
                  step="0.5"
                  value={eps}
                  onChange={(e) => onSetEps(parseFloat(e.target.value))}
                  style={{ width: '80px', accentColor: '#00f0ff', cursor: 'pointer' }}
                />
                <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#00f0ff', minWidth: '45px' }}>
                  {eps} EPS
                </span>
              </div>

              {/* Stage Transition Delay Slider */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: '#94a3b8' }}>Pulse:</span>
                <input
                  type="range"
                  min="10"
                  max="200"
                  step="10"
                  value={stageDelayMs}
                  onChange={(e) => onSetStageDelayMs(parseInt(e.target.value))}
                  style={{ width: '70px', accentColor: '#10b981', cursor: 'pointer' }}
                />
                <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#10b981', minWidth: '40px' }}>
                  {stageDelayMs}ms
                </span>
              </div>

              {/* Start / Stop Stream Button */}
              <button
                className={`btn-cyber ${isStreaming ? 'btn-cyber-danger' : 'btn-cyber-primary'}`}
                onClick={onToggleStream}
              >
                {isStreaming ? (
                  <>
                    <Pause size={15} />
                    <span>Pause Stream</span>
                  </>
                ) : (
                  <>
                    <Play size={15} />
                    <span>Start Live Stream</span>
                  </>
                )}
              </button>

              {/* Single Stream Trigger */}
              <button
                className="btn-cyber btn-cyber-secondary"
                onClick={onTriggerSingleEvent}
                disabled={isProcessing}
                title="Send selected log through live animated stream"
              >
                <Sparkles size={15} color="#00f0ff" />
                <span>Stream Single</span>
              </button>
            </div>
          ) : (
            /* Step-by-Step Debugger Controls */
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#c084fc', marginRight: '6px' }}>
                Stage: <strong style={{ color: '#fff' }}>{currentStage}</strong>
              </span>

              {/* Step Forward */}
              <button
                className="btn-cyber btn-cyber-primary"
                onClick={onStepForward}
                disabled={!canStepForward || isProcessing}
                style={{ opacity: canStepForward ? 1 : 0.5 }}
                title="Advance to next pipeline stage"
              >
                <StepForward size={15} />
                <span>Step Next Stage</span>
              </button>

              {/* Fast Forward */}
              <button
                className="btn-cyber btn-cyber-secondary"
                onClick={onFastForward}
                disabled={!canStepForward || isProcessing}
                style={{ opacity: canStepForward ? 1 : 0.5 }}
                title="Execute all remaining stages"
              >
                <FastForward size={15} />
                <span>Fast Forward</span>
              </button>

              {/* Reset Stepper */}
              <button
                className="btn-cyber btn-cyber-secondary"
                onClick={onResetStepper}
                title="Reset back to Ingest stage"
              >
                <RotateCcw size={15} />
                <span>Reset</span>
              </button>
            </div>
          )}

        </div>

      </div>
    </div>
  );
};
