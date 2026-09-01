import React from 'react';
import type { 
  StageEnum, 
  StageStatus, 
  PipelineContext, 
  StageExecutionMetrics, 
  SampleLog 
} from '../types';
import { 
  FileInput, 
  Cpu, 
  GitMerge, 
  ShieldCheck, 
  Database, 
  BrainCircuit, 
  CheckCircle2,
  Play,
  Pause,
  RotateCcw,
  StepForward,
  FastForward,
  Radio,
  Sliders,
  Layers,
  Zap,
  Clock,
} from 'lucide-react';

interface MainLivePipelineProps {
  context: PipelineContext | null;
  selectedStage: StageEnum;
  onSelectStage: (stage: StageEnum) => void;
  activeTransitionStage?: StageEnum | null;
  // Controls
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

interface StageDefinition {
  id: StageEnum;
  number: string;
  name: string;
  icon: React.ComponentType<{ size: number; color?: string; className?: string }>;
  accentColor: string;
  glowClass: string;
  badgeClass: string;
  subtitle: string;
}

const STAGES: StageDefinition[] = [
  {
    id: 'INGEST',
    number: '01',
    name: 'INGESTION',
    icon: FileInput,
    accentColor: '#00f0ff',
    glowClass: 'anim-pulse-cyan',
    badgeClass: 'badge-cyan',
    subtitle: 'Zero-Loss Raw Capture & SHA-256',
  },
  {
    id: 'PARSE',
    number: '02',
    name: 'PARSER',
    icon: Cpu,
    accentColor: '#c084fc',
    glowClass: 'anim-pulse-cyan',
    badgeClass: 'badge-purple',
    subtitle: 'Multi-Dialect AST Extraction',
  },
  {
    id: 'NORMALIZE',
    number: '03',
    name: 'NORMALIZATION',
    icon: GitMerge,
    accentColor: '#38bdf8',
    glowClass: 'anim-pulse-cyan',
    badgeClass: 'badge-cyan',
    subtitle: 'Canonical Taxonomy Mapping',
  },
  {
    id: 'VALIDATE',
    number: '04',
    name: 'VALIDATION',
    icon: ShieldCheck,
    accentColor: '#10b981',
    glowClass: 'anim-pulse-green',
    badgeClass: 'badge-green',
    subtitle: 'Semantic Rules & DQI Scoring',
  },
  {
    id: 'STORE',
    number: '05',
    name: 'STORAGE',
    icon: Database,
    accentColor: '#fbbf24',
    glowClass: 'anim-pulse-amber',
    badgeClass: 'badge-amber',
    subtitle: 'PostgreSQL / SQLite WAL Engine',
  },
  {
    id: 'ML',
    number: '06',
    name: 'ML ANOMALY',
    icon: BrainCircuit,
    accentColor: '#f43f5e',
    glowClass: 'anim-pulse-red',
    badgeClass: 'badge-red',
    subtitle: 'Local Isolation Forest & Entropy',
  },
  {
    id: 'STANDARDIZED',
    number: '07',
    name: 'EXPORT',
    icon: CheckCircle2,
    accentColor: '#818cf8',
    glowClass: 'anim-pulse-green',
    badgeClass: 'badge-blue',
    subtitle: 'Standardized SIEM ECS/HEC/OCSF',
  },
];

export const MainLivePipeline: React.FC<MainLivePipelineProps> = ({
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
  canStepForward,
  isProcessing,
}) => {
  const getStageMetric = (stageId: StageEnum): StageExecutionMetrics | undefined => {
    return context?.stage_metrics?.find((m) => m.stage === stageId);
  };

  const getNodeStatus = (stageId: StageEnum): { status: StageStatus; isCurrent: boolean; isCompleted: boolean } => {
    if (!context) return { status: 'PENDING', isCurrent: false, isCompleted: false };
    
    const isCompleted = context.stages_completed?.includes(stageId) || false;
    const isCurrent = context.current_stage === stageId || activeTransitionStage === stageId;
    const metric = getStageMetric(stageId);

    if (metric?.status === 'ERROR') return { status: 'ERROR', isCurrent, isCompleted };
    if (metric?.status === 'WARNING') return { status: 'WARNING', isCurrent, isCompleted };
    if (isCurrent && !isCompleted) return { status: 'RUNNING', isCurrent, isCompleted: false };
    if (isCompleted) return { status: 'COMPLETED', isCurrent, isCompleted: true };
    return { status: 'PENDING', isCurrent, isCompleted: false };
  };

  const getStageSnippet = (stageId: StageEnum): string => {
    if (!context) return 'Awaiting payload';
    
    if (stageId === 'INGEST' && context.raw_event) {
      return `${context.raw_event.raw.length_bytes}B • SHA-256 OK`;
    }
    if (stageId === 'PARSE' && context.parsed_event) {
      return `${context.parsed_event.parser_name} (${Object.keys(context.parsed_event.extracted_fields).length} keys)`;
    }
    if (stageId === 'NORMALIZE' && context.normalized_event) {
      return `${context.normalized_event.event.action} • ${context.normalized_event.event.severity}`;
    }
    if (stageId === 'VALIDATE' && context.validated_event) {
      return `DQI ${context.validated_event.data_quality_score}% • Validated`;
    }
    if (stageId === 'STORE' && context.stored_event) {
      return `WAL -${context.stored_event.storage.compression_ratio}% reduction`;
    }
    if (stageId === 'ML' && context.ml_event) {
      return `Anomaly: ${context.ml_event.ml.anomaly_score.toFixed(2)} (${context.ml_event.ml.risk_level})`;
    }
    if (stageId === 'STANDARDIZED' && context.final_event) {
      return `ECS, Splunk, OCSF Ready`;
    }
    return 'Pending execution';
  };

  return (
    <div className="glass-panel" style={{ padding: '20px 24px', position: 'relative', overflow: 'hidden' }}>
      
      {/* Top Header & View Controls */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#f8fafc', letterSpacing: '0.02em' }}>
              Main Live Pipeline
            </h2>
            <span className={`badge ${isStreaming ? 'badge-cyan anim-pulse-cyan' : 'badge-gray'}`} style={{ fontSize: '0.7rem' }}>
              <Zap size={12} />
              {isStreaming ? `LIVE STREAM (${eps} EPS)` : mode === 'DEBUG' ? 'STEP DEBUGGER' : 'STANDBY'}
            </span>
          </div>
          <p style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            Real-Time Heterogeneous Perimeter Network Processing Flow
          </p>
        </div>

        {/* Mode Switcher & Integrated Stream Toolbar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          
          {/* Sample Preset Dropdown */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>Preset:</span>
            <select
              value={selectedSampleId}
              onChange={(e) => onSelectSample(e.target.value)}
              disabled={isStreaming}
              style={{
                background: 'rgba(15, 23, 42, 0.9)',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                color: '#e2e8f0',
                padding: '6px 12px',
                borderRadius: '8px',
                fontSize: '0.78rem',
                fontFamily: 'var(--font-mono)',
                cursor: isStreaming ? 'not-allowed' : 'pointer',
                maxWidth: '210px',
              }}
            >
              {samples.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.title}
                </option>
              ))}
            </select>
          </div>

          {/* Mode Switcher */}
          <div style={{ display: 'flex', background: 'rgba(2, 6, 23, 0.75)', borderRadius: '8px', padding: '3px', border: '1px solid rgba(255, 255, 255, 0.1)' }}>
            <button
              onClick={() => onSetMode('STREAM')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '5px 12px',
                borderRadius: '6px',
                border: 'none',
                cursor: 'pointer',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.75rem',
                fontWeight: 600,
                background: mode === 'STREAM' ? 'linear-gradient(135deg, #00f0ff, #0284c7)' : 'transparent',
                color: mode === 'STREAM' ? '#06090f' : '#94a3b8',
                transition: 'all 0.2s ease',
              }}
            >
              <Radio size={13} />
              <span>STREAM</span>
            </button>

            <button
              onClick={() => onSetMode('DEBUG')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '5px 12px',
                borderRadius: '6px',
                border: 'none',
                cursor: 'pointer',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.75rem',
                fontWeight: 600,
                background: mode === 'DEBUG' ? 'linear-gradient(135deg, #a855f7, #6366f1)' : 'transparent',
                color: mode === 'DEBUG' ? '#ffffff' : '#94a3b8',
                transition: 'all 0.2s ease',
              }}
            >
              <Layers size={13} />
              <span>STEP DEBUG</span>
            </button>
          </div>

          {/* Action Buttons based on mode */}
          {mode === 'STREAM' ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                className={`btn-cyber ${isStreaming ? 'btn-cyber-danger' : 'btn-cyber-primary'}`}
                onClick={onToggleStream}
                style={{ padding: '6px 14px', fontSize: '0.78rem' }}
              >
                {isStreaming ? <Pause size={14} /> : <Play size={14} />}
                <span>{isStreaming ? 'Pause Stream' : 'Live Stream'}</span>
              </button>

              <button
                className="btn-cyber btn-cyber-secondary"
                onClick={onTriggerSingleEvent}
                disabled={isStreaming || isProcessing}
                style={{ padding: '6px 12px', fontSize: '0.78rem' }}
                title="Inject single event"
              >
                <Zap size={14} />
                <span>Single</span>
              </button>

              {/* EPS Slider */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(15, 23, 42, 0.6)', padding: '4px 10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                <Sliders size={13} color="#00f0ff" />
                <span style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>{eps} EPS</span>
                <input
                  type="range"
                  min="0.5"
                  max="15.0"
                  step="0.5"
                  value={eps}
                  onChange={(e) => onSetEps(parseFloat(e.target.value))}
                  style={{ width: '60px', accentColor: '#00f0ff', cursor: 'pointer' }}
                />
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                className="btn-cyber btn-cyber-primary"
                onClick={onStepForward}
                disabled={!canStepForward || isProcessing}
                style={{ padding: '6px 14px', fontSize: '0.78rem' }}
              >
                <StepForward size={14} />
                <span>Step ➔</span>
              </button>

              <button
                className="btn-cyber btn-cyber-secondary"
                onClick={onFastForward}
                disabled={!canStepForward || isProcessing}
                style={{ padding: '6px 12px', fontSize: '0.78rem' }}
              >
                <FastForward size={14} />
                <span>Run End</span>
              </button>

              <button
                className="btn-cyber btn-cyber-secondary"
                onClick={onResetStepper}
                style={{ padding: '6px 10px' }}
                title="Reset Pipeline"
              >
                <RotateCcw size={14} />
              </button>
            </div>
          )}

        </div>
      </div>

      {/* Centerpiece Visual Pipeline Flow Node Canvas */}
      <div 
        style={{ 
          position: 'relative', 
          padding: '24px 10px 20px 10px',
          borderRadius: '12px',
          background: 'rgba(6, 10, 18, 0.65)',
          border: '1px solid rgba(255, 255, 255, 0.06)',
          minHeight: '190px',
        }}
      >
        {/* Ambient background glow behind nodes */}
        <div 
          style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: '90%',
            height: '60px',
            background: 'radial-gradient(ellipse at center, rgba(0, 240, 255, 0.08) 0%, rgba(168, 85, 247, 0.04) 50%, transparent 80%)',
            filter: 'blur(20px)',
            pointerEvents: 'none',
          }} 
        />

        {/* SVG Connecting Flow Lines across all 7 stages */}
        <svg 
          style={{ 
            position: 'absolute', 
            top: '60px', 
            left: '3%', 
            width: '94%', 
            height: '24px', 
            zIndex: 1, 
            pointerEvents: 'none' 
          }}
        >
          <defs>
            <linearGradient id="pipelineFlowGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.8" />
              <stop offset="25%" stopColor="#a855f7" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#10b981" stopOpacity="0.8" />
              <stop offset="75%" stopColor="#f59e0b" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#6366f1" stopOpacity="0.8" />
            </linearGradient>
          </defs>

          {/* Background Track Line */}
          <line
            x1="2%"
            y1="12"
            x2="98%"
            y2="12"
            stroke="rgba(255, 255, 255, 0.08)"
            strokeWidth="3"
            strokeLinecap="round"
          />

          {/* Animated Active Particle Flow Line */}
          <line
            x1="2%"
            y1="12"
            x2="98%"
            y2="12"
            stroke="url(#pipelineFlowGrad)"
            strokeWidth={isStreaming ? "3.5" : "2"}
            strokeLinecap="round"
            className={isStreaming ? "anim-flow-active" : ""}
            strokeOpacity={isStreaming ? 0.9 : 0.4}
          />
        </svg>

        {/* The 7 Interactive Stage Nodes */}
        <div 
          style={{ 
            position: 'relative', 
            zIndex: 2, 
            display: 'grid', 
            gridTemplateColumns: 'repeat(7, 1fr)', 
            gap: '12px',
          }}
        >
          {STAGES.map((st) => {
            const { status, isCurrent, isCompleted } = getNodeStatus(st.id);
            const isSelected = selectedStage === st.id;
            const metric = getStageMetric(st.id);
            const snippet = getStageSnippet(st.id);
            const Icon = st.icon;

            // Determine border and glow styling
            let borderColor = 'rgba(255, 255, 255, 0.08)';
            let bgColor = 'rgba(15, 23, 42, 0.85)';
            let iconBg = 'rgba(255, 255, 255, 0.05)';
            let statusBadge = 'badge-gray';
            let statusLabel = 'QUEUED';

            if (status === 'COMPLETED') {
              borderColor = 'rgba(16, 185, 129, 0.5)';
              bgColor = 'rgba(6, 78, 59, 0.25)';
              iconBg = 'rgba(16, 185, 129, 0.2)';
              statusBadge = 'badge-green';
              statusLabel = 'COMPLETED';
            } else if (status === 'RUNNING' || isCurrent) {
              borderColor = st.accentColor;
              bgColor = 'rgba(15, 23, 42, 0.95)';
              iconBg = `${st.accentColor}25`;
              statusBadge = st.badgeClass;
              statusLabel = 'ACTIVE';
            } else if (status === 'WARNING') {
              borderColor = 'rgba(245, 158, 11, 0.6)';
              bgColor = 'rgba(120, 53, 15, 0.25)';
              iconBg = 'rgba(245, 158, 11, 0.2)';
              statusBadge = 'badge-amber';
              statusLabel = 'WARNING';
            } else if (status === 'ERROR') {
              borderColor = 'rgba(239, 68, 68, 0.7)';
              bgColor = 'rgba(127, 29, 29, 0.3)';
              iconBg = 'rgba(239, 68, 68, 0.25)';
              statusBadge = 'badge-red';
              statusLabel = 'ERROR';
            }

            return (
              <div
                key={st.id}
                onClick={() => onSelectStage(st.id)}
                style={{
                  background: isSelected ? 'rgba(30, 41, 59, 0.9)' : bgColor,
                  border: `1.5px solid ${isSelected ? '#00f0ff' : borderColor}`,
                  borderRadius: '12px',
                  padding: '12px 10px',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  textAlign: 'center',
                  transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
                  boxShadow: isSelected 
                    ? '0 0 20px rgba(0, 240, 255, 0.35)' 
                    : isCurrent 
                    ? `0 0 16px ${st.accentColor}40` 
                    : '0 4px 12px rgba(0, 0, 0, 0.4)',
                  transform: isSelected ? 'translateY(-2px)' : 'none',
                }}
              >
                {/* Node Top: Stage Number & Status Badge */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', marginBottom: '8px' }}>
                  <span style={{ fontSize: '0.65rem', fontFamily: 'var(--font-mono)', color: '#64748b', fontWeight: 700 }}>
                    [{st.number}]
                  </span>
                  <span className={`badge ${statusBadge}`} style={{ fontSize: '0.58rem', padding: '1px 5px' }}>
                    {statusLabel}
                  </span>
                </div>

                {/* Node Center: Icon & Name */}
                <div
                  style={{
                    width: '38px',
                    height: '38px',
                    borderRadius: '50%',
                    background: iconBg,
                    border: `1.5px solid ${isCurrent || isSelected ? st.accentColor : 'rgba(255, 255, 255, 0.1)'}`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginBottom: '8px',
                    transition: 'all 0.2s ease',
                    boxShadow: isCurrent ? `0 0 12px ${st.accentColor}` : 'none',
                  }}
                  className={isCurrent ? st.glowClass : ''}
                >
                  <Icon size={18} color={isCompleted ? '#10b981' : st.accentColor} />
                </div>

                <div style={{ fontSize: '0.78rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc', letterSpacing: '0.04em', whiteSpace: 'nowrap' }}>
                  {st.name}
                </div>

                {/* Duration Microseconds */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '3px', marginTop: '4px', color: '#38bdf8', fontSize: '0.68rem', fontFamily: 'var(--font-mono)' }}>
                  <Clock size={10} />
                  <span>{metric ? `${metric.duration_us} µs` : '--'}</span>
                </div>

                {/* Real Data Snippet Pill */}
                <div 
                  style={{
                    marginTop: '8px',
                    fontSize: '0.62rem',
                    fontFamily: 'var(--font-mono)',
                    color: isCompleted ? '#cbd5e1' : '#64748b',
                    background: 'rgba(0, 0, 0, 0.45)',
                    padding: '3px 6px',
                    borderRadius: '4px',
                    width: '100%',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    border: '1px solid rgba(255, 255, 255, 0.04)',
                  }}
                  title={snippet}
                >
                  {snippet}
                </div>

              </div>
            );
          })}
        </div>

      </div>

      {/* Bottom Status Legend & Quick Metric Bar */}
      <div 
        style={{ 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'space-between', 
          marginTop: '14px', 
          paddingTop: '10px', 
          borderTop: '1px solid rgba(255, 255, 255, 0.06)',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        {/* Status Legend */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.72rem', color: '#64748b', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
            State Legend:
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.72rem', color: '#94a3b8' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10b981', boxShadow: '0 0 6px #10b981' }} />
            <span>Completed</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.72rem', color: '#94a3b8' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#00f0ff', boxShadow: '0 0 6px #00f0ff' }} />
            <span>Active / In-Flight</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.72rem', color: '#94a3b8' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#64748b' }} />
            <span>Queued</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.72rem', color: '#94a3b8' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f59e0b' }} />
            <span>Warning / Anomaly</span>
          </div>
        </div>

        {/* Total Pipeline Latency */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
          <span style={{ color: '#64748b' }}>End-to-End Latency:</span>
          <span style={{ color: '#38bdf8', fontWeight: 700 }}>
            {context?.total_duration_us ? `${context.total_duration_us} µs (${(context.total_duration_us / 1000).toFixed(2)} ms)` : 'Idle'}
          </span>
        </div>

      </div>

    </div>
  );
};
