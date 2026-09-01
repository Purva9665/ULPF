import React from 'react';
import type { 
  StageEnum, 
  StageStatus, 
  PipelineContext, 
  StageExecutionMetrics 
} from '../types';
import { 
  FileInput, 
  Cpu, 
  GitMerge, 
  ShieldCheck, 
  Database, 
  BrainCircuit, 
  CheckCircle2,
  Clock,
  Fingerprint
} from 'lucide-react';

interface PipelineGraphProps {
  context: PipelineContext | null;
  selectedStage: StageEnum;
  onSelectStage: (stage: StageEnum) => void;
  activeTransitionStage?: StageEnum | null;
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
    name: 'INGEST',
    icon: FileInput,
    accentColor: '#00f0ff',
    glowClass: 'anim-pulse-cyan',
    badgeClass: 'badge-cyan',
    subtitle: 'Zero-Loss Raw Capture & SHA-256 Hash',
  },
  {
    id: 'PARSE',
    number: '02',
    name: 'PARSE',
    icon: Cpu,
    accentColor: '#a855f7',
    glowClass: 'anim-pulse-cyan',
    badgeClass: 'badge-purple',
    subtitle: 'Auto-Dialect AST Token Extraction',
  },
  {
    id: 'NORMALIZE',
    number: '03',
    name: 'NORMALIZE',
    icon: GitMerge,
    accentColor: '#38bdf8',
    glowClass: 'anim-pulse-cyan',
    badgeClass: 'badge-cyan',
    subtitle: 'Canonical Taxonomy Mapping',
  },
  {
    id: 'VALIDATE',
    number: '04',
    name: 'VALIDATE',
    icon: ShieldCheck,
    accentColor: '#10b981',
    glowClass: 'anim-pulse-green',
    badgeClass: 'badge-green',
    subtitle: 'Schema Rules & DQI Integrity Scoring',
  },
  {
    id: 'STORE',
    number: '05',
    name: 'STORE',
    icon: Database,
    accentColor: '#f59e0b',
    glowClass: 'anim-pulse-cyan',
    badgeClass: 'badge-amber',
    subtitle: 'SQLite WAL & Columnar Layout',
  },
  {
    id: 'ML',
    number: '06',
    name: 'ML ANALYSIS',
    icon: BrainCircuit,
    accentColor: '#ef4444',
    glowClass: 'anim-pulse-red',
    badgeClass: 'badge-red',
    subtitle: 'Local Isolation Forest & Entropy',
  },
  {
    id: 'STANDARDIZED',
    number: '07',
    name: 'STANDARDIZED',
    icon: CheckCircle2,
    accentColor: '#6366f1',
    glowClass: 'anim-pulse-green',
    badgeClass: 'badge-green',
    subtitle: 'SIEM & Data-Lake Ready Output',
  },
];

export const PipelineGraph: React.FC<PipelineGraphProps> = ({
  context,
  selectedStage,
  onSelectStage,
  activeTransitionStage,
}) => {
  // Helper to find stage execution metric
  const getStageMetric = (stageId: StageEnum): StageExecutionMetrics | undefined => {
    return context?.stage_metrics?.find((m) => m.stage === stageId);
  };

  // Helper to determine node status
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

  // Get intermediate summary pill for stage
  const getStageSummaryPill = (stageId: StageEnum) => {
    if (!context) return null;

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
      return `DQI ${context.validated_event.data_quality_score}%`;
    }
    if (stageId === 'STORE' && context.stored_event) {
      return `-${context.stored_event.storage.compression_ratio}% Size`;
    }
    if (stageId === 'ML' && context.ml_event) {
      return `Score: ${context.ml_event.ml.anomaly_score} (${context.ml_event.ml.risk_level})`;
    }
    if (stageId === 'STANDARDIZED' && context.final_event) {
      return `ULPF v1.0 • Ready`;
    }
    return null;
  };

  return (
    <div className="glass-panel" style={{ margin: '16px 20px', padding: '20px 24px' }}>
      
      {/* Section Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#00f0ff', boxShadow: '0 0 10px #00f0ff' }} />
          <h2 style={{ fontSize: '0.9rem', fontWeight: 700, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#f8fafc' }}>
            Live Engine State Machine Telemetry
          </h2>
        </div>

        {/* Global Pipeline Timing */}
        {context && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#94a3b8' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <Fingerprint size={14} color="#00f0ff" />
              <span>Event ID: <strong style={{ color: '#e2e8f0' }}>{context.event_id.slice(0, 8)}...</strong></span>
            </span>
            <span style={{ color: '#475569' }}>|</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <Clock size={14} color="#10b981" />
              <span>Total Latency: <strong style={{ color: '#10b981' }}>{context.total_duration_us || 0} µs</strong></span>
            </span>
          </div>
        )}
      </div>

      {/* 7-Stage Node Grid */}
      <div 
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: '12px',
          position: 'relative',
        }}
      >
        {STAGES.map((stage) => {
          const { status, isCurrent, isCompleted } = getNodeStatus(stage.id);
          const metric = getStageMetric(stage.id);
          const isSelected = selectedStage === stage.id;
          const summaryPill = getStageSummaryPill(stage.id);
          const Icon = stage.icon;

          // Compute border and background based on state
          let borderColor = 'rgba(255, 255, 255, 0.08)';
          let bgColor = 'rgba(15, 23, 42, 0.6)';
          let glowBox = 'none';

          if (isSelected) {
            borderColor = stage.accentColor;
            glowBox = `0 0 20px ${stage.accentColor}40`;
            bgColor = 'rgba(15, 23, 42, 0.95)';
          } else if (isCurrent) {
            borderColor = stage.accentColor;
            glowBox = `0 0 15px ${stage.accentColor}60`;
          } else if (isCompleted) {
            borderColor = 'rgba(16, 185, 129, 0.4)';
          }

          return (
            <div
              key={stage.id}
              onClick={() => onSelectStage(stage.id)}
              className="glass-panel-interactive"
              style={{
                position: 'relative',
                padding: '14px',
                borderRadius: '10px',
                backgroundColor: bgColor,
                border: `1.5px solid ${borderColor}`,
                boxShadow: glowBox,
                cursor: 'pointer',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                minHeight: '135px',
                transition: 'all 0.2s ease',
              }}
            >
              {/* Top Row: Stage Number & Status Pill */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <span style={{ 
                  fontFamily: 'var(--font-mono)', 
                  fontSize: '0.7rem', 
                  fontWeight: 700, 
                  color: isSelected ? stage.accentColor : '#64748b' 
                }}>
                  {stage.number}
                </span>

                {/* Status Indicator */}
                {status === 'RUNNING' && (
                  <span className="badge badge-cyan anim-pulse-cyan" style={{ fontSize: '0.62rem', padding: '2px 6px' }}>
                    RUNNING
                  </span>
                )}
                {status === 'COMPLETED' && (
                  <span className="badge badge-green" style={{ fontSize: '0.62rem', padding: '2px 6px' }}>
                    DONE
                  </span>
                )}
                {status === 'WARNING' && (
                  <span className="badge badge-amber" style={{ fontSize: '0.62rem', padding: '2px 6px' }}>
                    WARN
                  </span>
                )}
                {status === 'ERROR' && (
                  <span className="badge badge-red anim-pulse-red" style={{ fontSize: '0.62rem', padding: '2px 6px' }}>
                    ERROR
                  </span>
                )}
                {status === 'PENDING' && (
                  <span className="badge badge-gray" style={{ fontSize: '0.62rem', padding: '2px 6px' }}>
                    WAIT
                  </span>
                )}
              </div>

              {/* Stage Icon & Name */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                <div 
                  style={{
                    width: '28px',
                    height: '28px',
                    borderRadius: '6px',
                    backgroundColor: `${stage.accentColor}20`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    border: `1px solid ${stage.accentColor}40`,
                  }}
                >
                  <Icon size={16} color={stage.accentColor} />
                </div>
                <div>
                  <div style={{ 
                    fontFamily: 'var(--font-mono)', 
                    fontWeight: 700, 
                    fontSize: '0.82rem', 
                    color: isSelected ? '#f8fafc' : '#cbd5e1' 
                  }}>
                    {stage.name}
                  </div>
                </div>
              </div>

              {/* Latency / Summary info */}
              <div style={{ marginTop: 'auto' }}>
                {metric && (
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.68rem', fontFamily: 'var(--font-mono)', color: '#94a3b8', marginTop: '4px' }}>
                    <span>Latency:</span>
                    <span style={{ color: '#38bdf8', fontWeight: 600 }}>{metric.duration_us} µs</span>
                  </div>
                )}
                {summaryPill && (
                  <div 
                    style={{
                      fontSize: '0.65rem',
                      fontFamily: 'var(--font-mono)',
                      color: stage.accentColor,
                      background: `${stage.accentColor}12`,
                      padding: '3px 6px',
                      borderRadius: '4px',
                      marginTop: '6px',
                      textOverflow: 'ellipsis',
                      overflow: 'hidden',
                      whiteSpace: 'nowrap',
                    }}
                    title={summaryPill}
                  >
                    {summaryPill}
                  </div>
                )}
              </div>

              {/* Selection pointer caret */}
              {isSelected && (
                <div 
                  style={{
                    position: 'absolute',
                    bottom: '-8px',
                    left: '50%',
                    transform: 'translateX(-50%)',
                    width: 0,
                    height: 0,
                    borderLeft: '7px solid transparent',
                    borderRight: '7px solid transparent',
                    borderTop: `7px solid ${stage.accentColor}`,
                  }}
                />
              )}
            </div>
          );
        })}
      </div>

    </div>
  );
};
