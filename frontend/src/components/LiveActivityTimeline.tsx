import React from 'react';
import type { TimelineItem } from '../types';
import { 
  Activity, 
  ArrowRight, 
  Trash2,
  CheckCircle2, 
  Cpu, 
  Database, 
  BrainCircuit, 
  FileInput, 
  GitMerge, 
} from 'lucide-react';

interface LiveActivityTimelineProps {
  items: TimelineItem[];
  onSelectItem?: (item: TimelineItem) => void;
  onClear?: () => void;
  onOpenHistory: () => void;
}

export const LiveActivityTimeline: React.FC<LiveActivityTimelineProps> = ({
  items,
  onSelectItem,
  onClear,
  onOpenHistory,
}) => {
  const getStageColor = (stage: string) => {
    switch (stage) {
      case 'INGEST': return '#00f0ff';
      case 'PARSE': return '#c084fc';
      case 'NORMALIZE': return '#38bdf8';
      case 'VALIDATE': return '#10b981';
      case 'STORE': return '#fbbf24';
      case 'ML': return '#f43f5e';
      case 'STANDARDIZED': return '#818cf8';
      default: return '#94a3b8';
    }
  };

  const getStageIcon = (stage: string) => {
    switch (stage) {
      case 'INGEST': return FileInput;
      case 'PARSE': return Cpu;
      case 'NORMALIZE': return GitMerge;
      case 'VALIDATE': return CheckCircle2;
      case 'STORE': return Database;
      case 'ML': return BrainCircuit;
      default: return Activity;
    }
  };

  return (
    <div 
      className="glass-panel" 
      style={{ 
        padding: '20px', 
        display: 'flex', 
        flexDirection: 'column', 
        height: '100%',
        maxHeight: '480px',
      }}
    >
      {/* Header */}
      <div 
        style={{ 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'space-between', 
          marginBottom: '16px', 
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)', 
          paddingBottom: '10px' 
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#00f0ff', boxShadow: '0 0 8px #00f0ff' }} />
          <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
            Live Activity Timeline
          </h3>
          <span className="badge badge-cyan" style={{ fontSize: '0.62rem', padding: '1px 6px' }}>
            {items.length} EVENTS
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          {onClear && items.length > 0 && (
            <button
              onClick={onClear}
              style={{ background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer', padding: '4px' }}
              title="Clear Timeline"
            >
              <Trash2 size={13} />
            </button>
          )}
          <button
            onClick={onOpenHistory}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              background: 'transparent',
              border: 'none',
              color: '#38bdf8',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.72rem',
              fontWeight: 600,
              cursor: 'pointer',
              padding: '2px 6px',
            }}
          >
            <span>View All</span>
            <ArrowRight size={12} />
          </button>
        </div>
      </div>

      {/* Timeline Scroll Area */}
      <div style={{ flex: 1, overflowY: 'auto', paddingRight: '4px' }}>
        {items.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 10px', color: '#64748b', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
            <Activity size={24} color="#334155" style={{ margin: '0 auto 8px auto' }} />
            <div>No events recorded yet.</div>
            <div style={{ fontSize: '0.7rem', marginTop: '4px' }}>Start live stream to view transitions.</div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {items.map((item) => {
              const color = getStageColor(item.stage);
              const Icon = getStageIcon(item.stage);

              return (
                <div
                  key={item.id}
                  onClick={() => onSelectItem && onSelectItem(item)}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                    padding: '8px 10px',
                    borderRadius: '8px',
                    background: 'rgba(15, 23, 42, 0.65)',
                    border: '1px solid rgba(255, 255, 255, 0.05)',
                    cursor: onSelectItem ? 'pointer' : 'default',
                    transition: 'all 0.15s ease',
                  }}
                  className="glass-panel-interactive"
                >
                  {/* Stage Icon Node */}
                  <div
                    style={{
                      width: '28px',
                      height: '28px',
                      borderRadius: '50%',
                      background: `${color}18`,
                      border: `1px solid ${color}60`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                      marginTop: '2px',
                    }}
                  >
                    <Icon size={14} color={color} />
                  </div>

                  {/* Text Details */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '6px' }}>
                      <span style={{ fontSize: '0.74rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: color }}>
                        {item.stage}
                      </span>
                      <span style={{ fontSize: '0.65rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                        {item.timestamp}
                      </span>
                    </div>

                    <div 
                      style={{ 
                        fontSize: '0.72rem', 
                        color: '#f1f5f9', 
                        fontWeight: 500,
                        marginTop: '2px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                      title={item.title}
                    >
                      {item.title}
                    </div>

                    {item.subtitle && (
                      <div 
                        style={{ 
                          fontSize: '0.66rem', 
                          color: '#94a3b8', 
                          fontFamily: 'var(--font-mono)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {item.subtitle}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

    </div>
  );
};
