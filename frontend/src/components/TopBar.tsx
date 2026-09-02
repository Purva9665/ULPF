import React from 'react';
import type { EngineStats } from '../types';
import { Terminal, FileCode, Clock } from 'lucide-react';

interface TopBarProps {
  activeTab: string;
  onSelectTab: (tab: string) => void;
  stats: EngineStats | null;
  isConnected?: boolean;
  onOpenTestBench: () => void;
  onOpenHistory?: () => void;
  onOpenExports: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  onSelectTab,
  stats,
  isConnected = false,
  onOpenTestBench,
  onOpenHistory,
  onOpenExports,
}) => {
  const isStreaming = stats?.is_streaming || false;
  const eps = stats?.current_eps || 0;
  const dqi = stats?.storage.avg_data_quality_score || 98.6;
  const totalProcessed = stats?.storage.total_events || stats?.total_processed || 0;
  const totalAnomalies = stats?.storage.total_anomalies || 0;

  const NAV_VIEWS = [
    { id: 'overview', label: 'Dashboard' },
    { id: 'analytics', label: 'Analytics' },
    { id: 'explorer', label: 'Log Explorer' },
    { id: 'journey', label: 'Event Journey' },
  ];

  return (
    <header
      style={{
        background: 'var(--panel)',
        borderBottom: '1px solid var(--hairline)',
        padding: '8px 20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px',
        position: 'sticky',
        top: 0,
        zIndex: 30,
        minHeight: '46px',
      }}
    >
      {/* Left: Telemetry Readout Strip */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
        
        {/* Status Indicator Dot */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span 
            style={{ 
              width: '7px', 
              height: '7px', 
              borderRadius: '50%', 
              backgroundColor: isConnected ? 'var(--confirm-moss)' : 'var(--alert-coral)',
              display: 'inline-block',
            }} 
          />
          <span className="readout" style={{ fontSize: '0.74rem', fontWeight: 600, color: isConnected ? 'var(--text-high)' : 'var(--alert-coral)' }}>
            {isConnected ? (isStreaming ? 'STREAMING' : 'ONLINE') : 'OFFLINE'}
          </span>
        </div>

        <div style={{ height: '14px', width: '1px', background: 'var(--hairline)' }} />

        {/* Telemetry Metrics */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', fontSize: '0.74rem' }}>
          <span className="readout" style={{ color: 'var(--text-mid)' }}>
            RATE <strong style={{ color: 'var(--phosphor-amber)' }}>{eps.toFixed(1)}</strong> EPS
          </span>

          <span className="readout" style={{ color: 'var(--text-mid)' }}>
            AVG DQI <strong style={{ color: 'var(--confirm-moss)' }}>{dqi.toFixed(1)}%</strong>
          </span>

          <span className="readout" style={{ color: 'var(--text-mid)' }}>
            PROCESSED <strong style={{ color: 'var(--text-high)' }}>{totalProcessed.toLocaleString()}</strong>
          </span>

          {totalAnomalies > 0 && (
            <span className="readout" style={{ color: 'var(--alert-coral)' }}>
              ANOMALIES <strong>{totalAnomalies}</strong>
            </span>
          )}
        </div>

      </div>

      {/* Center: Monitoring Surface Quick Switch */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '2px', background: 'var(--panel-sunken)', padding: '2px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--hairline)' }}>
        {NAV_VIEWS.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onSelectTab(tab.id)}
              style={{
                background: isActive ? 'var(--panel)' : 'transparent',
                color: isActive ? 'var(--phosphor-amber)' : 'var(--text-mid)',
                border: isActive ? '1px solid var(--hairline-bright)' : '1px solid transparent',
                borderRadius: 'var(--radius-sm)',
                padding: '4px 10px',
                fontSize: '0.74rem',
                fontFamily: 'var(--font-chrome)',
                fontWeight: isActive ? 600 : 500,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Right: Quick Action Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        
        <button 
          className="btn-instrument" 
          onClick={onOpenTestBench}
          title="Custom Ingestion Test Bench"
        >
          <Terminal size={12} color="var(--phosphor-amber)" />
          <span>Test Bench</span>
        </button>

        {onOpenHistory && (
          <button 
            className="btn-instrument" 
            onClick={onOpenHistory}
            title="Event Journal History"
          >
            <Clock size={12} />
            <span>Journal</span>
          </button>
        )}

        <button 
          className="btn-instrument" 
          onClick={onOpenExports}
          title="SIEM Exporters Modal"
        >
          <FileCode size={12} />
          <span>Export</span>
        </button>

      </div>
    </header>
  );
};
