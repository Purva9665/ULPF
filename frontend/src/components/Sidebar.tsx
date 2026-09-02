import React from 'react';
import { 
  Activity, 
  BarChart3, 
  Search, 
  Milestone,
  Terminal,
  Clock,
  FileCode, Play } from 'lucide-react';
import type { EngineStats } from '../types';

interface SidebarProps {
  activeTab: string;
  onSelectTab: (tab: string) => void;
  stats: EngineStats | null;
  isConnected: boolean;
  onOpenTestBench: () => void;
  onOpenHistory: () => void;
  onOpenExports: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  stats,
  isConnected: _isConnected,
  onOpenTestBench,
  onOpenHistory,
  onOpenExports,
}) => {
  const MONITORING_NAV = [
    { id: 'demo', label: 'Demo', icon: Play },
    { id: 'overview', label: 'Dashboard', icon: Activity },
    { id: 'analytics', label: 'Analytics', icon: BarChart3 },
    { id: 'explorer', label: 'Log Explorer', icon: Search, badge: stats?.storage?.total_events ? String(stats.storage.total_events) : undefined },
    { id: 'journey', label: 'Event Journey', icon: Milestone },
  ];

  const SIGNAL_CHAIN = [
    { id: 'ingestion', num: '01', name: 'Ingestion' },
    { id: 'parser', num: '02', name: 'Parser' },
    { id: 'normalization', num: '03', name: 'Normalization' },
    { id: 'validation', num: '04', name: 'Validation / DQI' },
    { id: 'storage', num: '05', name: 'Storage (WAL)' },
    { id: 'ml', num: '06', name: 'ML Anomaly' },
    { id: 'export', num: '07', name: 'SIEM Export' },
  ];

  return (
    <aside 
      style={{
        width: '230px',
        minWidth: '230px',
        background: 'var(--panel)',
        borderRight: '1px solid var(--hairline)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        padding: '16px 12px',
        height: '100vh',
        position: 'sticky',
        top: 0,
        overflowY: 'auto',
        zIndex: 40,
      }}
    >
      {/* Top Section */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
        
        {/* Brand Header */}
        <div style={{ padding: '0 4px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ 
              fontFamily: 'var(--font-chrome)', 
              fontSize: '1.05rem', 
              fontWeight: 700, 
              letterSpacing: '0.04em',
              color: 'var(--text-high)',
            }}>
              ULPF
            </span>
            <span className="badge-inst badge-hairline" style={{ fontSize: '0.62rem' }}>
              ENGINE v1.0
            </span>
          </div>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-low)', fontFamily: 'var(--font-readout)', marginTop: '2px' }}>
            Universal Log Pre-processing
          </div>
        </div>

        {/* 1. Monitoring Views */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <div style={{ fontSize: '0.62rem', color: 'var(--text-low)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', padding: '0 8px 6px 8px', fontFamily: 'var(--font-readout)' }}>
            SURFACES
          </div>
          {MONITORING_NAV.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                className={`patch-nav-item ${isActive ? 'active' : ''}`}
                onClick={() => onSelectTab(item.id)}
              >
                <Icon size={14} color={isActive ? 'var(--phosphor-amber)' : 'var(--text-mid)'} />
                <span style={{ flex: 1 }}>{item.label}</span>
                {item.badge && (
                  <span className="readout" style={{ fontSize: '0.66rem', color: isActive ? 'var(--phosphor-amber)' : 'var(--text-low)' }}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Hairline Divider between Monitoring and Patch Signal Chain */}
        <div style={{ height: '1px', background: 'var(--hairline)', margin: '2px 4px' }} />

        {/* 2. Signal Chain Jacks (01 to 07) */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <div style={{ fontSize: '0.62rem', color: 'var(--text-low)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', padding: '0 8px 6px 8px', fontFamily: 'var(--font-readout)' }}>
            SIGNAL CHAIN
          </div>
          {SIGNAL_CHAIN.map((stage) => {
            const isActive = activeTab === stage.id;
            return (
              <button
                key={stage.id}
                className={`patch-nav-item ${isActive ? 'active' : ''}`}
                onClick={() => onSelectTab(stage.id)}
              >
                <span 
                  className="readout" 
                  style={{ 
                    fontSize: '0.68rem', 
                    fontWeight: 700, 
                    color: isActive ? 'var(--phosphor-amber)' : 'var(--text-low)',
                    minWidth: '22px',
                  }}
                >
                  [{stage.num}]
                </span>
                <span style={{ flex: 1, fontSize: '0.8rem' }}>{stage.name}</span>
              </button>
            );
          })}
        </div>

      </div>

      {/* Bottom Instrument Panel Utilities */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', borderTop: '1px solid var(--hairline)', paddingTop: '12px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '4px' }}>
          <button 
            className="btn-instrument" 
            onClick={onOpenTestBench}
            style={{ padding: '4px 6px', fontSize: '0.66rem', justifyContent: 'center' }}
            title="Ingestion Test Bench"
          >
            <Terminal size={11} />
            <span>Bench</span>
          </button>
          
          <button 
            className="btn-instrument" 
            onClick={onOpenHistory}
            style={{ padding: '4px 6px', fontSize: '0.66rem', justifyContent: 'center' }}
            title="Event Journal History"
          >
            <Clock size={11} />
            <span>Log</span>
          </button>

          <button 
            className="btn-instrument" 
            onClick={onOpenExports}
            style={{ padding: '4px 6px', fontSize: '0.66rem', justifyContent: 'center' }}
            title="SIEM Exporters"
          >
            <FileCode size={11} />
            <span>Export</span>
          </button>
        </div>

        <div style={{ padding: '4px 6px', fontSize: '0.66rem', color: 'var(--text-low)', fontFamily: 'var(--font-readout)' }}>
          DB: SQLite WAL (local)
        </div>
      </div>

    </aside>
  );
};
