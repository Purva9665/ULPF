import React from 'react';
import { 
  Activity, 
  Terminal, 
  Database, 
  FileCode, 
  Radio,
  ShieldCheck,
} from 'lucide-react';
import type { EngineStats } from '../types';

interface HeaderProps {
  stats: EngineStats | null;
  isConnected: boolean;
  activeTab: string;
  onSelectTab: (tab: string) => void;
  onOpenTestBench: () => void;
  onOpenHistory: () => void;
  onOpenExports: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  stats,
  isConnected,
  activeTab,
  onSelectTab,
  onOpenTestBench,
  onOpenHistory,
  onOpenExports,
}) => {
  const NAV_TABS = [
    { id: 'overview', label: 'Overview' },
    { id: 'ingestion', label: 'Ingestion' },
    { id: 'parser', label: 'Parser' },
    { id: 'normalization', label: 'Normalization' },
    { id: 'validation', label: 'Validation' },
    { id: 'storage', label: 'Storage' },
    { id: 'ml', label: 'ML Anomaly' },
    { id: 'export', label: 'Export' },
    { id: 'analytics', label: 'Analytics' },
    { id: 'explorer', label: 'Log Explorer' },
    { id: 'journey', label: 'Event Journey' },
  ];

  return (
    <header 
      className="glass-panel" 
      style={{ 
        margin: '16px 20px 0 20px', 
        padding: '10px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px',
      }}
    >
      {/* Brand Identity */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div 
          style={{
            width: '38px',
            height: '38px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, #00f0ff 0%, #3b82f6 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 20px rgba(0, 240, 255, 0.4)',
          }}
        >
          <Activity size={22} color="#06090f" strokeWidth={2.6} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ 
              fontFamily: 'var(--font-display)', 
              fontSize: '1.2rem', 
              fontWeight: 800, 
              letterSpacing: '0.08em',
              background: 'linear-gradient(90deg, #00f0ff, #ffffff, #a855f7)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}>
              ULPF
            </span>
            <span className="badge badge-cyan" style={{ fontSize: '0.65rem', padding: '2px 6px' }}>
              MAIN CONTROL ROOM
            </span>
          </div>
          <p style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            Universal Log Pre-processing Framework
          </p>
        </div>
      </div>

      {/* Navigation Tabs (Enterprise Header Bar) */}
      <nav style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
        {NAV_TABS.map((tab) => (
          <button
            key={tab.id}
            className={`nav-tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => onSelectTab(tab.id)}
            title={tab.id === 'overview' ? 'Main Engine Dashboard' : `${tab.label} (Sub-Dashboard)`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* System Status & Actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        
        {/* Offline / Air-Gapped & Connection Status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {/* OFFLINE MODE INDICATOR */}
          <span 
            className="badge badge-emerald" 
            style={{ 
              fontSize: '0.68rem', 
              padding: '4px 8px', 
              display: 'flex', 
              alignItems: 'center', 
              gap: '5px',
              border: '1px solid rgba(16, 185, 129, 0.4)',
              background: 'rgba(16, 185, 129, 0.12)',
            }}
            title="Zero Cloud Dependencies — 100% Local Scikit-Learn ML & SQLite WAL Storage"
          >
            <ShieldCheck size={12} color="#10b981" />
            <span style={{ fontWeight: 600, letterSpacing: '0.04em' }}>OFFLINE AIR-GAP</span>
          </span>

          <span 
            className={`badge ${isConnected ? 'badge-green' : 'badge-red'}`} 
            style={{ fontSize: '0.68rem', padding: '4px 8px' }}
          >
            <span style={{ 
              width: '6px', 
              height: '6px', 
              borderRadius: '50%', 
              backgroundColor: isConnected ? '#10b981' : '#ef4444',
              boxShadow: isConnected ? '0 0 8px #10b981' : 'none'
            }} />
            {isConnected ? 'LIVE ENGINE' : 'ENGINE OFFLINE'}
          </span>

          <span 
            className="badge badge-blue" 
            style={{ fontSize: '0.68rem', padding: '4px 8px' }}
          >
            <Radio size={11} className={stats?.is_streaming ? 'anim-pulse-cyan' : ''} />
            {stats?.is_streaming ? `${stats.current_eps} EPS` : 'IDLE / STEP'}
          </span>
        </div>

        {/* Action Tools */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button 
            className="btn-cyber btn-cyber-secondary" 
            onClick={onOpenTestBench}
            style={{ padding: '6px 12px', fontSize: '0.76rem' }}
            title="Custom Ingestion Test Bench"
          >
            <Terminal size={14} />
            <span>Test Bench</span>
          </button>
          
          <button 
            className="btn-cyber btn-cyber-secondary" 
            onClick={onOpenHistory}
            style={{ padding: '6px 12px', fontSize: '0.76rem' }}
            title="SQLite WAL Event Journal"
          >
            <Database size={14} />
            <span>Journal</span>
          </button>

          <button 
            className="btn-cyber btn-cyber-secondary" 
            onClick={onOpenExports}
            style={{ padding: '6px 12px', fontSize: '0.76rem' }}
            title="SIEM / Data Lake Exporter"
          >
            <FileCode size={14} />
            <span>SIEM Export</span>
          </button>
        </div>

        {/* User / Operator Avatar */}
        <div 
          style={{
            width: '32px',
            height: '32px',
            borderRadius: '50%',
            background: 'linear-gradient(135deg, #1e293b, #334155)',
            border: '1px solid rgba(255, 255, 255, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '0.75rem',
            fontWeight: 700,
            color: '#38bdf8',
            fontFamily: 'var(--font-mono)',
          }}
          title="Security Operations Engine Operator"
        >
          UL
        </div>

      </div>

    </header>
  );
};
