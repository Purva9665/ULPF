import React from 'react';
import { 
  Server, 
  GitBranch, 
  Database, 
  BrainCircuit, 
  Wifi, 
  ShieldCheck, 
} from 'lucide-react';
import type { EngineStats } from '../types';

interface SystemHealthCardProps {
  stats: EngineStats | null;
  isConnected: boolean;
}

export const SystemHealthCard: React.FC<SystemHealthCardProps> = ({
  stats,
  isConnected,
}) => {
  const HEALTH_ITEMS = [
    {
      name: 'Engine Core',
      component: 'FastAPI / Uvicorn',
      status: 'OPERATIONAL',
      icon: Server,
      accent: '#00f0ff',
      details: `${stats?.parsers_count || 9} Parsers Registered`,
    },
    {
      name: 'Pipeline State',
      component: '7 Stages Zero-Loss',
      status: 'ACTIVE',
      icon: GitBranch,
      accent: '#10b981',
      details: `${stats?.buffered_contexts_count || 0} Buffered Contexts`,
    },
    {
      name: 'SQLite WAL Storage',
      component: 'Dual WAL & Columnar Buffer',
      status: 'LOCAL PERSISTENT',
      icon: Database,
      accent: '#fbbf24',
      details: `${stats?.storage.total_events || 0} Stored Records (/data volume)`,
    },
    {
      name: 'ML Anomaly Engine',
      component: 'Isolation Forest & Entropy',
      status: 'TRAINED & READY',
      icon: BrainCircuit,
      accent: '#f43f5e',
      details: `${stats?.storage.total_anomalies || 0} Anomalies Detected`,
    },
    {
      name: 'Live Telemetry',
      component: 'WebSocket Duplex',
      status: isConnected ? 'CONNECTED' : 'DISCONNECTED',
      icon: Wifi,
      accent: isConnected ? '#38bdf8' : '#ef4444',
      details: stats?.is_streaming ? `Stream Active (${stats.current_eps} EPS)` : 'Standby / Step Mode',
    },
  ];

  return (
    <div className="glass-panel" style={{ padding: '20px' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldCheck size={18} color="#10b981" />
          <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
            System Health
          </h3>
        </div>
        <span className="badge badge-green" style={{ fontSize: '0.62rem' }}>
          100% OPERATIONAL
        </span>
      </div>

      {/* Grid of Health Components */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {HEALTH_ITEMS.map((item, idx) => {
          const Icon = item.icon;
          return (
            <div
              key={idx}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '8px 12px',
                borderRadius: '8px',
                background: 'rgba(15, 23, 42, 0.65)',
                border: '1px solid rgba(255, 255, 255, 0.05)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div
                  style={{
                    width: '30px',
                    height: '30px',
                    borderRadius: '6px',
                    background: `${item.accent}15`,
                    border: `1px solid ${item.accent}40`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Icon size={15} color={item.accent} />
                </div>
                <div>
                  <div style={{ fontSize: '0.78rem', fontWeight: 600, color: '#f8fafc', fontFamily: 'var(--font-main)' }}>
                    {item.name}
                  </div>
                  <div style={{ fontSize: '0.66rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                    {item.component} • {item.details}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                <span 
                  style={{ 
                    width: '6px', 
                    height: '6px', 
                    borderRadius: '50%', 
                    background: item.status === 'DISCONNECTED' ? '#ef4444' : '#10b981',
                    boxShadow: item.status === 'DISCONNECTED' ? 'none' : '0 0 6px #10b981',
                  }} 
                />
                <span style={{ fontSize: '0.68rem', fontWeight: 600, fontFamily: 'var(--font-mono)', color: item.status === 'DISCONNECTED' ? '#ef4444' : '#34d399' }}>
                  {item.status}
                </span>
              </div>
            </div>
          );
        })}
      </div>

    </div>
  );
};
