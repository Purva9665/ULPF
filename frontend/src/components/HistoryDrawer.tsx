import React, { useEffect, useState } from 'react';
import { Database, X, RefreshCw, Eye } from 'lucide-react';
import { fetchStoredEvents, fetchEventDetail } from '../api';

interface HistoryDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectEvent: (eventDetails: any) => void;
}

export const HistoryDrawer: React.FC<HistoryDrawerProps> = ({
  isOpen,
  onClose,
  onSelectEvent,
}) => {
  const [events, setEvents] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const loadEvents = async () => {
    setIsLoading(true);
    try {
      const data = await fetchStoredEvents(50, 0);
      setEvents(data);
    } catch (e) {
      console.error('Failed to load events', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadEvents();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleRowClick = async (eventId: string) => {
    try {
      const detail = await fetchEventDetail(eventId);
      onSelectEvent(detail);
      onClose();
    } catch (e) {
      console.error('Failed to load event detail', e);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div 
        className="glass-panel"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '960px',
          maxHeight: '85vh',
          display: 'flex',
          flexDirection: 'column',
          padding: '24px',
          borderRadius: '12px',
          boxShadow: '0 0 40px rgba(0, 0, 0, 0.8)',
          border: '1px solid rgba(255, 255, 255, 0.15)',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Database size={20} color="#00f0ff" />
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                SQLite WAL Event Journal
              </h3>
              <p style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                Indexed Transactional Log Records in Local SQLite Database
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button 
              className="btn-cyber btn-cyber-secondary" 
              onClick={loadEvents} 
              disabled={isLoading}
              style={{ fontSize: '0.75rem', padding: '4px 10px' }}
            >
              <RefreshCw size={13} className={isLoading ? 'anim-pulse-cyan' : ''} />
              <span>Refresh</span>
            </button>
            <button 
              onClick={onClose}
              style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '4px' }}
            >
              <X size={20} />
            </button>
          </div>
        </div>

        {/* Table Container */}
        <div style={{ overflowY: 'auto', flex: 1 }}>
          {events.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
              {isLoading ? 'Loading stored events from SQLite...' : 'No events stored yet. Run events through the pipeline to populate storage.'}
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
              <thead>
                <tr style={{ background: 'rgba(15, 23, 42, 0.9)', color: '#64748b', textAlign: 'left', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                  <th style={{ padding: '8px 12px' }}>EVENT ID</th>
                  <th style={{ padding: '8px 12px' }}>VENDOR / PRODUCT</th>
                  <th style={{ padding: '8px 12px' }}>ACTION</th>
                  <th style={{ padding: '8px 12px' }}>SOURCE ➔ DESTINATION</th>
                  <th style={{ padding: '8px 12px' }}>ANOMALY SCORE</th>
                  <th style={{ padding: '8px 12px' }}>DQI</th>
                  <th style={{ padding: '8px 12px' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr 
                    key={ev.event_id}
                    style={{ 
                      borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                      transition: 'background 0.15s ease',
                      cursor: 'pointer',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(0, 240, 255, 0.06)')}
                    onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    onClick={() => handleRowClick(ev.event_id)}
                  >
                    <td style={{ padding: '10px 12px', color: '#00f0ff', fontWeight: 600 }}>
                      {ev.event_id.slice(0, 8)}...
                    </td>
                    <td style={{ padding: '10px 12px', color: '#f8fafc' }}>
                      {ev.vendor} • <span style={{ color: '#94a3b8' }}>{ev.product}</span>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <span className={`badge ${ev.action === 'ALLOW' ? 'badge-green' : 'badge-red'}`} style={{ fontSize: '0.65rem' }}>
                        {ev.action}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px', color: '#cbd5e1' }}>
                      {ev.src_ip || '-'}:{ev.src_port || '-'} ➔ {ev.dst_ip || '-'}:{ev.dst_port || '-'}
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <span className={`badge ${ev.anomaly_score >= 0.6 ? 'badge-red' : 'badge-green'}`} style={{ fontSize: '0.65rem' }}>
                        {ev.anomaly_score ? ev.anomaly_score.toFixed(2) : '0.00'}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px', color: '#10b981', fontWeight: 700 }}>
                      {ev.data_quality_score}%
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <button 
                        className="btn-cyber btn-cyber-secondary"
                        style={{ fontSize: '0.7rem', padding: '3px 8px' }}
                      >
                        <Eye size={12} />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

      </div>
    </div>
  );
};
