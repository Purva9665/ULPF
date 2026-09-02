import React, { useEffect, useState } from 'react';
import { X, RefreshCw, Eye } from 'lucide-react';
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
    <div className="modal-overlay" onClick={onClose}>
      <div 
        className="panel-machined"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '900px',
          maxHeight: '85vh',
          display: 'flex',
          flexDirection: 'column',
          padding: '20px',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
          <div>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
              EVENT JOURNAL HISTORY
            </h3>
            <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)', marginTop: '2px' }}>
              SQLite WAL Indexed Telemetry Records
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button 
              onClick={loadEvents} 
              disabled={isLoading}
              className="btn-instrument"
            >
              <RefreshCw size={11} className={isLoading ? 'anim-pulse-cyan' : ''} />
              <span>Refresh</span>
            </button>
            <button 
              onClick={onClose} 
              className="btn-instrument"
              style={{ padding: '3px 6px' }}
            >
              <X size={12} />
            </button>
          </div>
        </div>

        {/* Content Table */}
        <div style={{ flex: 1, overflowY: 'auto', maxHeight: '500px' }}>
          {isLoading ? (
            <div className="readout" style={{ padding: '30px', textAlign: 'center', color: 'var(--phosphor-amber)', fontSize: '0.76rem' }}>
              Reading SQLite WAL events...
            </div>
          ) : events.length === 0 ? (
            <div className="readout" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-low)', fontSize: '0.76rem' }}>
              No events found in SQLite WAL storage.
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontFamily: 'var(--font-readout)', fontSize: '0.72rem' }}>
              <thead>
                <tr style={{ background: 'var(--panel-sunken)', borderBottom: '1px solid var(--hairline)', color: 'var(--text-low)', textTransform: 'uppercase', fontSize: '0.64rem' }}>
                  <th style={{ padding: '6px 10px' }}>Event UUID</th>
                  <th style={{ padding: '6px 10px' }}>Timestamp</th>
                  <th style={{ padding: '6px 10px' }}>Vendor</th>
                  <th style={{ padding: '6px 10px' }}>Source IP</th>
                  <th style={{ padding: '6px 10px' }}>Action</th>
                  <th style={{ padding: '6px 10px' }}>DQI</th>
                  <th style={{ padding: '6px 10px' }}>Anomaly</th>
                  <th style={{ padding: '6px 10px', textAlign: 'center' }}>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev, idx) => {
                  const isAnom = ev.is_anomalous === 1 || (ev.anomaly_score && ev.anomaly_score >= 0.60);
                  const actColor = ev.action === 'ALLOW' ? 'var(--confirm-moss)' : ev.action === 'DENY' || ev.action === 'DROP' ? 'var(--alert-coral)' : 'var(--phosphor-amber)';

                  return (
                    <tr
                      key={ev.event_id || idx}
                      onClick={() => handleRowClick(ev.event_id)}
                      style={{
                        borderBottom: '1px solid var(--hairline)',
                        background: idx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.01)',
                        cursor: 'pointer',
                      }}
                    >
                      <td style={{ padding: '6px 10px', color: 'var(--phosphor-amber)', fontWeight: 600 }}>
                        {ev.event_id ? ev.event_id.slice(0, 8) : 'N/A'}
                      </td>
                      <td style={{ padding: '6px 10px', color: 'var(--text-mid)' }}>
                        {ev.timestamp ? ev.timestamp.slice(11, 19) : ev.ingested_at ? ev.ingested_at.slice(11, 19) : '00:00:00'}
                      </td>
                      <td style={{ padding: '6px 10px', color: 'var(--text-high)' }}>
                        {ev.vendor || 'Generic'}
                      </td>
                      <td style={{ padding: '6px 10px', color: 'var(--text-mid)' }}>
                        {ev.src_ip || '—'}
                      </td>
                      <td style={{ padding: '6px 10px' }}>
                        <span style={{ color: actColor, fontWeight: 700 }}>
                          {ev.action || 'UNKNOWN'}
                        </span>
                      </td>
                      <td style={{ padding: '6px 10px', color: 'var(--confirm-moss)' }}>
                        {ev.data_quality_score ?? 100}%
                      </td>
                      <td style={{ padding: '6px 10px' }}>
                        <span className={`badge-inst ${isAnom ? 'badge-coral' : 'badge-moss'}`}>
                          {ev.anomaly_score !== undefined ? Number(ev.anomaly_score).toFixed(2) : '0.00'}
                        </span>
                      </td>
                      <td style={{ padding: '6px 10px', textAlign: 'center' }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleRowClick(ev.event_id);
                          }}
                          className="btn-instrument"
                          style={{ padding: '2px 5px', fontSize: '0.62rem' }}
                        >
                          <Eye size={10} />
                          <span>Load</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};
