import React from 'react';
import { 
  Database, 
  ExternalLink, 
  Eye,
  Copy,
  Check,
} from 'lucide-react';

interface StoredEventSummary {
  id?: number;
  event_id: string;
  timestamp: string;
  vendor: string;
  product: string;
  action: string;
  severity: string;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  data_quality_score: number;
  anomaly_score?: number;
  is_anomalous?: boolean | number;
  stored_at?: string;
  duration_us?: number;
}

interface RecentEventsTableProps {
  events: StoredEventSummary[];
  onSelectEvent: (eventId: string) => void;
  onOpenHistory: () => void;
}

export const RecentEventsTable: React.FC<RecentEventsTableProps> = ({
  events,
  onSelectEvent,
  onOpenHistory,
}) => {
  const [copiedId, setCopiedId] = React.useState<string | null>(null);

  const copyEventId = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const getActionBadge = (act: string) => {
    switch (act.toUpperCase()) {
      case 'ALLOW': return 'badge-green';
      case 'DENY':
      case 'DROP':
      case 'REJECT': return 'badge-red';
      case 'ALERT': return 'badge-amber';
      default: return 'badge-gray';
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '20px' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Database size={18} color="#00f0ff" />
          <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
            Recent Processed Events Journal
          </h3>
          <span className="badge badge-cyan" style={{ fontSize: '0.62rem' }}>
            SQLITE WAL PERSISTED
          </span>
        </div>

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
          }}
        >
          <span>Open Full Database Journal</span>
          <ExternalLink size={12} />
        </button>
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto' }}>
        {events.length === 0 ? (
          <div style={{ padding: '30px', textAlign: 'center', color: '#64748b', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
            No recent events recorded. Run logs through the live engine to populate journal records.
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: '0.74rem' }}>
            <thead>
              <tr style={{ background: 'rgba(15, 23, 42, 0.9)', color: '#64748b', textAlign: 'left', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
                <th style={{ padding: '8px 10px' }}>EVENT ID</th>
                <th style={{ padding: '8px 10px' }}>VENDOR / PRODUCT</th>
                <th style={{ padding: '8px 10px' }}>ACTION</th>
                <th style={{ padding: '8px 10px' }}>SOURCE ➔ DESTINATION</th>
                <th style={{ padding: '8px 10px' }}>DQI QUALITY</th>
                <th style={{ padding: '8px 10px' }}>ML ANOMALY</th>
                <th style={{ padding: '8px 10px' }}>TIMESTAMP</th>
                <th style={{ padding: '8px 10px', textAlign: 'right' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {events.slice(0, 10).map((ev) => {
                const isAnomalous = ev.is_anomalous === 1 || ev.is_anomalous === true || (ev.anomaly_score && ev.anomaly_score > 0.4);
                const score = ev.anomaly_score !== undefined ? Number(ev.anomaly_score).toFixed(2) : '0.08';

                return (
                  <tr
                    key={ev.event_id}
                    onClick={() => onSelectEvent(ev.event_id)}
                    style={{
                      borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                      cursor: 'pointer',
                      transition: 'background 0.15s ease',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(30, 41, 59, 0.5)')}
                    onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                  >
                    {/* Event ID with copy */}
                    <td style={{ padding: '8px 10px', color: '#f8fafc', fontWeight: 600 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span>{ev.event_id.slice(0, 10)}...</span>
                        <button
                          onClick={(e) => copyEventId(ev.event_id, e)}
                          style={{ background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer', padding: '2px' }}
                          title="Copy UUID"
                        >
                          {copiedId === ev.event_id ? <Check size={11} color="#10b981" /> : <Copy size={11} />}
                        </button>
                      </div>
                    </td>

                    {/* Vendor / Product */}
                    <td style={{ padding: '8px 10px', color: '#cbd5e1' }}>
                      <span className="badge badge-purple" style={{ fontSize: '0.62rem' }}>
                        {ev.vendor || 'Perimeter'} {ev.product ? `/ ${ev.product}` : ''}
                      </span>
                    </td>

                    {/* Action */}
                    <td style={{ padding: '8px 10px' }}>
                      <span className={`badge ${getActionBadge(ev.action)}`} style={{ fontSize: '0.62rem' }}>
                        {ev.action || 'UNKNOWN'}
                      </span>
                    </td>

                    {/* Endpoints */}
                    <td style={{ padding: '8px 10px', color: '#94a3b8' }}>
                      <span style={{ color: '#38bdf8' }}>{ev.src_ip || '0.0.0.0'}:{ev.src_port || '*'}</span>
                      <span style={{ margin: '0 4px', color: '#64748b' }}>➔</span>
                      <span style={{ color: '#c084fc' }}>{ev.dst_ip || '0.0.0.0'}:{ev.dst_port || '*'}</span>
                    </td>

                    {/* DQI */}
                    <td style={{ padding: '8px 10px' }}>
                      <span style={{ color: '#34d399', fontWeight: 700 }}>
                        {ev.data_quality_score || 100}%
                      </span>
                    </td>

                    {/* ML Anomaly */}
                    <td style={{ padding: '8px 10px' }}>
                      <span 
                        className={`badge ${isAnomalous ? 'badge-red' : 'badge-green'}`} 
                        style={{ fontSize: '0.62rem' }}
                      >
                        {score} {isAnomalous ? 'ANOMALY' : 'NORMAL'}
                      </span>
                    </td>

                    {/* Timestamp */}
                    <td style={{ padding: '8px 10px', color: '#64748b', fontSize: '0.68rem' }}>
                      {ev.timestamp ? ev.timestamp.slice(11, 19) : (ev.stored_at ? ev.stored_at.slice(11, 19) : '09:24:01')}
                    </td>

                    {/* Action */}
                    <td style={{ padding: '8px 10px', textAlign: 'right' }}>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectEvent(ev.event_id);
                        }}
                        className="btn-cyber btn-cyber-secondary"
                        style={{ padding: '3px 8px', fontSize: '0.68rem' }}
                      >
                        <Eye size={12} />
                        <span>Inspect</span>
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
  );
};
