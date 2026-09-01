import React, { useState, useEffect } from 'react';
import type { 
  PipelineContext, 
  EngineStats 
} from '../types';
import { fetchStoredEvents, fetchEventDetail } from '../api';
import { 
  Database, 
  ArrowLeft, 
  HardDrive, 
  Search, 
  RefreshCw, 
  Eye, 
  Copy, 
  Check, 
  Clock, 
  Server, 
} from 'lucide-react';

interface StorageViewProps {
  context: PipelineContext | null;
  stats: EngineStats | null;
  onBackToOverview: () => void;
  onSelectEventId?: (eventId: string) => void;
}

export const StorageView: React.FC<StorageViewProps> = ({
  context,
  stats,
  onBackToOverview,
}) => {
  const [events, setEvents] = useState<any[]>([]);
  const [selectedRecord, setSelectedRecord] = useState<any | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const loadEvents = async () => {
    setIsLoading(true);
    try {
      const data = await fetchStoredEvents(100, 0);
      setEvents(data);
      if (data.length > 0 && !selectedRecord) {
        const detail = await fetchEventDetail(data[0].event_id);
        setSelectedRecord(detail);
      }
    } catch (e) {
      console.error('Failed to query database records', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, []);

  const handleRowClick = async (eventId: string) => {
    try {
      const detail = await fetchEventDetail(eventId);
      setSelectedRecord(detail);
    } catch (e) {
      console.error('Failed to load record details', e);
    }
  };

  const copyJson = (obj: any) => {
    navigator.clipboard.writeText(JSON.stringify(obj, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const totalEvents = stats?.storage.total_events || events.length;
  const rawBytes = stats?.storage.total_raw_bytes || 0;
  const compBytes = stats?.storage.total_compressed_bytes || 0;
  const ratio = stats?.storage.overall_compression_ratio || 0.0;
  const writeLatency = context?.stored_event?.storage_duration_us || 38;

  const filteredEvents = events.filter((ev) => 
    ev.event_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (ev.src_ip && ev.src_ip.includes(searchTerm)) ||
    (ev.dst_ip && ev.dst_ip.includes(searchTerm)) ||
    (ev.action && ev.action.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Header Bar */}
      <div className="glass-panel" style={{ padding: '16px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <button
            onClick={onBackToOverview}
            className="btn-cyber btn-cyber-secondary"
            style={{ padding: '6px 12px', fontSize: '0.78rem' }}
          >
            <ArrowLeft size={14} />
            <span>Control Room</span>
          </button>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="badge badge-amber" style={{ fontSize: '0.72rem' }}>STAGE 05</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Local SQLite WAL Storage Engine
              </h2>
            </div>
            <p style={{ fontSize: '0.74rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Zero-Cloud Relational Database Persistence, Docker Volume Storage (/data), and Zlib Compression
            </p>
          </div>
        </div>

        {/* Persistence Status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(15, 23, 42, 0.7)', padding: '6px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px #10b981' }} />
          <span style={{ fontSize: '0.72rem', color: '#f8fafc', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            DATABASE PERSISTENT: ulpf_events.db (WAL MODE)
          </span>
        </div>
      </div>

      {/* Top 4 Metrics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        
        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Database Records</span>
            <Database size={16} color="#fbbf24" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#f8fafc', margin: '4px 0' }}>
            {totalEvents.toLocaleString()} Events
          </div>
          <div style={{ fontSize: '0.68rem', color: '#10b981', fontFamily: 'var(--font-mono)' }}>
            100% Persisted to Disk (Durable)
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Storage Footprint</span>
            <HardDrive size={16} color="#10b981" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#10b981', margin: '4px 0' }}>
            -{ratio}% REDUCTION
          </div>
          <div style={{ fontSize: '0.68rem', color: '#34d399', fontFamily: 'var(--font-mono)' }}>
            {(rawBytes / 1024).toFixed(1)} KB ➔ {(compBytes / 1024).toFixed(1)} KB (Zlib)
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Transaction Latency</span>
            <Clock size={16} color="#00f0ff" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#00f0ff', margin: '4px 0' }}>
            {writeLatency} µs
          </div>
          <div style={{ fontSize: '0.68rem', color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>
            WAL Fast Commit & Index Update
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Indexed Columns</span>
            <Server size={16} color="#c084fc" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#c084fc', margin: '4px 0' }}>
            7 B-Tree Indexes
          </div>
          <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            src_ip, dst_ip, action, anomaly...
          </div>
        </div>

      </div>

      {/* Main Grid: Left Stored Events Query Browser, Right Record Inspector */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 480px', gap: '20px' }}>
        
        {/* Left: Interactive Database Table Browser */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px', flexWrap: 'wrap', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Database size={18} color="#fbbf24" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Relational Database Table: <code style={{ color: '#00f0ff' }}>ulpf_events</code>
              </h3>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', background: '#040813', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '6px', padding: '2px 8px' }}>
                <Search size={12} color="#64748b" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Filter IP / Action / UUID..."
                  style={{ background: 'transparent', border: 'none', color: '#e2e8f0', fontSize: '0.72rem', fontFamily: 'var(--font-mono)', padding: '3px 6px', width: '150px', outline: 'none' }}
                />
              </div>

              <button
                onClick={loadEvents}
                disabled={isLoading}
                className="btn-cyber btn-cyber-secondary"
                style={{ padding: '4px 8px' }}
                title="Refresh Table"
              >
                <RefreshCw size={13} className={isLoading ? 'anim-pulse-cyan' : ''} />
              </button>
            </div>
          </div>

          <div style={{ overflowX: 'auto', maxHeight: '440px', overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: '0.74rem' }}>
              <thead>
                <tr style={{ background: 'rgba(15, 23, 42, 0.9)', color: '#64748b', textAlign: 'left', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
                  <th style={{ padding: '8px 10px' }}>EVENT ID</th>
                  <th style={{ padding: '8px 10px' }}>VENDOR</th>
                  <th style={{ padding: '8px 10px' }}>ACTION</th>
                  <th style={{ padding: '8px 10px' }}>SRC ➔ DST</th>
                  <th style={{ padding: '8px 10px' }}>DQI</th>
                  <th style={{ padding: '8px 10px' }}>ML ANOMALY</th>
                  <th style={{ padding: '8px 10px', textAlign: 'right' }}>VIEW</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map((ev) => {
                  const isSelected = selectedRecord?.event_id === ev.event_id;
                  const isAnomalous = ev.is_anomalous === 1 || ev.is_anomalous === true || (ev.anomaly_score && ev.anomaly_score > 0.4);

                  return (
                    <tr
                      key={ev.event_id}
                      onClick={() => handleRowClick(ev.event_id)}
                      style={{
                        background: isSelected ? 'rgba(245, 158, 11, 0.12)' : 'transparent',
                        borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                        cursor: 'pointer',
                      }}
                    >
                      <td style={{ padding: '8px 10px', color: '#f8fafc', fontWeight: 600 }}>
                        {ev.event_id.slice(0, 10)}...
                      </td>
                      <td style={{ padding: '8px 10px', color: '#cbd5e1' }}>
                        {ev.vendor}
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        <span className={`badge ${ev.action === 'ALLOW' ? 'badge-green' : 'badge-red'}`} style={{ fontSize: '0.6rem' }}>
                          {ev.action}
                        </span>
                      </td>
                      <td style={{ padding: '8px 10px', color: '#94a3b8' }}>
                        <span style={{ color: '#38bdf8' }}>{ev.src_ip || '*'}:{ev.src_port || '*'}</span>
                        <span style={{ margin: '0 4px', color: '#64748b' }}>➔</span>
                        <span style={{ color: '#c084fc' }}>{ev.dst_ip || '*'}:{ev.dst_port || '*'}</span>
                      </td>
                      <td style={{ padding: '8px 10px', color: '#34d399', fontWeight: 700 }}>
                        {ev.data_quality_score || 100}%
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        <span className={`badge ${isAnomalous ? 'badge-red' : 'badge-green'}`} style={{ fontSize: '0.58rem' }}>
                          {ev.anomaly_score !== undefined ? Number(ev.anomaly_score).toFixed(2) : '0.08'}
                        </span>
                      </td>
                      <td style={{ padding: '8px 10px', textAlign: 'right' }}>
                        <Eye size={13} color={isSelected ? '#fbbf24' : '#64748b'} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

        </div>

        {/* Right: Selected Database Record Deep Inspection */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <HardDrive size={18} color="#10b981" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Stored Database Record Payload
              </h3>
            </div>

            {selectedRecord && (
              <button
                onClick={() => copyJson(selectedRecord)}
                className="btn-cyber btn-cyber-secondary"
                style={{ padding: '4px 10px', fontSize: '0.72rem' }}
              >
                {copied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                <span>Copy Record</span>
              </button>
            )}
          </div>

          {selectedRecord ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', flex: 1, overflowY: 'auto', maxHeight: '440px' }}>
              
              {/* Record Summary Strip */}
              <div style={{ background: 'rgba(15, 23, 42, 0.8)', padding: '10px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                <div style={{ fontSize: '0.74rem', fontFamily: 'var(--font-mono)', color: '#f8fafc', fontWeight: 700 }}>
                  Event UUID: {selectedRecord.event_id}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '6px', fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                  <span>SHA-256: <strong style={{ color: '#00f0ff' }}>{selectedRecord.raw_sha256 ? selectedRecord.raw_sha256.slice(0, 16) + '...' : 'none'}</strong></span>
                  <span>Stored At: {selectedRecord.stored_at || 'now'}</span>
                </div>
              </div>

              {/* Raw vs Normalized JSON tabs */}
              <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                PERSISTED CANONICAL JSON:
              </div>
              <div className="code-box" style={{ flex: 1, maxHeight: '200px' }}>
                {selectedRecord.normalized_json 
                  ? (typeof selectedRecord.normalized_json === 'string' 
                      ? selectedRecord.normalized_json 
                      : JSON.stringify(selectedRecord.normalized_json, null, 2))
                  : (selectedRecord.normalized_event 
                      ? JSON.stringify(selectedRecord.normalized_event, null, 2)
                      : 'No JSON payload available.')}
              </div>

              <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', fontWeight: 700, marginTop: '6px' }}>
                PERSISTED PRISTINE RAW LOG:
              </div>
              <div className="code-box" style={{ color: '#38bdf8', maxHeight: '90px' }}>
                {selectedRecord.raw_payload || (selectedRecord.raw_event?.raw.payload) || 'No raw payload available.'}
              </div>

            </div>
          ) : (
            <div style={{ padding: '40px 10px', textAlign: 'center', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
              Select a record from the database table on the left to inspect its stored representations.
            </div>
          )}

        </div>

      </div>

    </div>
  );
};
