import React, { useState, useEffect } from 'react';
import type { 
  PipelineContext, 
  EngineStats 
} from '../types';
import { fetchStoredEvents, fetchEventDetail } from '../api';
import { 
  ArrowLeft, 
  Copy, 
  Check, 
  RefreshCw
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
      const data = await fetchStoredEvents(50, 0);
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
  const ratio = stats?.storage.overall_compression_ratio || 52.4;
  const writeLatency = context?.stored_event?.storage_duration_us || 38;

  const filteredEvents = events.filter((ev) => 
    ev.event_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (ev.src_ip && ev.src_ip.includes(searchTerm)) ||
    (ev.dst_ip && ev.dst_ip.includes(searchTerm)) ||
    (ev.action && ev.action.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      
      {/* Header Bar */}
      <div className="panel-machined" style={{ padding: '12px 18px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            onClick={onBackToOverview}
            className="btn-instrument"
          >
            <ArrowLeft size={13} />
            <span>Control Room</span>
          </button>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span className="badge-inst badge-amber">STAGE [05]</span>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
              SQLite WAL Storage & Columnar Compression
            </h2>
          </div>
        </div>

        <div className="readout" style={{ fontSize: '0.74rem', color: 'var(--text-low)' }}>
          WRITE LATENCY: <strong style={{ color: 'var(--phosphor-amber)' }}>{writeLatency} µs</strong>
        </div>
      </div>

      {/* 4 Readout Metric Tiles */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>TOTAL STORED EVENTS</div>
          <div className="readout" style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-high)', margin: '2px 0' }}>
            {totalEvents.toLocaleString()}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--confirm-moss)' }}>WAL Mode Active</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>ZLIB COMPRESSION REDUCTION</div>
          <div className="readout" style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--signal-teal)', margin: '2px 0' }}>
            -{ratio.toFixed(1)}%
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Payload Footprint Saved</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>RAW BYTE VOLUME</div>
          <div className="readout" style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-high)', margin: '2px 0' }}>
            {(rawBytes / 1024).toFixed(1)} KB
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Pre-Compression Bytes</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>COMPRESSED DISK SIZE</div>
          <div className="readout" style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--confirm-moss)', margin: '2px 0' }}>
            {(compBytes / 1024).toFixed(1)} KB
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Disk Footprint</div>
        </div>
      </div>

      {/* Main Dual Grid: Left Stored Event Table, Right Stored Record Detail */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 420px', gap: '12px' }}>
        
        {/* Left: Events List */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              STORED WAL RECORDS (ulpf_events.db)
            </span>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <input
                type="text"
                placeholder="Filter events..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  background: 'var(--panel-sunken)',
                  border: '1px solid var(--hairline)',
                  borderRadius: 'var(--radius-sm)',
                  color: 'var(--text-high)',
                  fontFamily: 'var(--font-readout)',
                  fontSize: '0.72rem',
                  padding: '3px 8px',
                  outline: 'none',
                  width: '130px',
                }}
              />
              <button
                onClick={loadEvents}
                disabled={isLoading}
                className="btn-instrument"
                style={{ padding: '2px 6px', fontSize: '0.66rem' }}
                title="Refresh from SQLite WAL"
              >
                <RefreshCw size={10} className={isLoading ? 'anim-pulse-cyan' : ''} />
              </button>
            </div>
          </div>

          <div style={{ overflowX: 'auto', maxHeight: '380px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontFamily: 'var(--font-readout)', fontSize: '0.72rem' }}>
              <thead>
                <tr style={{ background: 'var(--panel-sunken)', borderBottom: '1px solid var(--hairline)', color: 'var(--text-low)', textTransform: 'uppercase', fontSize: '0.64rem' }}>
                  <th style={{ padding: '6px 10px' }}>UUID</th>
                  <th style={{ padding: '6px 10px' }}>Vendor</th>
                  <th style={{ padding: '6px 10px' }}>Source IP</th>
                  <th style={{ padding: '6px 10px' }}>Action</th>
                  <th style={{ padding: '6px 10px' }}>DQI</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map((ev, idx) => (
                  <tr 
                    key={ev.event_id || idx}
                    onClick={() => handleRowClick(ev.event_id)}
                    style={{ 
                      borderBottom: '1px solid var(--hairline)',
                      background: selectedRecord?.event_id === ev.event_id ? 'var(--phosphor-amber-dim)' : idx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.01)',
                      cursor: 'pointer',
                    }}
                  >
                    <td style={{ padding: '6px 10px', color: 'var(--phosphor-amber)', fontWeight: 600 }}>
                      {ev.event_id ? ev.event_id.slice(0, 8) : 'N/A'}
                    </td>
                    <td style={{ padding: '6px 10px', color: 'var(--text-high)' }}>
                      {ev.vendor || 'Generic'}
                    </td>
                    <td style={{ padding: '6px 10px', color: 'var(--text-mid)' }}>
                      {ev.src_ip || '—'}
                    </td>
                    <td style={{ padding: '6px 10px' }}>
                      <span className={`badge-inst ${ev.action === 'ALLOW' ? 'badge-moss' : 'badge-coral'}`}>
                        {ev.action || 'UNKNOWN'}
                      </span>
                    </td>
                    <td style={{ padding: '6px 10px', color: 'var(--confirm-moss)' }}>
                      {ev.data_quality_score ?? 100}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Selected Stored Record JSON */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              STORED RECORD JSON DETAIL
            </span>
            {selectedRecord && (
              <button
                onClick={() => copyJson(selectedRecord)}
                className="btn-instrument"
                style={{ padding: '2px 6px', fontSize: '0.66rem' }}
              >
                {copied ? <Check size={10} color="var(--confirm-moss)" /> : <Copy size={10} />}
                <span>Copy</span>
              </button>
            )}
          </div>

          <div className="readout-box" style={{ minHeight: '340px', color: 'var(--text-mid)', fontSize: '0.7rem' }}>
            {selectedRecord 
              ? JSON.stringify(selectedRecord, null, 2)
              : '// Click an event row on the left to inspect stored record'}
          </div>
        </div>

      </div>

    </div>
  );
};
