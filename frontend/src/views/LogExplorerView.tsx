import React, { useState, useEffect } from 'react';
import { 
  Search, 
  ArrowLeft, 
  RefreshCw, 
  AlertTriangle, 
  Copy, 
  Check, 
  Eye, 
  Milestone,
  X
} from 'lucide-react';
import { fetchStoredEvents, fetchEventDetail } from '../api';
import type { EngineStats } from '../types';

interface LogExplorerViewProps {
  stats: EngineStats | null;
  onBackToOverview: () => void;
  onInspectEvent: (eventId: string) => void;
  onGoToJourney: (eventId: string) => void;
}

export const LogExplorerView: React.FC<LogExplorerViewProps> = ({
  stats,
  onBackToOverview,
  onInspectEvent,
  onGoToJourney,
}) => {
  const [events, setEvents] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAction, setSelectedAction] = useState('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedVendor, setSelectedVendor] = useState('ALL');
  const [anomalyFilter, setAnomalyFilter] = useState<'ALL' | 'ANOMALOUS' | 'NORMAL'>('ALL');
  
  // Pagination
  const [limit] = useState(25);
  const [offset, setOffset] = useState(0);

  // Detail Drawer State
  const [selectedEventDetail, setSelectedEventDetail] = useState<any | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const loadEvents = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const isAnom = anomalyFilter === 'ANOMALOUS' ? true : anomalyFilter === 'NORMAL' ? false : undefined;
      const data = await fetchStoredEvents({
        limit,
        offset,
        search: searchTerm.trim() || undefined,
        action: selectedAction,
        severity: selectedSeverity,
        vendor: selectedVendor,
        isAnomalous: isAnom,
      });
      setEvents(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to query database events');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, [offset, selectedAction, selectedSeverity, selectedVendor, anomalyFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setOffset(0);
    loadEvents();
  };

  const handleOpenDetail = async (eventId: string) => {
    try {
      const detail = await fetchEventDetail(eventId);
      setSelectedEventDetail(detail);
    } catch (err) {
      console.error('Failed to load event detail', err);
    }
  };

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
          <div>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
              Perimeter Security Log Explorer
            </h2>
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
          <div className="readout" style={{ fontSize: '0.72rem', color: 'var(--phosphor-amber)' }}>
            TOTAL: {stats?.storage.total_events ?? events.length} EVENTS
          </div>
        </div>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="panel-machined" style={{ padding: '12px 16px' }}>
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          
          {/* Search Box */}
          <div style={{ flex: 1, minWidth: '240px', position: 'relative' }}>
            <input
              type="text"
              placeholder="Search UUID, IP, Vendor, or Raw Payload..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                width: '100%',
                padding: '6px 10px 6px 30px',
                background: 'var(--panel-sunken)',
                border: '1px solid var(--hairline)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontFamily: 'var(--font-readout)',
                fontSize: '0.75rem',
                outline: 'none',
              }}
            />
            <Search size={13} color="var(--text-low)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
          </div>

          {/* Action Filter */}
          <select
            value={selectedAction}
            onChange={(e) => { setSelectedAction(e.target.value); setOffset(0); }}
            style={{
              padding: '6px 8px',
              background: 'var(--panel-sunken)',
              border: '1px solid var(--hairline)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-mid)',
              fontFamily: 'var(--font-readout)',
              fontSize: '0.72rem',
              outline: 'none',
            }}
          >
            <option value="ALL">Action: All</option>
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">DENY</option>
            <option value="DROP">DROP</option>
            <option value="ALERT">ALERT</option>
            <option value="RESET">RESET</option>
          </select>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => { setSelectedSeverity(e.target.value); setOffset(0); }}
            style={{
              padding: '6px 8px',
              background: 'var(--panel-sunken)',
              border: '1px solid var(--hairline)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-mid)',
              fontFamily: 'var(--font-readout)',
              fontSize: '0.72rem',
              outline: 'none',
            }}
          >
            <option value="ALL">Severity: All</option>
            <option value="INFORMATIONAL">INFORMATIONAL</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>

          {/* Vendor Filter */}
          <select
            value={selectedVendor}
            onChange={(e) => { setSelectedVendor(e.target.value); setOffset(0); }}
            style={{
              padding: '6px 8px',
              background: 'var(--panel-sunken)',
              border: '1px solid var(--hairline)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-mid)',
              fontFamily: 'var(--font-readout)',
              fontSize: '0.72rem',
              outline: 'none',
            }}
          >
            <option value="ALL">Vendor: All</option>
            <option value="Cisco">Cisco ASA</option>
            <option value="Palo Alto Networks">Palo Alto</option>
            <option value="Suricata">Suricata</option>
            <option value="Amazon Web Services">AWS VPC</option>
            <option value="Zeek Project">Zeek</option>
            <option value="Micro Focus ArcSight">ArcSight CEF</option>
            <option value="Microsoft">Windows</option>
          </select>

          {/* Anomaly Filter */}
          <select
            value={anomalyFilter}
            onChange={(e) => { setAnomalyFilter(e.target.value as any); setOffset(0); }}
            style={{
              padding: '6px 8px',
              background: 'var(--panel-sunken)',
              border: '1px solid var(--hairline)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-mid)',
              fontFamily: 'var(--font-readout)',
              fontSize: '0.72rem',
              outline: 'none',
            }}
          >
            <option value="ALL">ML: All</option>
            <option value="ANOMALOUS">Anomalies Only</option>
            <option value="NORMAL">Normal Only</option>
          </select>

          <button
            type="submit"
            className="btn-instrument btn-instrument-primary"
          >
            Search
          </button>

        </form>
      </div>

      {/* Main Events Table Container */}
      <div className="panel-machined" style={{ overflow: 'hidden' }}>
        
        {/* Table Header */}
        <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--hairline)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
            STORED TELEMETRY RECORDS
          </span>
          <span className="readout" style={{ fontSize: '0.68rem', color: 'var(--text-low)' }}>
            Showing {events.length} records (Offset: {offset})
          </span>
        </div>

        {/* Loading State */}
        {isLoading && (
          <div className="readout" style={{ padding: '30px', textAlign: 'center', color: 'var(--phosphor-amber)', fontSize: '0.78rem' }}>
            Querying SQLite WAL index tables...
          </div>
        )}

        {/* Error State */}
        {error && !isLoading && (
          <div className="readout" style={{ padding: '20px', textAlign: 'center', color: 'var(--alert-coral)', fontSize: '0.75rem' }}>
            <AlertTriangle size={14} style={{ display: 'inline-block', marginRight: '6px' }} />
            Query error: {error}
          </div>
        )}

        {/* Empty State */}
        {!isLoading && !error && events.length === 0 && (
          <div className="readout" style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-low)', fontSize: '0.76rem' }}>
            No events matched query.
          </div>
        )}

        {/* Table Rows */}
        {!isLoading && !error && events.length > 0 && (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontFamily: 'var(--font-readout)', fontSize: '0.72rem' }}>
              <thead>
                <tr style={{ background: 'var(--panel-sunken)', borderBottom: '1px solid var(--hairline)', color: 'var(--text-low)', textTransform: 'uppercase', fontSize: '0.64rem' }}>
                  <th style={{ padding: '8px 12px' }}>Event UUID</th>
                  <th style={{ padding: '8px 12px' }}>Timestamp</th>
                  <th style={{ padding: '8px 12px' }}>Vendor</th>
                  <th style={{ padding: '8px 12px' }}>Source IP:Port</th>
                  <th style={{ padding: '8px 12px' }}>Destination IP:Port</th>
                  <th style={{ padding: '8px 12px' }}>Action</th>
                  <th style={{ padding: '8px 12px' }}>Severity</th>
                  <th style={{ padding: '8px 12px' }}>DQI</th>
                  <th style={{ padding: '8px 12px' }}>Anomaly</th>
                  <th style={{ padding: '8px 12px', textAlign: 'center' }}>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev, idx) => {
                  const isAnom = ev.is_anomalous === 1 || (ev.anomaly_score && ev.anomaly_score >= 0.60);
                  const actColor = ev.action === 'ALLOW' ? 'var(--confirm-moss)' : ev.action === 'DENY' || ev.action === 'DROP' ? 'var(--alert-coral)' : 'var(--phosphor-amber)';
                  const sevColor = ev.severity === 'CRITICAL' ? 'var(--alert-coral)' : ev.severity === 'HIGH' ? 'var(--phosphor-amber)' : 'var(--text-mid)';

                  return (
                    <tr
                      key={ev.event_id || idx}
                      style={{
                        borderBottom: '1px solid var(--hairline)',
                        background: idx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.01)',
                      }}
                    >
                      <td style={{ padding: '8px 12px', color: 'var(--text-high)', fontWeight: 600 }}>
                        {ev.event_id ? ev.event_id.slice(0, 8) : 'N/A'}
                      </td>

                      <td style={{ padding: '8px 12px', color: 'var(--text-mid)' }}>
                        {ev.timestamp ? ev.timestamp.slice(11, 19) : ev.ingested_at ? ev.ingested_at.slice(11, 19) : '00:00:00'}
                      </td>

                      <td style={{ padding: '8px 12px', color: 'var(--text-high)' }}>
                        {ev.vendor || 'Generic'}
                      </td>

                      <td style={{ padding: '8px 12px', color: 'var(--text-mid)' }}>
                        {ev.src_ip ? `${ev.src_ip}:${ev.src_port || 0}` : '—'}
                      </td>

                      <td style={{ padding: '8px 12px', color: 'var(--text-mid)' }}>
                        {ev.dst_ip ? `${ev.dst_ip}:${ev.dst_port || 0}` : '—'}
                      </td>

                      <td style={{ padding: '8px 12px' }}>
                        <span style={{ color: actColor, fontWeight: 700 }}>
                          {ev.action || 'UNKNOWN'}
                        </span>
                      </td>

                      <td style={{ padding: '8px 12px' }}>
                        <span style={{ color: sevColor, fontWeight: 600 }}>
                          {ev.severity || 'INFO'}
                        </span>
                      </td>

                      <td style={{ padding: '8px 12px' }}>
                        <span style={{ color: 'var(--confirm-moss)', fontWeight: 600 }}>
                          {ev.data_quality_score ?? 100}%
                        </span>
                      </td>

                      <td style={{ padding: '8px 12px' }}>
                        <span className={`badge-inst ${isAnom ? 'badge-coral' : 'badge-moss'}`}>
                          {ev.anomaly_score !== undefined ? Number(ev.anomaly_score).toFixed(2) : '0.00'}
                        </span>
                      </td>

                      <td style={{ padding: '8px 12px', textAlign: 'center' }}>
                        <div style={{ display: 'inline-flex', gap: '4px' }}>
                          <button
                            onClick={() => handleOpenDetail(ev.event_id)}
                            className="btn-instrument"
                            style={{ padding: '2px 6px', fontSize: '0.64rem' }}
                            title="Inspect Record Detail"
                          >
                            <Eye size={10} />
                            <span>View</span>
                          </button>
                          <button
                            onClick={() => {
                              onInspectEvent(ev.event_id);
                              onGoToJourney(ev.event_id);
                            }}
                            className="btn-instrument btn-instrument-primary"
                            style={{ padding: '2px 6px', fontSize: '0.64rem' }}
                            title="Open in Event Journey"
                          >
                            <Milestone size={10} />
                            <span>Journey</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        <div style={{ padding: '10px 16px', borderTop: '1px solid var(--hairline)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <button
            onClick={() => setOffset(Math.max(0, offset - limit))}
            disabled={offset === 0 || isLoading}
            className="btn-instrument"
            style={{ padding: '3px 8px', fontSize: '0.7rem' }}
          >
            Previous
          </button>
          
          <span className="readout" style={{ fontSize: '0.7rem', color: 'var(--text-low)' }}>
            PAGE {Math.floor(offset / limit) + 1}
          </span>

          <button
            onClick={() => setOffset(offset + limit)}
            disabled={events.length < limit || isLoading}
            className="btn-instrument"
            style={{ padding: '3px 8px', fontSize: '0.7rem' }}
          >
            Next
          </button>
        </div>

      </div>

      {/* Record Inspection Modal */}
      {selectedEventDetail && (
        <div className="modal-overlay" onClick={() => setSelectedEventDetail(null)}>
          <div
            className="panel-machined"
            style={{ width: '750px', maxWidth: '95vw', maxHeight: '85vh', overflowY: 'auto', padding: '18px' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
              <span style={{ fontSize: '0.88rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
                RECORD DETAIL: {selectedEventDetail.event_id}
              </span>
              <button
                onClick={() => setSelectedEventDetail(null)}
                className="btn-instrument"
                style={{ padding: '3px 6px' }}
              >
                <X size={12} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              
              {/* Raw Payload Readout */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span className="readout" style={{ fontSize: '0.68rem', color: 'var(--text-low)' }}>PRISTINE RAW LOG</span>
                  <button
                    onClick={() => copyToClipboard(selectedEventDetail.raw_payload || '', 'raw')}
                    className="btn-instrument"
                    style={{ padding: '2px 6px', fontSize: '0.64rem' }}
                  >
                    {copiedKey === 'raw' ? <Check size={10} color="var(--confirm-moss)" /> : <Copy size={10} />}
                    <span>Copy</span>
                  </button>
                </div>
                <div className="readout-box" style={{ maxHeight: '100px', color: 'var(--text-high)' }}>
                  {selectedEventDetail.raw_payload}
                </div>
              </div>

              {/* SHA-256 Digest */}
              <div className="readout" style={{ fontSize: '0.68rem', color: 'var(--text-low)' }}>
                SHA-256: <span style={{ color: 'var(--confirm-moss)' }}>{selectedEventDetail.raw_sha256}</span>
              </div>

              {/* Normalized JSON */}
              {selectedEventDetail.normalized_json && (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <span className="readout" style={{ fontSize: '0.68rem', color: 'var(--text-low)' }}>STORED CANONICAL JSON</span>
                    <button
                      onClick={() => copyToClipboard(JSON.stringify(selectedEventDetail.normalized_json, null, 2), 'norm')}
                      className="btn-instrument"
                      style={{ padding: '2px 6px', fontSize: '0.64rem' }}
                    >
                      {copiedKey === 'norm' ? <Check size={10} color="var(--confirm-moss)" /> : <Copy size={10} />}
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="readout-box" style={{ maxHeight: '180px', color: 'var(--text-mid)', fontSize: '0.7rem' }}>
                    {typeof selectedEventDetail.normalized_json === 'string'
                      ? selectedEventDetail.normalized_json
                      : JSON.stringify(selectedEventDetail.normalized_json, null, 2)}
                  </div>
                </div>
              )}

              {/* Trace Journey Action */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '6px' }}>
                <button
                  onClick={() => {
                    const id = selectedEventDetail.event_id;
                    setSelectedEventDetail(null);
                    onInspectEvent(id);
                    onGoToJourney(id);
                  }}
                  className="btn-instrument btn-instrument-primary"
                >
                  <Milestone size={11} />
                  <span>Trace Full Event Journey</span>
                </button>
              </div>

            </div>
          </div>
        </div>
      )}

    </div>
  );
};
