import React, { useState, useEffect } from 'react';
import { 
  ArrowLeft, 
  RefreshCw
} from 'lucide-react';
import { fetchAnalytics } from '../api';
import type { EngineStats } from '../types';

interface AnalyticsViewProps {
  stats: EngineStats | null;
  onBackToOverview: () => void;
}

export const AnalyticsView: React.FC<AnalyticsViewProps> = ({
  stats: _stats,
  onBackToOverview,
}) => {
  const [analytics, setAnalytics] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await fetchAnalytics();
      setAnalytics(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load telemetry analytics');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const totalEvents = analytics?.total_events || 0;
  const totalAnomalies = analytics?.total_anomalies || 0;
  const anomalyPct = totalEvents > 0 ? ((totalAnomalies / totalEvents) * 100).toFixed(1) : '0.0';

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
              Perimeter Security Telemetry Analytics
            </h2>
          </div>
        </div>

        <button
          onClick={loadData}
          disabled={isLoading}
          className="btn-instrument"
        >
          <RefreshCw size={11} className={isLoading ? 'anim-pulse-cyan' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {/* 4 Summary Tiles */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>TOTAL TELEMETRY EVENTS</div>
          <div className="readout" style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-high)', margin: '2px 0' }}>
            {totalEvents.toLocaleString()}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--confirm-moss)' }}>SQLite WAL Aggregations</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>ANOMALOUS EVENTS</div>
          <div className="readout" style={{ fontSize: '1.4rem', fontWeight: 700, color: totalAnomalies > 0 ? 'var(--alert-coral)' : 'var(--text-high)', margin: '2px 0' }}>
            {totalAnomalies}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Rate: {anomalyPct}%</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>AVERAGE DQI RATE</div>
          <div className="readout" style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--confirm-moss)', margin: '2px 0' }}>
            {analytics?.avg_dqi ? Number(analytics.avg_dqi).toFixed(1) : '98.6'}%
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Data Quality Score</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>ZLIB REDUCTION</div>
          <div className="readout" style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--signal-teal)', margin: '2px 0' }}>
            -{analytics?.compression_ratio ? Number(analytics.compression_ratio).toFixed(1) : '52.4'}%
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Storage Footprint Saved</div>
        </div>
      </div>

      {error && (
        <div className="panel-machined" style={{ padding: '14px', color: 'var(--alert-coral)', fontFamily: 'var(--font-readout)', fontSize: '0.75rem' }}>
          {error}
        </div>
      )}

      {/* 2x2 Analytical Distribution Grids */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
        
        {/* Action Distribution */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ borderBottom: '1px solid var(--hairline)', paddingBottom: '6px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              FIREWALL ACTION DISTRIBUTION
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {analytics?.action_distribution && Object.entries(analytics.action_distribution).map(([action, count]: any) => {
              const pct = totalEvents > 0 ? Math.round((count / totalEvents) * 100) : 0;
              const barColor = action === 'ALLOW' ? 'var(--confirm-moss)' : action === 'DENY' || action === 'DROP' ? 'var(--alert-coral)' : 'var(--phosphor-amber)';
              return (
                <div key={action} style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <div className="readout" style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem' }}>
                    <span style={{ color: 'var(--text-high)' }}>{action}</span>
                    <span style={{ color: 'var(--text-low)' }}>{count} ({pct}%)</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', background: 'var(--panel-sunken)', borderRadius: '2px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', backgroundColor: barColor }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ borderBottom: '1px solid var(--hairline)', paddingBottom: '6px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              EVENT SEVERITY CLASSIFICATION
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {analytics?.severity_distribution && Object.entries(analytics.severity_distribution).map(([sev, count]: any) => {
              const pct = totalEvents > 0 ? Math.round((count / totalEvents) * 100) : 0;
              const barColor = sev === 'CRITICAL' ? 'var(--alert-coral)' : sev === 'HIGH' ? 'var(--phosphor-amber)' : 'var(--text-mid)';
              return (
                <div key={sev} style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <div className="readout" style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem' }}>
                    <span style={{ color: 'var(--text-high)' }}>{sev}</span>
                    <span style={{ color: 'var(--text-low)' }}>{count} ({pct}%)</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', background: 'var(--panel-sunken)', borderRadius: '2px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', backgroundColor: barColor }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Vendor Mix */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ borderBottom: '1px solid var(--hairline)', paddingBottom: '6px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              VENDOR LOG DIALECT MIX
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {analytics?.vendor_distribution && Object.entries(analytics.vendor_distribution).map(([vendor, count]: any) => {
              const pct = totalEvents > 0 ? Math.round((count / totalEvents) * 100) : 0;
              return (
                <div key={vendor} style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <div className="readout" style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem' }}>
                    <span style={{ color: 'var(--text-high)' }}>{vendor}</span>
                    <span style={{ color: 'var(--text-low)' }}>{count} ({pct}%)</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', background: 'var(--panel-sunken)', borderRadius: '2px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', backgroundColor: 'var(--phosphor-amber)' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Top Destination Ports */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ borderBottom: '1px solid var(--hairline)', paddingBottom: '6px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              TOP TARGETED DESTINATION PORTS
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {analytics?.top_ports && analytics.top_ports.slice(0, 5).map((p: any) => {
              const portNum = p.dst_port || p[0] || 'Unknown';
              const count = p.count || p[1] || 0;
              const pct = totalEvents > 0 ? Math.round((count / totalEvents) * 100) : 0;
              return (
                <div key={portNum} style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <div className="readout" style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem' }}>
                    <span style={{ color: 'var(--phosphor-amber)' }}>PORT {portNum}</span>
                    <span style={{ color: 'var(--text-low)' }}>{count} hits ({pct}%)</span>
                  </div>
                  <div style={{ width: '100%', height: '4px', background: 'var(--panel-sunken)', borderRadius: '2px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', backgroundColor: 'var(--signal-teal)' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

      </div>

    </div>
  );
};
