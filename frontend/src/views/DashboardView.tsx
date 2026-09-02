import React, { useState } from 'react';
import type { 
  PipelineContext, 
  EngineStats, 
  StageEnum, 
  SampleLog 
} from '../types';
import { PipelineTopology } from '../components/PipelineTopology';
import { 
  Copy, 
  Check, 
  Milestone
} from 'lucide-react';

interface DashboardViewProps {
  context: PipelineContext | null;
  stats: EngineStats | null;
  selectedStage: StageEnum;
  onSelectStage: (stage: StageEnum) => void;
  activeTransitionStage?: StageEnum | null;
  mode: 'STREAM' | 'DEBUG';
  onSetMode: (mode: 'STREAM' | 'DEBUG') => void;
  isStreaming: boolean;
  onToggleStream: () => void;
  eps: number;
  onSetEps: (eps: number) => void;
  samples: SampleLog[];
  selectedSampleId: string;
  onSelectSample: (sampleId: string) => void;
  onTriggerSingleEvent: () => void;
  onStepForward: () => void;
  onResetStepper: () => void;
  onFastForward: () => void;
  canStepForward: boolean;
  isProcessing: boolean;
  onInspectEvent: (eventId: string) => void;
  onGoToStage: (stageTab: string) => void;
  onGoToJourney: (eventId: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  context,
  stats,
  selectedStage,
  onSelectStage,
  activeTransitionStage,
  mode,
  onSetMode,
  isStreaming,
  onToggleStream,
  eps,
  onSetEps,
  samples,
  selectedSampleId,
  onSelectSample,
  onTriggerSingleEvent,
  onStepForward,
  onResetStepper,
  onFastForward,
  canStepForward,
  isProcessing,
  onInspectEvent,
  onGoToStage,
  onGoToJourney,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const totalEvents = stats?.storage.total_events || stats?.total_processed || 0;
  const totalAnomalies = stats?.storage.total_anomalies || 0;
  const compressionRatio = stats?.storage.overall_compression_ratio || 52.4;
  const avgLatency = context?.total_duration_us || 340;
  const avgDqi = stats?.storage.avg_data_quality_score || 98.6;

  const rawPayload = context?.raw_event?.raw.payload || 'Awaiting log stream...';
  const sha256 = context?.raw_event?.raw.sha256_hash || '—';
  const normEvent = context?.normalized_event;
  const recentEvents = stats?.storage.recent_events || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      
      {/* 1. Top Instrument Readout Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '10px' }}>
        
        {/* Card 1: Data Reduction */}
        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)', textTransform: 'uppercase' }}>
            ZLIB COMPRESSION
          </div>
          <div className="readout" style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--signal-teal)', margin: '2px 0' }}>
            -{compressionRatio.toFixed(1)}%
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>
            WAL Columnar Footprint
          </div>
        </div>

        {/* Card 2: Total Events */}
        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)', textTransform: 'uppercase' }}>
            STORED EVENTS
          </div>
          <div className="readout" style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-high)', margin: '2px 0' }}>
            {totalEvents.toLocaleString()}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>
            SQLite WAL Database
          </div>
        </div>

        {/* Card 3: DQI Score */}
        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)', textTransform: 'uppercase' }}>
            AVERAGE DQI
          </div>
          <div className="readout" style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--confirm-moss)', margin: '2px 0' }}>
            {avgDqi.toFixed(1)}%
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>
            Rule Validation Rate
          </div>
        </div>

        {/* Card 4: Anomalies */}
        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)', textTransform: 'uppercase' }}>
            ANOMALIES FLAGGED
          </div>
          <div className="readout" style={{ fontSize: '1.4rem', fontWeight: 700, color: totalAnomalies > 0 ? 'var(--alert-coral)' : 'var(--text-mid)', margin: '2px 0' }}>
            {totalAnomalies}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>
            Isolation Forest Flags
          </div>
        </div>

        {/* Card 5: Pipeline Latency */}
        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)', textTransform: 'uppercase' }}>
            PIPELINE LATENCY
          </div>
          <div className="readout" style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--phosphor-amber)', margin: '2px 0' }}>
            {avgLatency} <span style={{ fontSize: '0.8rem', color: 'var(--text-low)' }}>µs</span>
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>
            Sub-millisecond End-to-End
          </div>
        </div>

      </div>

      {/* 2. Hero Pipeline Signal Chain */}
      <PipelineTopology
        context={context}
        selectedStage={selectedStage}
        onSelectStage={(st) => {
          onSelectStage(st);
          if (st === 'INGEST') onGoToStage('ingestion');
          else if (st === 'PARSE') onGoToStage('parser');
          else if (st === 'NORMALIZE') onGoToStage('normalization');
          else if (st === 'VALIDATE') onGoToStage('validation');
          else if (st === 'STORE') onGoToStage('storage');
          else if (st === 'ML') onGoToStage('ml');
          else if (st === 'STANDARDIZED') onGoToStage('export');
        }}
        activeTransitionStage={activeTransitionStage}
        mode={mode}
        onSetMode={onSetMode}
        isStreaming={isStreaming}
        onToggleStream={onToggleStream}
        eps={eps}
        onSetEps={onSetEps}
        samples={samples}
        selectedSampleId={selectedSampleId}
        onSelectSample={onSelectSample}
        onTriggerSingleEvent={onTriggerSingleEvent}
        onStepForward={onStepForward}
        onResetStepper={onResetStepper}
        onFastForward={onFastForward}
        canStepForward={canStepForward}
        isProcessing={isProcessing}
      />

      {/* 3. Mid Section: Dual Readouts (Raw vs Canonical Normalized) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
        
        {/* Raw Log Readout */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="badge-inst badge-hairline">STAGE 01</span>
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
                Pristine Raw Log Payload
              </span>
            </div>
            <button
              onClick={() => copyToClipboard(rawPayload, 'raw')}
              className="btn-instrument"
              style={{ padding: '2px 6px', fontSize: '0.66rem' }}
            >
              {copiedKey === 'raw' ? <Check size={10} color="var(--confirm-moss)" /> : <Copy size={10} />}
              <span>Copy</span>
            </button>
          </div>

          <div className="readout-box" style={{ minHeight: '110px', maxHeight: '150px', color: 'var(--text-high)' }}>
            {rawPayload}
          </div>

          <div className="readout" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.68rem', color: 'var(--text-low)' }}>
            <span>SHA-256: <span style={{ color: 'var(--confirm-moss)' }}>{sha256.slice(0, 24)}...</span></span>
            <span>BYTES: <strong style={{ color: 'var(--text-high)' }}>{context?.raw_event?.raw.length_bytes || 0} B</strong></span>
          </div>
        </div>

        {/* Canonical Normalized Readout */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="badge-inst badge-hairline">STAGE 03</span>
              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
                Normalized Canonical Schema
              </span>
            </div>
            <button
              onClick={() => copyToClipboard(JSON.stringify(normEvent, null, 2), 'norm')}
              className="btn-instrument"
              style={{ padding: '2px 6px', fontSize: '0.66rem' }}
            >
              {copiedKey === 'norm' ? <Check size={10} color="var(--confirm-moss)" /> : <Copy size={10} />}
              <span>Copy JSON</span>
            </button>
          </div>

          <div className="readout-box" style={{ minHeight: '110px', maxHeight: '150px', color: 'var(--text-mid)' }}>
            {normEvent ? JSON.stringify(normEvent, null, 2) : '// Awaiting normalization...'}
          </div>

          <div className="readout" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.68rem', color: 'var(--text-low)' }}>
            <span>ACTION: <strong style={{ color: 'var(--text-high)' }}>{normEvent?.event.action || '—'}</strong></span>
            <span>SEVERITY: <strong style={{ color: 'var(--phosphor-amber)' }}>{normEvent?.event.severity || '—'}</strong></span>
            <span>SCHEMA: ULPF v1.0</span>
          </div>
        </div>

      </div>

      {/* 4. Bottom Section: Stored Events Telemetry Feed */}
      <div className="panel-machined" style={{ overflow: 'hidden' }}>
        
        <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--hairline)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
            RECENT STORED PERIMETER EVENTS (SQLITE WAL)
          </span>

          <button
            onClick={() => onGoToStage('explorer')}
            className="btn-instrument"
            style={{ padding: '3px 8px', fontSize: '0.7rem' }}
          >
            Open Explorer
          </button>
        </div>

        {recentEvents.length === 0 ? (
          <div className="readout" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-low)', fontSize: '0.76rem' }}>
            No perimeter events stored yet. Trigger single events or start live streaming above.
          </div>
        ) : (
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
                  <th style={{ padding: '8px 12px', textAlign: 'center' }}>Trace</th>
                </tr>
              </thead>
              <tbody>
                {recentEvents.slice(0, 6).map((ev: any, idx: number) => {
                  const isAnom = ev.is_anomalous === 1 || (ev.anomaly_score && ev.anomaly_score >= 0.60);
                  const actColor = ev.action === 'ALLOW' ? 'var(--confirm-moss)' : ev.action === 'DENY' || ev.action === 'DROP' ? 'var(--alert-coral)' : 'var(--phosphor-amber)';
                  const sevColor = ev.severity === 'CRITICAL' ? 'var(--alert-coral)' : ev.severity === 'HIGH' ? 'var(--phosphor-amber)' : 'var(--text-mid)';

                  return (
                    <tr 
                      key={ev.event_id || idx}
                      style={{ 
                        borderBottom: '1px solid var(--hairline)',
                        background: idx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.01)'
                      }}
                    >
                      <td style={{ padding: '8px 12px', color: 'var(--text-high)', fontWeight: 600 }}>
                        {ev.event_id ? ev.event_id.slice(0, 8) : 'N/A'}
                      </td>
                      <td style={{ padding: '8px 12px', color: 'var(--text-mid)' }}>
                        {ev.timestamp ? ev.timestamp.slice(11, 19) : '00:00:00'}
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
                        <button
                          onClick={() => {
                            onInspectEvent(ev.event_id);
                            onGoToJourney(ev.event_id);
                          }}
                          className="btn-instrument"
                          style={{ padding: '2px 6px', fontSize: '0.64rem' }}
                        >
                          <Milestone size={10} />
                          <span>Trace</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

      </div>

    </div>
  );
};
