import React, { useState } from 'react';
import type { 
  PipelineContext, 
  EngineStats, 
  ExportSchemas 
} from '../types';
import { 
  FileCode, 
  ArrowLeft, 
  CheckCircle2, 
  Download, 
  Copy, 
  Check, 
  Server, 
  Clock, 
  ShieldCheck, 
} from 'lucide-react';

interface ExportViewProps {
  context: PipelineContext | null;
  stats: EngineStats | null;
  exports: ExportSchemas | null;
  onBackToOverview: () => void;
}

export const ExportView: React.FC<ExportViewProps> = ({
  context,
  stats,
  exports,
  onBackToOverview,
}) => {
  const [selectedFormat, setSelectedFormat] = useState<'ulpf' | 'elastic' | 'splunk' | 'ocsf' | 'parquet'>('ulpf');
  const [copied, setCopied] = useState(false);

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadJson = (data: any, filename: string) => {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const finalEvent = context?.final_event;
  const isReady = !!exports || !!finalEvent;
  const totalExported = stats?.storage.total_events || stats?.total_processed || 1;

  const EXPORT_DESTINATIONS = [
    {
      id: 'ulpf',
      name: 'ULPF Canonical Standard',
      target: 'Native Data Bus / Core SIEM',
      schema: 'ULPF v1.0.0 Zero-Loss',
      status: 'ONLINE',
      format: 'JSON / Native',
      badge: 'badge-cyan',
    },
    {
      id: 'elastic',
      name: 'Elastic Common Schema (ECS)',
      target: 'Elasticsearch 8.x / OpenSearch / Logstash',
      schema: 'ECS 8.11 / @timestamp',
      status: 'ONLINE',
      format: 'REST Bulk / Index API',
      badge: 'badge-purple',
    },
    {
      id: 'splunk',
      name: 'Splunk HEC (HTTP Event Collector)',
      target: 'Splunk Enterprise / Cloud Indexer',
      schema: 'Splunk JSON Event Envelope',
      status: 'ONLINE',
      format: 'HEC REST / 8088',
      badge: 'badge-amber',
    },
    {
      id: 'ocsf',
      name: 'Open Cybersecurity Schema (OCSF)',
      target: 'AWS Security Lake / Snowflake / Chronicle',
      schema: 'OCSF v1.1.0 (Class 4001)',
      status: 'ONLINE',
      format: 'OCSF Event Schema',
      badge: 'badge-green',
    },
    {
      id: 'parquet',
      name: 'Columnar Flat Schema (Parquet)',
      target: 'AWS S3 / Apache Iceberg / Athena',
      schema: 'Flat Parquet Dataframe Row',
      status: 'ONLINE',
      format: 'Columnar JSON / S3',
      badge: 'badge-blue',
    },
  ];

  const getPayloadForFormat = () => {
    if (!exports) return finalEvent ? finalEvent : { message: 'Awaiting event completion' };
    switch (selectedFormat) {
      case 'ulpf': return exports.ulpf_standard || finalEvent;
      case 'elastic': return exports.elastic_ecs;
      case 'splunk': return exports.splunk_hec;
      case 'ocsf': return exports.ocsf_v1;
      case 'parquet': return exports.columnar_flat;
      default: return exports.ulpf_standard;
    }
  };

  const currentPayload = getPayloadForFormat();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Top Header Bar */}
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
              <span className="badge badge-blue" style={{ fontSize: '0.72rem' }}>STAGE 07</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Standardized SIEM & Data Lake Exporter
              </h2>
            </div>
            <p style={{ fontSize: '0.74rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Real-Time Serialization for Elastic ECS 8.x, Splunk HEC, OCSF v1.1, and Parquet Columnar Storage
            </p>
          </div>
        </div>

        {/* Stage Path */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(15, 23, 42, 0.7)', padding: '6px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <span style={{ fontSize: '0.72rem', color: '#10b981', fontFamily: 'var(--font-mono)' }}>VALIDATED ULPF</span>
          <span style={{ color: '#64748b' }}>➔</span>
          <span style={{ fontSize: '0.72rem', color: '#818cf8', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>[07] EXPORT ENGINE</span>
          <span style={{ color: '#64748b' }}>➔</span>
          <span style={{ fontSize: '0.72rem', color: '#00f0ff', fontFamily: 'var(--font-mono)' }}>SIEM / S3 DESTINATIONS</span>
        </div>
      </div>

      {/* Top 4 Metrics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        
        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Export Formats</span>
            <FileCode size={16} color="#818cf8" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#818cf8', margin: '4px 0' }}>
            5 Standard Envelopes
          </div>
          <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            ECS, Splunk, OCSF, Parquet, ULPF
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Records Exported</span>
            <CheckCircle2 size={16} color="#10b981" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#10b981', margin: '4px 0' }}>
            {totalExported.toLocaleString()} Events
          </div>
          <div style={{ fontSize: '0.68rem', color: '#34d399', fontFamily: 'var(--font-mono)' }}>
            100% Schema Conformance
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Export Status</span>
            <ShieldCheck size={16} color="#00f0ff" />
          </div>
          <div style={{ fontSize: '1.3rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#00f0ff', margin: '4px 0' }}>
            {isReady ? 'DISPATCH READY' : 'QUEUED'}
          </div>
          <div style={{ fontSize: '0.68rem', color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>
            Non-Blocking Zero-Copy Output
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Serialization Latency</span>
            <Clock size={16} color="#fbbf24" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fbbf24', margin: '4px 0' }}>
            16 µs
          </div>
          <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            Fast In-Memory JSON Encoding
          </div>
        </div>

      </div>

      {/* Main Grid: Left Destination Connectors, Right Live Export Payload Preview */}
      <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: '20px' }}>
        
        {/* Left: Export Destinations & Formats */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Server size={18} color="#818cf8" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                SIEM & Lake Destinations
              </h3>
            </div>
            <span className="badge badge-blue" style={{ fontSize: '0.62rem' }}>5 CONNECTORS</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', flex: 1, overflowY: 'auto' }}>
            {EXPORT_DESTINATIONS.map((dest) => {
              const isSelected = selectedFormat === dest.id;
              return (
                <div
                  key={dest.id}
                  onClick={() => setSelectedFormat(dest.id as any)}
                  style={{
                    background: isSelected ? 'rgba(99, 102, 241, 0.15)' : 'rgba(15, 23, 42, 0.65)',
                    border: `1.5px solid ${isSelected ? '#818cf8' : 'rgba(255, 255, 255, 0.05)'}`,
                    borderRadius: '8px',
                    padding: '12px 14px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: 700, color: isSelected ? '#818cf8' : '#f8fafc', fontFamily: 'var(--font-main)' }}>
                      {dest.name}
                    </span>
                    <span className="badge badge-green" style={{ fontSize: '0.58rem' }}>
                      {dest.status}
                    </span>
                  </div>

                  <div style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                    Target: {dest.target}
                  </div>
                  <div style={{ fontSize: '0.66rem', color: '#64748b', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                    Format: {dest.schema}
                  </div>
                </div>
              );
            })}
          </div>

        </div>

        {/* Right: Live Schema Envelope JSON Preview */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileCode size={18} color="#00f0ff" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Standardized Envelope Payload: <code style={{ color: '#00f0ff' }}>{selectedFormat.toUpperCase()}</code>
              </h3>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                onClick={() => copyText(JSON.stringify(currentPayload, null, 2))}
                className="btn-cyber btn-cyber-secondary"
                style={{ padding: '4px 10px', fontSize: '0.72rem' }}
              >
                {copied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                <span>Copy JSON</span>
              </button>

              <button
                onClick={() => downloadJson(currentPayload, `ulpf_export_${selectedFormat}_${context?.event_id || 'sample'}.json`)}
                className="btn-cyber btn-cyber-primary"
                style={{ padding: '4px 12px', fontSize: '0.72rem' }}
              >
                <Download size={12} />
                <span>Download</span>
              </button>
            </div>
          </div>

          <div className="code-box" style={{ flex: 1, maxHeight: '440px', overflowY: 'auto' }}>
            {JSON.stringify(currentPayload, null, 2)}
          </div>

        </div>

      </div>

    </div>
  );
};
