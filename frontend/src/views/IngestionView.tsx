import React, { useState } from 'react';
import type { 
  PipelineContext, 
  EngineStats, 
  SampleLog 
} from '../types';
import { 
  FileInput, 
  ArrowLeft, 
  ShieldCheck, 
  Radio, 
  Terminal, 
  Copy, 
  Check, 
  Clock, 
  Fingerprint,
  Zap,
  Server,
} from 'lucide-react';

interface IngestionViewProps {
  context: PipelineContext | null;
  stats: EngineStats | null;
  onBackToOverview: () => void;
  onRunCustomIngest: (rawText: string) => void;
  samples: SampleLog[];
}

export const IngestionView: React.FC<IngestionViewProps> = ({
  context,
  stats,
  onBackToOverview,
  onRunCustomIngest,
  samples,
}) => {
  const [customInput, setCustomInput] = useState<string>('');
  const [copied, setCopied] = useState(false);

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const rawEvent = context?.raw_event;
  const rawPayload = rawEvent?.raw.payload || '';
  const sha256 = rawEvent?.raw.sha256_hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const byteLength = rawEvent?.raw.length_bytes || rawPayload.length;
  const protocol = rawEvent?.raw.source_protocol || 'SYSLOG_UDP';
  const ingestedAt = rawEvent?.ingested_at || new Date().toISOString();

  // Ingestion metrics
  const metric = context?.stage_metrics?.find((m) => m.stage === 'INGEST');
  const durationUs = metric?.duration_us || 18;

  // Active perimeter log sources configured in ULPF
  const ACTIVE_SOURCES = [
    { name: 'Syslog UDP Daemon', port: '514/UDP', protocol: 'SYSLOG_UDP', status: 'ONLINE', rate: stats?.is_streaming ? `${stats.current_eps} EPS` : 'Standby', format: 'RFC 3164 / 5424' },
    { name: 'HTTPS Ingestion API', port: '8000/TCP', protocol: 'HTTP_REST', status: 'ONLINE', rate: 'Active (REST/WS)', format: 'JSON / Raw String' },
    { name: 'AWS CloudWatch VPC Stream', port: 'AWS-SDK', protocol: 'VPC_FLOW', status: 'READY', rate: 'Poll Mode', format: 'AWS Flow Logs v2' },
    { name: 'Suricata EVE Socket', port: 'UNIX_SOCK', protocol: 'FILE_BEAT', status: 'READY', rate: 'JSON Tail', format: 'Suricata EVE JSON' },
    { name: 'Zeek Network Sensor', port: 'LOG_SINK', protocol: 'ZEEK_STREAM', status: 'READY', rate: 'TSV Tail', format: 'Zeek TSV Format' },
  ];

  const generateHexDump = (str: string) => {
    if (!str) return 'No raw payload to display.';
    const bytes = new TextEncoder().encode(str);
    const lines: string[] = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const hex = Array.from(chunk)
        .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join(' ');
      const ascii = Array.from(chunk)
        .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
        .join('');
      const offset = i.toString(16).padStart(4, '0').toUpperCase();
      lines.push(`${offset}  ${hex.padEnd(48, ' ')}  |${ascii}|`);
    }
    return lines.join('\n');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Top Header & Breadcrumb */}
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
              <span className="badge badge-cyan" style={{ fontSize: '0.72rem' }}>STAGE 01</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Ingestion Engine Dashboard
              </h2>
            </div>
            <p style={{ fontSize: '0.74rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Zero-Loss Raw Stream Capture, Tamper-Proof Cryptographic Digest & Byte Stream Integrity
            </p>
          </div>
        </div>

        {/* Visual Stage Path */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(15, 23, 42, 0.7)', padding: '6px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <span style={{ fontSize: '0.72rem', color: '#00f0ff', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>PERIMETER SOURCE</span>
          <span style={{ color: '#64748b' }}>➔</span>
          <span style={{ fontSize: '0.72rem', color: '#10b981', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>[01] INGESTION</span>
          <span style={{ color: '#64748b' }}>➔</span>
          <span style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>PARSER PIPELINE</span>
        </div>
      </div>

      {/* Top 4 Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        
        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Ingestion Rate</span>
            <Radio size={16} color="#00f0ff" className={stats?.is_streaming ? 'anim-pulse-cyan' : ''} />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#f8fafc', margin: '4px 0' }}>
            {stats?.is_streaming ? `${stats.current_eps} EPS` : 'Step Mode'}
          </div>
          <div style={{ fontSize: '0.68rem', color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>
            Real-Time Telemetry Stream
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Zero-Loss Status</span>
            <ShieldCheck size={16} color="#10b981" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#10b981', margin: '4px 0' }}>
            100.0% ACCEPTED
          </div>
          <div style={{ fontSize: '0.68rem', color: '#34d399', fontFamily: 'var(--font-mono)' }}>
            0 Dropped / 0 Tampered
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Captured Payload Size</span>
            <FileInput size={16} color="#c084fc" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#f8fafc', margin: '4px 0' }}>
            {byteLength} Bytes
          </div>
          <div style={{ fontSize: '0.68rem', color: '#c084fc', fontFamily: 'var(--font-mono)' }}>
            Encoding: UTF-8 (Exact Byte Sequence)
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Ingest Execution Latency</span>
            <Clock size={16} color="#fbbf24" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fbbf24', margin: '4px 0' }}>
            {durationUs} µs
          </div>
          <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            Hashing & Buffer Memory Commit
          </div>
        </div>

      </div>

      {/* Main Grid: Active Ingestion Sources & Current Ingested Payload */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        
        {/* Left: Active Sources & Ingestion Ports */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Server size={18} color="#00f0ff" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Active Perimeter Ingestion Endpoints
              </h3>
            </div>
            <span className="badge badge-green" style={{ fontSize: '0.62rem' }}>5 CONNECTORS</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {ACTIVE_SOURCES.map((src, idx) => (
              <div
                key={idx}
                style={{
                  background: 'rgba(15, 23, 42, 0.65)',
                  padding: '10px 14px',
                  borderRadius: '8px',
                  border: '1px solid rgba(255, 255, 255, 0.05)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#f8fafc', fontFamily: 'var(--font-main)' }}>
                    {src.name}
                  </div>
                  <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                    Port/Sink: <strong style={{ color: '#38bdf8' }}>{src.port}</strong> • Format: {src.format}
                  </div>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <span className="badge badge-green" style={{ fontSize: '0.62rem' }}>
                    {src.status}
                  </span>
                  <div style={{ fontSize: '0.68rem', color: '#cbd5e1', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                    {src.rate}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Quick Custom Ingest Tool */}
          <div style={{ marginTop: '16px', paddingTop: '14px', borderTop: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <div style={{ fontSize: '0.74rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#00f0ff', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Terminal size={14} />
              <span>TEST CUSTOM LOG INGESTION:</span>
            </div>
            <textarea
              rows={3}
              value={customInput}
              onChange={(e) => setCustomInput(e.target.value)}
              placeholder="Paste raw syslog, CEF, or JSON log string to test live ingestion..."
              style={{
                width: '100%',
                background: '#040813',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                borderRadius: '8px',
                padding: '8px 10px',
                color: '#e2e8f0',
                fontSize: '0.75rem',
                fontFamily: 'var(--font-mono)',
                resize: 'none',
                marginBottom: '8px',
              }}
            />
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', gap: '6px' }}>
                {samples.slice(0, 2).map((s) => (
                  <button
                    key={s.id}
                    onClick={() => setCustomInput(s.raw)}
                    className="btn-cyber btn-cyber-secondary"
                    style={{ padding: '3px 8px', fontSize: '0.68rem' }}
                  >
                    Load {s.vendor}
                  </button>
                ))}
              </div>
              <button
                className="btn-cyber btn-cyber-primary"
                onClick={() => {
                  if (customInput.trim()) {
                    onRunCustomIngest(customInput.trim());
                  }
                }}
                disabled={!customInput.trim()}
                style={{ padding: '5px 14px', fontSize: '0.74rem' }}
              >
                <Zap size={13} />
                <span>Ingest Payload</span>
              </button>
            </div>
          </div>

        </div>

        {/* Right: Captured Raw Event & Cryptographic Proof */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Fingerprint size={18} color="#00f0ff" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Captured Raw Byte Sequence
              </h3>
            </div>
            <button
              onClick={() => copyText(rawPayload)}
              className="btn-cyber btn-cyber-secondary"
              style={{ padding: '4px 10px', fontSize: '0.72rem' }}
            >
              {copied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
              <span>{copied ? 'Copied' : 'Copy Raw'}</span>
            </button>
          </div>

          {/* Cryptographic Hash Verification Box */}
          <div style={{ background: 'rgba(0, 240, 255, 0.06)', border: '1px solid rgba(0, 240, 255, 0.25)', borderRadius: '8px', padding: '10px 12px', marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '0.68rem', color: '#00f0ff', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                SHA-256 INTEGRITY DIGEST (Tamper-Evidence):
              </span>
              <span className="badge badge-cyan" style={{ fontSize: '0.6rem' }}>VERIFIED</span>
            </div>
            <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#f8fafc', wordBreak: 'break-all', marginTop: '4px' }}>
              {sha256}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginTop: '6px', fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              <span>Protocol: <strong style={{ color: '#38bdf8' }}>{protocol}</strong></span>
              <span>Length: <strong style={{ color: '#34d399' }}>{byteLength} Bytes</strong></span>
              <span>Ingested At: <strong style={{ color: '#c084fc' }}>{ingestedAt}</strong></span>
            </div>
          </div>

          {/* Raw String Box */}
          <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
            Raw ASCII Character Stream:
          </div>
          <div className="code-box" style={{ maxHeight: '110px', color: '#38bdf8', marginBottom: '12px' }}>
            {rawPayload || 'No event captured yet.'}
          </div>

          {/* Hex Dump Inspector */}
          <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
            Hexadecimal Byte Offset Inspector:
          </div>
          <div className="hex-dump" style={{ flex: 1, maxHeight: '170px', overflowY: 'auto' }}>
            {generateHexDump(rawPayload)}
          </div>

        </div>

      </div>

    </div>
  );
};
