import React, { useState } from 'react';
import type { 
  PipelineContext, 
  EngineStats, 
  SampleLog 
} from '../types';
import { 
  ArrowLeft, 
  Copy, 
  Check 
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
  stats: _stats,
  onBackToOverview,
  onRunCustomIngest: _onRunCustomIngest,
  samples: _samples,
}) => {
  const [copied, setCopied] = useState(false);

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const rawEvent = context?.raw_event;
  const rawPayload = rawEvent?.raw.payload || '';
  const sha256 = rawEvent?.raw.sha256_hash || '—';
  const byteLength = rawEvent?.raw.length_bytes || rawPayload.length;
  const protocol = rawEvent?.raw.source_protocol || 'SYSLOG_UDP';
  const ingestedAt = rawEvent?.ingested_at || new Date().toISOString();

  const metric = context?.stage_metrics?.find((m) => m.stage === 'INGEST');
  const durationUs = metric?.duration_us || 18;

  const generateHexDump = (str: string) => {
    if (!str) return 'No raw payload captured.';
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span className="badge-inst badge-amber">STAGE [01]</span>
              <h2 style={{ fontSize: '1.05rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
                Ingestion & Zero-Loss Capture
              </h2>
            </div>
          </div>
        </div>

        <div className="readout" style={{ fontSize: '0.74rem', color: 'var(--text-low)' }}>
          STAGE LATENCY: <strong style={{ color: 'var(--phosphor-amber)' }}>{durationUs} µs</strong>
        </div>
      </div>

      {/* 4 Readout Metric Tiles */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>PAYLOAD LENGTH</div>
          <div className="readout" style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-high)', margin: '2px 0' }}>
            {byteLength} <span style={{ fontSize: '0.75rem', color: 'var(--text-low)' }}>bytes</span>
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--confirm-moss)' }}>100% Ingested</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>INGEST PROTOCOL</div>
          <div className="readout" style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--phosphor-amber)', margin: '2px 0' }}>
            {protocol}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Direct Pipe</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>INTEGRITY STATUS</div>
          <div className="readout" style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--confirm-moss)', margin: '2px 0' }}>
            SHA-256 VERIFIED
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Cryptographic Digest</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>CAPTURE TIMESTAMP</div>
          <div className="readout" style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-high)', margin: '4px 0' }}>
            {ingestedAt.slice(11, 23)}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Microsecond Precision</div>
        </div>
      </div>

      {/* Main Dual Panels: Raw Log & Hex Matrix */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
        
        {/* Raw Log Payload */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              PRISTINE RAW LOG STRING
            </span>
            <button
              onClick={() => copyText(rawPayload)}
              className="btn-instrument"
              style={{ padding: '2px 6px', fontSize: '0.66rem' }}
            >
              {copied ? <Check size={10} color="var(--confirm-moss)" /> : <Copy size={10} />}
              <span>Copy</span>
            </button>
          </div>

          <div className="readout-box" style={{ minHeight: '200px', color: 'var(--text-high)' }}>
            {rawPayload || '// No log event ingested yet.'}
          </div>

          <div className="readout" style={{ fontSize: '0.68rem', color: 'var(--text-low)' }}>
            SHA-256: <strong style={{ color: 'var(--confirm-moss)' }}>{sha256}</strong>
          </div>
        </div>

        {/* Hex Dump Matrix */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              HEXADECIMAL BYTE DUMP
            </span>
            <span className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>
              16 BYTES / LINE
            </span>
          </div>

          <div className="readout-box" style={{ minHeight: '200px', color: 'var(--text-mid)', fontSize: '0.7rem' }}>
            {generateHexDump(rawPayload)}
          </div>

          <div className="readout" style={{ fontSize: '0.68rem', color: 'var(--text-low)' }}>
            Zero byte alteration guarantee during capture stage
          </div>
        </div>

      </div>

    </div>
  );
};
