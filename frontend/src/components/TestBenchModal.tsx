import React, { useState } from 'react';
import { Terminal, X, Play, Zap } from 'lucide-react';
import type { SampleLog } from '../types';

interface TestBenchModalProps {
  isOpen: boolean;
  onClose: () => void;
  onRunCustom: (rawText: string, explicitParser?: string) => void;
  onStreamCustom: (rawText: string) => void;
  samples: SampleLog[];
}

export const TestBenchModal: React.FC<TestBenchModalProps> = ({
  isOpen,
  onClose,
  onRunCustom,
  onStreamCustom,
  samples,
}) => {
  const [rawInput, setRawInput] = useState<string>(
    "%ASA-4-106023: Deny tcp src outside:198.51.100.99/50123 dst inside:10.0.0.5/445 by access-group 'OUTSIDE-IN' [0x0, 0x0]"
  );
  const [explicitParser, setExplicitParser] = useState<string>('auto');

  if (!isOpen) return null;

  const loadSample = (sample: SampleLog) => {
    setRawInput(sample.raw);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div 
        className="panel-machined"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '720px',
          padding: '20px',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid var(--hairline)', paddingBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Terminal size={16} color="var(--phosphor-amber)" />
            <h3 style={{ fontSize: '0.95rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
              INGESTION TEST BENCH
            </h3>
          </div>
          <button 
            onClick={onClose}
            className="btn-instrument"
            style={{ padding: '3px 6px' }}
          >
            <X size={12} />
          </button>
        </div>

        {/* Sample Presets Strip */}
        <div style={{ marginBottom: '12px' }}>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)', marginBottom: '4px' }}>
            LOAD PRESET TELEMETRY LOG:
          </div>
          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
            {samples.map((s) => (
              <button
                key={s.id}
                onClick={() => loadSample(s)}
                className="btn-instrument"
                style={{ padding: '3px 6px', fontSize: '0.66rem' }}
              >
                {s.vendor} • {s.title}
              </button>
            ))}
          </div>
        </div>

        {/* Raw Log Input Area */}
        <div style={{ marginBottom: '12px' }}>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)', marginBottom: '4px' }}>
            RAW LOG PAYLOAD:
          </div>
          <textarea
            value={rawInput}
            onChange={(e) => setRawInput(e.target.value)}
            rows={5}
            style={{
              width: '100%',
              background: 'var(--panel-sunken)',
              border: '1px solid var(--hairline)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-high)',
              fontFamily: 'var(--font-readout)',
              fontSize: '0.74rem',
              padding: '8px',
              outline: 'none',
              resize: 'vertical',
            }}
          />
        </div>

        {/* Parser Selection & Run Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span className="readout" style={{ fontSize: '0.68rem', color: 'var(--text-low)' }}>DIALECT PARSER:</span>
            <select
              value={explicitParser}
              onChange={(e) => setExplicitParser(e.target.value)}
              style={{
                background: 'var(--panel-sunken)',
                border: '1px solid var(--hairline)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-high)',
                fontFamily: 'var(--font-readout)',
                fontSize: '0.72rem',
                padding: '4px 8px',
                outline: 'none',
              }}
            >
              <option value="auto">Auto-Detect Dialect</option>
              <option value="cisco_asa">Cisco ASA Syslog</option>
              <option value="palo_alto_panos">Palo Alto PAN-OS CSV</option>
              <option value="suricata_eve">Suricata EVE JSON</option>
              <option value="zeek_conn">Zeek Connection TSV</option>
              <option value="aws_vpc_flow">AWS VPC Flow Logs</option>
              <option value="cef">ArcSight CEF</option>
              <option value="key_value">Generic Key=Value</option>
              <option value="syslog_rfc3164">BSD Syslog RFC 3164</option>
              <option value="windows_security_event">Windows Event XML</option>
            </select>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={() => onStreamCustom(rawInput)}
              className="btn-instrument"
            >
              <Play size={11} />
              <span>Stream Live</span>
            </button>

            <button
              onClick={() => onRunCustom(rawInput, explicitParser === 'auto' ? undefined : explicitParser)}
              className="btn-instrument btn-instrument-primary"
            >
              <Zap size={11} />
              <span>Process Event</span>
            </button>
          </div>

        </div>

      </div>
    </div>
  );
};
