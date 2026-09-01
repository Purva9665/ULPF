import React, { useState } from 'react';
import { Terminal, X, Play, Sparkles } from 'lucide-react';
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
    <div className="modal-backdrop" onClick={onClose}>
      <div 
        className="glass-panel"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '750px',
          padding: '24px',
          borderRadius: '12px',
          boxShadow: '0 0 40px rgba(0, 240, 255, 0.2)',
          border: '1px solid rgba(0, 240, 255, 0.4)',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ width: '32px', height: '32px', borderRadius: '6px', background: 'rgba(0, 240, 255, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Terminal size={18} color="#00f0ff" />
            </div>
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                ULPF Ingestion Test Bench
              </h3>
              <p style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                Inject and test arbitrary heterogeneous perimeter firewall and security logs
              </p>
            </div>
          </div>
          <button 
            onClick={onClose}
            style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '4px' }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Quick Presets */}
        <div style={{ marginBottom: '14px' }}>
          <span style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: '6px' }}>
            Quick Load Authentic Attack & Traffic Samples:
          </span>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {samples.slice(0, 6).map((s) => (
              <button
                key={s.id}
                onClick={() => loadSample(s)}
                style={{
                  background: 'rgba(15, 23, 42, 0.8)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  color: '#cbd5e1',
                  padding: '4px 8px',
                  borderRadius: '4px',
                  fontSize: '0.7rem',
                  fontFamily: 'var(--font-mono)',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
                onMouseEnter={(e) => (e.currentTarget.style.borderColor = '#00f0ff')}
                onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.1)')}
              >
                {s.title}
              </button>
            ))}
          </div>
        </div>

        {/* Input Textarea */}
        <div style={{ marginBottom: '16px' }}>
          <span style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>
            Raw Log Payload String:
          </span>
          <textarea
            value={rawInput}
            onChange={(e) => setRawInput(e.target.value)}
            rows={5}
            style={{
              width: '100%',
              background: '#020617',
              color: '#38bdf8',
              border: '1px solid rgba(0, 240, 255, 0.25)',
              borderRadius: '8px',
              padding: '12px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.82rem',
              outline: 'none',
              resize: 'vertical',
            }}
            placeholder="Paste your raw syslog, CEF, JSON, PAN-OS CSV, or VPC flow log..."
          />
        </div>

        {/* Parser Selection */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#94a3b8' }}>Parser Dialect:</span>
            <select
              value={explicitParser}
              onChange={(e) => setExplicitParser(e.target.value)}
              style={{
                background: 'rgba(15, 23, 42, 0.9)',
                color: '#f8fafc',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                padding: '6px 12px',
                borderRadius: '6px',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.78rem',
                outline: 'none',
              }}
            >
              <option value="auto">Auto-Detect Dialect (Recommended)</option>
              <option value="cisco_asa">Cisco ASA / FTD Syslog</option>
              <option value="palo_alto_panos">Palo Alto PAN-OS CSV</option>
              <option value="suricata_eve">Suricata / Snort EVE JSON</option>
              <option value="aws_vpc_flow">AWS VPC Flow Log</option>
              <option value="zeek_network_security">Zeek (Bro) Conn / DNS TSV</option>
              <option value="arcsight_cef">ArcSight CEF</option>
              <option value="generic_keyvalue">Fortinet / Key-Value</option>
              <option value="syslog_generic">Linux Syslog / iptables / NGINX</option>
              <option value="windows_security_event">Windows Security Event</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              className="btn-cyber btn-cyber-secondary"
              onClick={() => {
                onStreamCustom(rawInput);
                onClose();
              }}
            >
              <Sparkles size={14} color="#00f0ff" />
              <span>Live Stream Event</span>
            </button>

            <button
              className="btn-cyber btn-cyber-primary"
              onClick={() => {
                onRunCustom(rawInput, explicitParser === 'auto' ? undefined : explicitParser);
                onClose();
              }}
            >
              <Play size={14} />
              <span>Run Pipeline Synchronously</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
