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

interface ParserViewProps {
  context: PipelineContext | null;
  stats?: EngineStats | null;
  onBackToOverview: () => void;
  onSelectSample: (sampleId: string) => void;
  samples?: SampleLog[];
}

export const ParserView: React.FC<ParserViewProps> = ({
  context,
  onBackToOverview,
  onSelectSample: _onSelectSample,
}) => {
  const [copied, setCopied] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  const copyJson = (obj: any) => {
    navigator.clipboard.writeText(JSON.stringify(obj, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const parsedEvent = context?.parsed_event;
  const parserName = parsedEvent?.parser_name || 'cisco_asa';
  const vendor = parsedEvent?.parser_vendor || 'Cisco';
  const product = parsedEvent?.parser_product || 'ASA Firewall';
  const confidence = parsedEvent ? (parsedEvent.confidence_score * 100).toFixed(0) : '100';
  const fields = parsedEvent?.extracted_fields || {};
  const tokens = parsedEvent?.tokens || [];
  const durationUs = parsedEvent?.parsing_duration_us || 42;

  const REGISTERED_PARSERS = [
    { id: 'cisco_asa', name: 'Cisco ASA Syslog', vendor: 'Cisco', dialect: 'ASA-4-*' },
    { id: 'palo_alto_panos', name: 'Palo Alto PAN-OS CSV', vendor: 'Palo Alto', dialect: 'CSV TRAFFIC' },
    { id: 'suricata_eve', name: 'Suricata EVE JSON', vendor: 'OISF Suricata', dialect: 'eve.json' },
    { id: 'zeek_conn', name: 'Zeek Connection TSV', vendor: 'Zeek', dialect: 'conn.log' },
    { id: 'aws_vpc_flow', name: 'AWS VPC Flow Logs', vendor: 'AWS', dialect: 'Space-Delimited' },
    { id: 'cef', name: 'ArcSight CEF', vendor: 'ArcSight', dialect: 'CEF:0|Vendor|...' },
    { id: 'key_value', name: 'Generic Key=Value', vendor: 'Multi-Vendor', dialect: 'k1=v1 k2="v2"' },
    { id: 'syslog_rfc3164', name: 'BSD Syslog RFC 3164', vendor: 'RFC Standard', dialect: '<PRI>Timestamp' },
    { id: 'windows_security_event', name: 'Windows Event XML', vendor: 'Microsoft', dialect: 'EventID 4624' },
  ];

  const filteredFields = Object.entries(fields).filter(([k, v]) => 
    k.toLowerCase().includes(searchTerm.toLowerCase()) || 
    String(v).toLowerCase().includes(searchTerm.toLowerCase())
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
            <span className="badge-inst badge-amber">STAGE [02]</span>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
              Parser & AST Token Disassembly
            </h2>
          </div>
        </div>

        <div className="readout" style={{ fontSize: '0.74rem', color: 'var(--text-low)' }}>
          STAGE LATENCY: <strong style={{ color: 'var(--phosphor-amber)' }}>{durationUs} µs</strong>
        </div>
      </div>

      {/* 4 Readout Metric Tiles */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px' }}>
        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>ACTIVE PARSER</div>
          <div className="readout" style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-high)', margin: '2px 0' }}>
            {parserName}
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--phosphor-amber)' }}>{vendor} • {product}</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>EXTRACTED FIELDS</div>
          <div className="readout" style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-high)', margin: '2px 0' }}>
            {Object.keys(fields).length} <span style={{ fontSize: '0.75rem', color: 'var(--text-low)' }}>keys</span>
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--confirm-moss)' }}>AST Dictionary</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>TOKEN COUNT</div>
          <div className="readout" style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--text-high)', margin: '2px 0' }}>
            {tokens.length} <span style={{ fontSize: '0.75rem', color: 'var(--text-low)' }}>tokens</span>
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Lexical Decomposition</div>
        </div>

        <div className="panel-machined" style={{ padding: '12px 14px' }}>
          <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>PARSER CONFIDENCE</div>
          <div className="readout" style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--confirm-moss)', margin: '2px 0' }}>
            {confidence}%
          </div>
          <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)' }}>Deterministic Match</div>
        </div>
      </div>

      {/* Main Grid: Left Extracted Fields, Right Parser Registry */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: '12px' }}>
        
        {/* Left: Extracted AST Fields Table */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              EXTRACTED AST KEY-VALUE MATRIX
            </span>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <input
                type="text"
                placeholder="Filter keys..."
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
                onClick={() => copyJson(fields)}
                className="btn-instrument"
                style={{ padding: '2px 6px', fontSize: '0.66rem' }}
              >
                {copied ? <Check size={10} color="var(--confirm-moss)" /> : <Copy size={10} />}
                <span>JSON</span>
              </button>
            </div>
          </div>

          <div style={{ overflowX: 'auto', maxHeight: '380px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontFamily: 'var(--font-readout)', fontSize: '0.72rem' }}>
              <thead>
                <tr style={{ background: 'var(--panel-sunken)', borderBottom: '1px solid var(--hairline)', color: 'var(--text-low)', textTransform: 'uppercase', fontSize: '0.64rem' }}>
                  <th style={{ padding: '6px 10px' }}>Source AST Key</th>
                  <th style={{ padding: '6px 10px' }}>Extracted Value</th>
                  <th style={{ padding: '6px 10px' }}>Inferred Type</th>
                </tr>
              </thead>
              <tbody>
                {filteredFields.map(([k, v], idx) => (
                  <tr 
                    key={k}
                    style={{ 
                      borderBottom: '1px solid var(--hairline)',
                      background: idx % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.01)'
                    }}
                  >
                    <td style={{ padding: '6px 10px', color: 'var(--phosphor-amber)', fontWeight: 600 }}>
                      {k}
                    </td>
                    <td style={{ padding: '6px 10px', color: 'var(--text-high)' }}>
                      {String(v)}
                    </td>
                    <td style={{ padding: '6px 10px', color: 'var(--text-low)' }}>
                      {typeof v === 'number' ? 'integer' : 'string'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: 9-Dialect Parser Registry */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              REGISTERED PARSER MATRIX
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {REGISTERED_PARSERS.map((p) => {
              const isMatch = p.id === parserName;
              return (
                <div
                  key={p.id}
                  style={{
                    background: isMatch ? 'var(--phosphor-amber-dim)' : 'var(--panel-sunken)',
                    border: `1px solid ${isMatch ? 'var(--phosphor-amber)' : 'var(--hairline)'}`,
                    borderRadius: 'var(--radius-sm)',
                    padding: '6px 8px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '0.74rem', fontWeight: isMatch ? 700 : 500, color: isMatch ? 'var(--phosphor-amber)' : 'var(--text-high)' }}>
                      {p.name}
                    </div>
                    <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)' }}>
                      {p.vendor} • {p.dialect}
                    </div>
                  </div>
                  {isMatch && (
                    <span className="badge-inst badge-amber" style={{ fontSize: '0.6rem' }}>
                      MATCH
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>

      </div>

    </div>
  );
};
