import React, { useState } from 'react';
import type { 
  PipelineContext, 
  EngineStats, 
  SampleLog 
} from '../types';
import { 
  Cpu, 
  ArrowLeft, 
  CheckCircle2, 
  Layers, 
  Clock, 
  Search, 
  Check, 
  Copy, 
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
  onSelectSample,
}) => {
  const [copied, setCopied] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  const copyJson = (obj: any) => {
    navigator.clipboard.writeText(JSON.stringify(obj, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const parsedEvent = context?.parsed_event;
  const rawPayload = context?.raw_event?.raw.payload || '';
  const parserName = parsedEvent?.parser_name || 'cisco_asa';
  const vendor = parsedEvent?.parser_vendor || 'Cisco';
  const product = parsedEvent?.parser_product || 'ASA Firewall';
  const confidence = parsedEvent ? (parsedEvent.confidence_score * 100).toFixed(0) : '100';
  const fields = parsedEvent?.extracted_fields || {};
  const tokens = parsedEvent?.tokens || [];
  const durationUs = parsedEvent?.parsing_duration_us || 42;

  // The 9 Built-in Plug-and-Play Parsers in ULPF
  const REGISTERED_PARSERS = [
    { id: 'cisco_asa', name: 'Cisco ASA Syslog Parser', vendor: 'Cisco Systems', dialect: 'Syslog / ASA-4-*', priority: 1, sample: 'cisco_asa_smb_sweep' },
    { id: 'palo_alto_panos', name: 'Palo Alto PAN-OS CSV Parser', vendor: 'Palo Alto Networks', dialect: 'CSV / TRAFFIC,THREAT', priority: 2, sample: 'palo_alto_ssh_brute' },
    { id: 'suricata_eve', name: 'Suricata EVE JSON Parser', vendor: 'OISF Suricata', dialect: 'JSON / eve.json', priority: 3, sample: 'suricata_dns_tunnel' },
    { id: 'zeek_conn', name: 'Zeek Connection TSV Parser', vendor: 'Zeek / Corelight', dialect: 'TSV / conn.log', priority: 4, sample: 'zeek_conn_sweep' },
    { id: 'aws_vpc_flow', name: 'AWS VPC Flow Logs Parser', vendor: 'Amazon Web Services', dialect: 'Space-Delimited / v2', priority: 5, sample: 'aws_vpc_flow_egress' },
    { id: 'cef', name: 'Common Event Format (CEF) Parser', vendor: 'ArcSight / Standard', dialect: 'CEF:0|Vendor|...', priority: 6, sample: 'cef_checkpoint_fw' },
    { id: 'key_value', name: 'Generic Key=Value Parser', vendor: 'Generic / Multi-Vendor', dialect: 'k1=v1 k2="v2"', priority: 7, sample: 'fortinet_kv_traffic' },
    { id: 'syslog_rfc3164', name: 'BSD Syslog RFC 3164 Parser', vendor: 'IETF RFC Standard', dialect: '<PRI>Timestamp Host Tag', priority: 8, sample: 'iptables_drop' },
    { id: 'windows_security_event', name: 'Windows Security XML Parser', vendor: 'Microsoft Windows', dialect: 'XML / EventID 4624/4625', priority: 9, sample: 'windows_rdp_brute' },
  ];

  const filteredFields = Object.entries(fields).filter(([k, v]) => 
    k.toLowerCase().includes(searchTerm.toLowerCase()) || 
    String(v).toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Header Bar */}
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
              <span className="badge badge-purple" style={{ fontSize: '0.72rem' }}>STAGE 02</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Parser & AST Extraction Dashboard
              </h2>
            </div>
            <p style={{ fontSize: '0.74rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
              Heterogeneous Dialect Recognition, Token AST Disassembly, and Plug-and-Play Registry
            </p>
          </div>
        </div>

        {/* Visual Flow Path */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(15, 23, 42, 0.7)', padding: '6px 14px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <span style={{ fontSize: '0.72rem', color: '#00f0ff', fontFamily: 'var(--font-mono)' }}>RAW LOG</span>
          <span style={{ color: '#64748b' }}>➔</span>
          <span style={{ fontSize: '0.72rem', color: '#c084fc', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>[02] PARSER AST</span>
          <span style={{ color: '#64748b' }}>➔</span>
          <span style={{ fontSize: '0.72rem', color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>STRUCTURED FIELDS</span>
        </div>
      </div>

      {/* Top 4 Metrics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        
        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Selected Parser</span>
            <Cpu size={16} color="#c084fc" />
          </div>
          <div style={{ fontSize: '1.25rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#c084fc', margin: '4px 0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {parserName}
          </div>
          <div style={{ fontSize: '0.68rem', color: '#e2e8f0', fontFamily: 'var(--font-mono)' }}>
            Vendor: {vendor} ({product})
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Confidence Score</span>
            <CheckCircle2 size={16} color="#10b981" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#10b981', margin: '4px 0' }}>
            {confidence}% MATCH
          </div>
          <div style={{ fontSize: '0.68rem', color: '#34d399', fontFamily: 'var(--font-mono)' }}>
            Deterministic Signature & AST Match
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Extracted Fields</span>
            <Layers size={16} color="#38bdf8" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#f8fafc', margin: '4px 0' }}>
            {Object.keys(fields).length} Keys
          </div>
          <div style={{ fontSize: '0.68rem', color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>
            {tokens.length} AST Tokens Disassembled
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>Parsing Duration</span>
            <Clock size={16} color="#fbbf24" />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'var(--font-mono)', color: '#fbbf24', margin: '4px 0' }}>
            {durationUs} µs
          </div>
          <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
            Compiled Lexer / Token AST Speed
          </div>
        </div>

      </div>

      {/* Main Parser Workspace: Left Extracted Fields Matrix, Right Parser Registry */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: '20px' }}>
        
        {/* Left: Raw Input vs Extracted Fields Matrix */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          {/* Raw Input Box */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <span style={{ fontSize: '0.74rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: '#00f0ff' }}>
                RAW LOG INPUT TO PARSER:
              </span>
              <span style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                {rawPayload.length} bytes
              </span>
            </div>
            <div className="code-box" style={{ maxHeight: '80px', color: '#38bdf8' }}>
              {rawPayload || 'No event currently loaded in pipeline.'}
            </div>
          </div>

          {/* Extracted Fields Table */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '0.82rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                  Extracted Intermediate Field Matrix ({Object.keys(fields).length})
                </span>
                <span className="badge badge-purple" style={{ fontSize: '0.62rem' }}>PARSED AST</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {/* Search in fields */}
                <div style={{ display: 'flex', alignItems: 'center', background: '#040813', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '6px', padding: '2px 8px' }}>
                  <Search size={12} color="#64748b" />
                  <input
                    type="text"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    placeholder="Filter keys/values..."
                    style={{ background: 'transparent', border: 'none', color: '#e2e8f0', fontSize: '0.72rem', fontFamily: 'var(--font-mono)', padding: '3px 6px', width: '130px', outline: 'none' }}
                  />
                </div>

                <button
                  onClick={() => copyJson(fields)}
                  className="btn-cyber btn-cyber-secondary"
                  style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                >
                  {copied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                  <span>Copy JSON</span>
                </button>
              </div>
            </div>

            {/* Grid of Key-Value Tokens */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '8px', maxHeight: '340px', overflowY: 'auto' }}>
              {filteredFields.map(([k, v]) => (
                <div
                  key={k}
                  style={{
                    background: 'rgba(15, 23, 42, 0.75)',
                    padding: '8px 12px',
                    borderRadius: '8px',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '3px' }}>
                    <span style={{ color: '#c084fc', fontSize: '0.7rem', fontWeight: 600 }}>{k}</span>
                    <span style={{ fontSize: '0.6rem', color: '#64748b' }}>
                      {typeof v === 'number' ? 'INTEGER' : typeof v === 'boolean' ? 'BOOLEAN' : 'STRING'}
                    </span>
                  </div>
                  <div style={{ color: '#f8fafc', fontSize: '0.75rem', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={String(v)}>
                    {String(v)}
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* Right: Plug-and-Play Parser Registry */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Cpu size={18} color="#c084fc" />
              <h3 style={{ fontSize: '0.98rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                Parser Registry Directory
              </h3>
            </div>
            <span className="badge badge-purple" style={{ fontSize: '0.62rem' }}>9 PARSERS</span>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '480px' }}>
            {REGISTERED_PARSERS.map((reg) => {
              const isCurrent = parserName === reg.id;
              return (
                <div
                  key={reg.id}
                  style={{
                    background: isCurrent ? 'rgba(168, 85, 247, 0.15)' : 'rgba(15, 23, 42, 0.65)',
                    border: `1px solid ${isCurrent ? 'rgba(168, 85, 247, 0.5)' : 'rgba(255, 255, 255, 0.05)'}`,
                    borderRadius: '8px',
                    padding: '10px 12px',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ fontSize: '0.78rem', fontWeight: 700, color: isCurrent ? '#c084fc' : '#f8fafc', fontFamily: 'var(--font-mono)' }}>
                      {reg.name}
                    </span>
                    {isCurrent && (
                      <span className="badge badge-purple" style={{ fontSize: '0.58rem' }}>ACTIVE</span>
                    )}
                  </div>

                  <div style={{ fontSize: '0.68rem', color: '#94a3b8', fontFamily: 'var(--font-mono)', marginBottom: '6px' }}>
                    Vendor: {reg.vendor} • {reg.dialect}
                  </div>

                  <button
                    onClick={() => onSelectSample(reg.sample)}
                    className="btn-cyber btn-cyber-secondary"
                    style={{ padding: '3px 8px', fontSize: '0.66rem', width: '100%', justifyContent: 'center' }}
                  >
                    <span>Test With {reg.vendor.split(' ')[0]} Sample</span>
                  </button>
                </div>
              );
            })}
          </div>

        </div>

      </div>

    </div>
  );
};
