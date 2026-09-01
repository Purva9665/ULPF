import React, { useState } from 'react';
import { FileCode, X, Copy, Check, Download } from 'lucide-react';
import type { ExportSchemas } from '../types';

interface ExportViewerModalProps {
  isOpen: boolean;
  onClose: () => void;
  context: any;
  exports: ExportSchemas | null;
}

export const ExportViewerModal: React.FC<ExportViewerModalProps> = ({
  isOpen,
  onClose,
  context: _context,
  exports,
}) => {
  const [activeTab, setActiveTab] = useState<'elastic' | 'splunk' | 'ocsf' | 'parquet'>('elastic');
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const currentPayload = exports
    ? activeTab === 'elastic'
      ? exports.elastic_ecs
      : activeTab === 'splunk'
      ? exports.splunk_hec
      : activeTab === 'ocsf'
      ? exports.ocsf_v1
      : exports.columnar_flat
    : { message: 'Run an event through the ULPF pipeline to generate SIEM export envelopes' };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(JSON.stringify(currentPayload, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(currentPayload, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `ulpf_export_${activeTab}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div 
        className="glass-panel"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '850px',
          maxHeight: '88vh',
          display: 'flex',
          flexDirection: 'column',
          padding: '24px',
          borderRadius: '12px',
          boxShadow: '0 0 40px rgba(59, 130, 246, 0.3)',
          border: '1px solid rgba(59, 130, 246, 0.4)',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <FileCode size={22} color="#3b82f6" />
            <div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, fontFamily: 'var(--font-display)', color: '#f8fafc' }}>
                SIEM & Data Lake Standard Exporter
              </h3>
              <p style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                Production-Ready Envelopes for Splunk, Elastic, OCSF v1.1 & Parquet Data Lakes
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button className="btn-cyber btn-cyber-secondary" onClick={copyToClipboard} style={{ fontSize: '0.75rem', padding: '4px 10px' }}>
              {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
            <button className="btn-cyber btn-cyber-secondary" onClick={downloadJSON} style={{ fontSize: '0.75rem', padding: '4px 10px' }}>
              <Download size={14} />
              <span>Download</span>
            </button>
            <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '4px' }}>
              <X size={20} />
            </button>
          </div>
        </div>

        {/* Format Selector Tabs */}
        <div style={{ display: 'flex', gap: '8px', marginBottom: '14px', flexWrap: 'wrap' }}>
          <button
            className={`btn-cyber ${activeTab === 'elastic' ? 'btn-cyber-primary' : 'btn-cyber-secondary'}`}
            onClick={() => setActiveTab('elastic')}
            style={{ fontSize: '0.75rem', padding: '6px 12px' }}
          >
            Elastic Common Schema (ECS 8.x)
          </button>

          <button
            className={`btn-cyber ${activeTab === 'splunk' ? 'btn-cyber-primary' : 'btn-cyber-secondary'}`}
            onClick={() => setActiveTab('splunk')}
            style={{ fontSize: '0.75rem', padding: '6px 12px' }}
          >
            Splunk HTTP Event Collector (HEC)
          </button>

          <button
            className={`btn-cyber ${activeTab === 'ocsf' ? 'btn-cyber-primary' : 'btn-cyber-secondary'}`}
            onClick={() => setActiveTab('ocsf')}
            style={{ fontSize: '0.75rem', padding: '6px 12px' }}
          >
            OCSF v1.1 (Open Cybersecurity Schema)
          </button>

          <button
            className={`btn-cyber ${activeTab === 'parquet' ? 'btn-cyber-primary' : 'btn-cyber-secondary'}`}
            onClick={() => setActiveTab('parquet')}
            style={{ fontSize: '0.75rem', padding: '6px 12px' }}
          >
            Parquet / DuckDB Columnar Flat
          </button>
        </div>

        {/* Code Content */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          <pre className="code-box" style={{ minHeight: '340px' }}>
            {JSON.stringify(currentPayload, null, 2)}
          </pre>
        </div>

      </div>
    </div>
  );
};
