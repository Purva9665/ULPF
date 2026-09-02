import React, { useState } from 'react';
import { X, Copy, Check, Download } from 'lucide-react';
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
      ? exports.ocsf_1_9_0
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
    <div className="modal-overlay" onClick={onClose}>
      <div 
        className="panel-machined"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: '780px',
          maxHeight: '85vh',
          display: 'flex',
          flexDirection: 'column',
          padding: '20px',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
          <div>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
              SIEM & DATA LAKE EXPORT GATEWAY
            </h3>
            <div className="readout" style={{ fontSize: '0.66rem', color: 'var(--text-low)', marginTop: '2px' }}>
              Standardized Schema Payloads
            </div>
          </div>
          <button 
            onClick={onClose}
            className="btn-instrument"
            style={{ padding: '3px 6px' }}
          >
            <X size={12} />
          </button>
        </div>

        {/* Tab Selection Strip */}
        <div style={{ display: 'flex', gap: '4px', marginBottom: '10px' }}>
          {[
            { id: 'elastic', label: 'Elastic ECS 8.11' },
            { id: 'splunk', label: 'Splunk HEC JSON' },
            { id: 'ocsf', label: 'OCSF 1.9.0.0' },
            { id: 'parquet', label: 'Columnar Flat JSON' },
          ].map((tab) => {
            const isTabActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                style={{
                  background: isTabActive ? 'var(--phosphor-amber-dim)' : 'var(--panel-sunken)',
                  color: isTabActive ? 'var(--phosphor-amber)' : 'var(--text-mid)',
                  border: `1px solid ${isTabActive ? 'var(--phosphor-amber)' : 'var(--hairline)'}`,
                  borderRadius: 'var(--radius-sm)',
                  padding: '4px 10px',
                  fontSize: '0.72rem',
                  fontFamily: 'var(--font-readout)',
                  fontWeight: isTabActive ? 600 : 500,
                  cursor: 'pointer',
                }}
              >
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Code Content */}
        <div className="readout-box" style={{ flex: 1, maxHeight: '380px', color: 'var(--text-mid)', fontSize: '0.72rem' }}>
          {JSON.stringify(currentPayload, null, 2)}
        </div>

        {/* Footer Actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '12px', borderTop: '1px solid var(--hairline)', paddingTop: '10px' }}>
          <button 
            onClick={copyToClipboard}
            className="btn-instrument"
          >
            {copied ? <Check size={11} color="var(--confirm-moss)" /> : <Copy size={11} />}
            <span>Copy</span>
          </button>
          
          <button 
            onClick={downloadJSON}
            className="btn-instrument btn-instrument-primary"
          >
            <Download size={11} />
            <span>Download</span>
          </button>
        </div>

      </div>
    </div>
  );
};
