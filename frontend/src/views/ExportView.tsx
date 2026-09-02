import React, { useState } from 'react';
import type { 
  PipelineContext, 
  EngineStats, 
  ExportSchemas 
} from '../types';
import { 
  ArrowLeft, 
  Download, 
  Copy, 
  Check
} from 'lucide-react';

interface ExportViewProps {
  context: PipelineContext | null;
  stats: EngineStats | null;
  exports: ExportSchemas | null;
  onBackToOverview: () => void;
}

export const ExportView: React.FC<ExportViewProps> = ({
  context,
  stats: _stats,
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

  const EXPORT_DESTINATIONS = [
    { id: 'ulpf', name: 'ULPF Canonical', schema: 'Zero-Loss Canonical JSON', target: 'Native Storage Bus' },
    { id: 'elastic', name: 'Elastic ECS 8.11', schema: '@timestamp / ECS Schema', target: 'Elasticsearch / Logstash' },
    { id: 'splunk', name: 'Splunk HEC', schema: 'Splunk Event Envelope', target: 'HTTP Event Collector' },
    { id: 'ocsf', name: 'OCSF 1.9.0.0', schema: 'Open Cybersecurity Schema', target: 'AWS Security Lake' },
    { id: 'parquet', name: 'Columnar Flat', schema: 'Flattened Key-Value Row', target: 'S3 / Athena / Iceberg' },
  ];

  const getPayloadForFormat = () => {
    if (!exports) return finalEvent ? finalEvent : { message: 'Awaiting event completion to generate exports' };
    switch (selectedFormat) {
      case 'ulpf': return exports.ulpf_standard || finalEvent;
      case 'elastic': return exports.elastic_ecs;
      case 'splunk': return exports.splunk_hec;
      case 'ocsf': return exports.ocsf_1_9_0;
      case 'parquet': return exports.columnar_flat;
      default: return exports.ulpf_standard;
    }
  };

  const currentPayload = getPayloadForFormat();

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
            <span className="badge-inst badge-amber">STAGE [07]</span>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 700, fontFamily: 'var(--font-chrome)', color: 'var(--text-high)' }}>
              SIEM & Data Lake Exporters
            </h2>
          </div>
        </div>

        <div className="readout" style={{ fontSize: '0.74rem', color: 'var(--confirm-moss)' }}>
          4 PRODUCTION FORMATS GENERATED
        </div>
      </div>

      {/* Main Grid: Left Format Selector, Right Schema Preview */}
      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '12px' }}>
        
        {/* Left: Destination List */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              EXPORT TARGET SCHEMAS
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {EXPORT_DESTINATIONS.map((dest) => {
              const isSelected = selectedFormat === dest.id;
              return (
                <div
                  key={dest.id}
                  onClick={() => setSelectedFormat(dest.id as any)}
                  style={{
                    background: isSelected ? 'var(--phosphor-amber-dim)' : 'var(--panel-sunken)',
                    border: `1px solid ${isSelected ? 'var(--phosphor-amber)' : 'var(--hairline)'}`,
                    borderRadius: 'var(--radius-sm)',
                    padding: '8px 10px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ fontSize: '0.76rem', fontWeight: isSelected ? 700 : 600, color: isSelected ? 'var(--phosphor-amber)' : 'var(--text-high)' }}>
                    {dest.name}
                  </div>
                  <div className="readout" style={{ fontSize: '0.64rem', color: 'var(--text-low)', marginTop: '2px' }}>
                    {dest.target}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Payload Readout & Action Buttons */}
        <div className="panel-machined" style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--hairline)', paddingBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-high)', fontFamily: 'var(--font-chrome)' }}>
              EXPORT PAYLOAD PREVIEW ({selectedFormat.toUpperCase()})
            </span>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <button
                onClick={() => copyText(JSON.stringify(currentPayload, null, 2))}
                className="btn-instrument"
                style={{ padding: '3px 8px', fontSize: '0.68rem' }}
              >
                {copied ? <Check size={10} color="var(--confirm-moss)" /> : <Copy size={10} />}
                <span>Copy JSON</span>
              </button>

              <button
                onClick={() => downloadJson(currentPayload, `ulpf_export_${selectedFormat}.json`)}
                className="btn-instrument btn-instrument-primary"
                style={{ padding: '3px 8px', fontSize: '0.68rem' }}
              >
                <Download size={10} />
                <span>Download</span>
              </button>
            </div>
          </div>

          <div className="readout-box" style={{ minHeight: '380px', color: 'var(--text-mid)', fontSize: '0.72rem' }}>
            {JSON.stringify(currentPayload, null, 2)}
          </div>
        </div>

      </div>

    </div>
  );
};
