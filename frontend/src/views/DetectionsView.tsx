/**
 * DetectionsView - the product's home screen.
 *
 * Everything else in this app reports on events the pipeline processed. This
 * reports on findings an analyst works: one row per detection, not one per
 * scored event. A port scan is one row here, not five thousand.
 *
 * Deliberately plain. Three panes, no animation, no gradients: a queue, the
 * selected detection's evidence, and a volume summary. An analyst reading this
 * under pressure needs to answer "what happened, why do you think so, what do I
 * do" without hunting.
 */

import React, { useEffect, useState, useCallback } from 'react';
import {
  fetchDetections, fetchDetectionDetail, fetchDetectionSummary,
  replaySamplesIntoDetections, triageDetection,
  type DetectionSummary, type DetectionRow, type DetectionDetail,
} from '../api';

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--red)',
  high: 'var(--amber)',
  medium: 'var(--cyan)',
  low: 'var(--slate)',
};

const STATES = [
  { value: 'investigating', label: 'Investigating' },
  { value: 'resolved_true_positive', label: 'Confirmed' },
  { value: 'resolved_false_positive', label: 'False positive' },
];

export const DetectionsView: React.FC = () => {
  const [summary, setSummary] = useState<DetectionSummary | null>(null);
  const [rows, setRows] = useState<DetectionRow[]>([]);
  const [selected, setSelected] = useState<DetectionDetail | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    const [s, d] = await Promise.all([
      fetchDetectionSummary(), fetchDetections(100),
    ]);
    setSummary(s);
    setRows(d.detections);
    return d.detections;
  }, []);

  useEffect(() => { refresh().catch(() => {}); }, [refresh]);

  const select = async (id: string) => {
    try { setSelected(await fetchDetectionDetail(id)); } catch { /* ignore */ }
  };

  const runSamples = async () => {
    setBusy(true);
    try {
      await replaySamplesIntoDetections();
      const list = await refresh();
      if (list.length) await select(list[0].detection_id);
    } finally { setBusy(false); }
  };

  const triage = async (state: string) => {
    if (!selected) return;
    await triageDetection(selected.detection_id, state);
    await refresh();
    await select(selected.detection_id);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Volume summary - the number that says whether this queue is workable */}
      <div className="glass-panel" style={{ padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between',
                      alignItems: 'center', marginBottom: 12 }}>
          <div className="section-label">Detection summary</div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {summary && (
              <span className={`badge ${summary.mode === 'trained' ? 'badge-green' : 'badge-amber'}`}>
                {summary.mode === 'trained' ? 'TRAINED MODEL' : 'HEURISTIC (no model)'}
              </span>
            )}
            <button className="btn-cyber btn-cyber-primary" onClick={runSamples} disabled={busy}>
              {busy ? 'Running...' : 'Run sample logs'}
            </button>
          </div>
        </div>
        {/* Three numbers, not five. The question this screen answers is
            "how big is my queue and is it workable" - everything else is
            available in the detail pane or the API. */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
          <Stat label="Open detections" value={summary?.detections_open ?? 0} />
          <Stat label="Events processed" value={summary?.events_seen ?? 0} />
          <Stat label="Events per detection" value={summary?.events_per_detection ?? 0} />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1fr', gap: 16,
                    alignItems: 'start' }}>
        {/* Queue */}
        <div className="glass-panel" style={{ padding: 16 }}>
          <div className="section-label" style={{ marginBottom: 10 }}>
            Detection queue ({rows.length})
          </div>
          {rows.length === 0 && (
            <div style={{ color: 'var(--slate)', fontSize: 13, padding: '18px 0' }}>
              No detections yet. Click <strong>Run sample logs</strong> to push the
              bundled sample events through the detection stack.
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6,
                        maxHeight: 460, overflowY: 'auto' }}>
            {rows.map(r => (
              <button
                key={r.detection_id}
                onClick={() => select(r.detection_id)}
                style={{
                  textAlign: 'left', cursor: 'pointer', padding: '10px 12px',
                  background: selected?.detection_id === r.detection_id
                    ? 'var(--bg-tertiary)' : 'transparent',
                  border: '1px solid var(--border-subtle)', borderRadius: 6,
                  borderLeft: `3px solid ${SEVERITY_COLOR[r.severity] || 'var(--slate)'}`,
                  color: 'inherit', font: 'inherit',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                  <span style={{ fontWeight: 600, fontSize: 13 }}>{r.title}</span>
                  <span style={{ color: SEVERITY_COLOR[r.severity], fontSize: 11,
                                 textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
                    {r.severity}
                  </span>
                </div>
                <div style={{ color: 'var(--slate)', fontSize: 11, marginTop: 4,
                              fontFamily: 'var(--font-mono)' }}>
                  {(r.confidence * 100).toFixed(0)}% confidence · {r.event_count} event
                  {r.event_count === 1 ? '' : 's'} · {r.threat_class}
                  {r.evidence_degraded && ' · EVIDENCE DEGRADED'}
                  {r.state !== 'new' && ` · ${r.state.replace(/_/g, ' ')}`}
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Detail: why we think so, and what to do */}
        <div className="glass-panel" style={{ padding: 16, minHeight: 300 }}>
          <div className="section-label" style={{ marginBottom: 10 }}>
            {selected ? 'Why this was flagged' : 'Select a detection'}
          </div>
          {!selected && (
            <div style={{ color: 'var(--slate)', fontSize: 13 }}>
              Pick a detection to see the evidence behind it.
            </div>
          )}
          {selected && (
            <>
              <div style={{ fontWeight: 600, marginBottom: 6 }}>{selected.title}</div>
              <div style={{ color: 'var(--slate)', fontSize: 12, marginBottom: 12,
                            fontFamily: 'var(--font-mono)' }}>
                {selected.entity} · {selected.event_count} events ·{' '}
                {selected.mitre_techniques.length > 0
                  ? `MITRE ${selected.mitre_techniques.join(', ')}` : 'no MITRE mapping'}
              </div>

              {selected.evidence_degraded && (
                <div className="badge badge-amber" style={{ marginBottom: 10 }}>
                  Evidence degraded - some fields parsed with low confidence
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6,
                            marginBottom: 14 }}>
                {selected.evidence.slice(0, 6).map((e, i) => (
                  <div key={i} style={{ fontSize: 12, display: 'flex', gap: 8 }}>
                    <span style={{
                      fontFamily: 'var(--font-mono)', fontSize: 11, minWidth: 46,
                      color: e.weight < 0 ? 'var(--emerald)' : 'var(--amber)',
                    }}>
                      {e.weight > 0 ? '+' : ''}{e.weight.toFixed(2)}
                    </span>
                    <span>{e.argues}</span>
                  </div>
                ))}
              </div>

              <div className="section-label" style={{ marginBottom: 6 }}>
                Contributing events
              </div>
              <div style={{ maxHeight: 130, overflowY: 'auto', marginBottom: 14 }}>
                {selected.events.slice(0, 8).map(ev => (
                  <div key={ev.event_id} style={{
                    fontFamily: 'var(--font-mono)', fontSize: 10.5,
                    color: 'var(--slate)', padding: '3px 0',
                  }}>
                    {ev.src_ip} → {ev.dst_ip}:{ev.dst_port} · sha256 {ev.raw_sha256.slice(0, 16)}…
                  </div>
                ))}
              </div>

              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {STATES.map(s => (
                  <button key={s.value} className="btn-cyber btn-cyber-secondary"
                          onClick={() => triage(s.value)}
                          style={{ fontSize: 11 }}>
                    {s.label}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

    </div>
  );
};

const Stat: React.FC<{ label: string; value: number }> = ({ label, value }) => (
  <div>
    <div style={{ fontSize: 22, fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
      {value.toLocaleString()}
    </div>
    <div style={{ fontSize: 11, color: 'var(--slate)' }}>{label}</div>
  </div>
);
