import React, { useState, useEffect } from 'react';
import type { SampleLog, PipelineContext, ExportSchemas } from '../types';
import { fetchSamples, processEventSync } from '../api';

/**
 * Single-screen demonstration view.
 *
 * Everything a reviewer needs to follow is visible at once, top to bottom:
 * raw event -> pipeline -> classification and the evidence behind it -> OCSF
 * output. No navigation during a two-minute walkthrough.
 *
 * The "Unknown source" entry in the left rail is the second half of the story:
 * paste a format ULPF has never seen and watch the adaptive parser infer a
 * template with no configuration.
 */

const MONO = "'SF Mono', 'Cascadia Code', Consolas, Menlo, 'Courier New', monospace";

const PIPELINE_STAGES = ['ingest', 'parse', 'normalize', 'validate', 'route'];

const UNKNOWN_PLACEHOLDER = `|MERIDIAN-IPS|4412|DROP|dmz->core|203.0.113.9%44210|10.0.7.4%445|sig-2201|SMB probe|
|MERIDIAN-IPS|4413|PASS|trust->net|10.0.7.9%51002|8.8.8.8%53|sig-0000|normal|
|MERIDIAN-IPS|4414|DROP|dmz->core|198.51.100.4%33112|10.0.7.4%3389|sig-2290|RDP probe|`;

/**
 * Rail label for a sample. Several samples share a vendor (two Cisco ASA, two
 * PAN-OS), so the vendor name alone produces duplicate entries the presenter
 * cannot tell apart. Prefer the descriptive half of the title.
 */
function shortLabel(s: SampleLog): string {
  const title = s.title || '';
  const afterColon = title.includes(':') ? title.split(':').slice(1).join(':') : title;
  const cleaned = afterColon.replace(/\s*\([^)]*\)\s*$/, '').trim();
  return cleaned || s.vendor || s.id;
}

/** Panel heading. Deliberately plain: uppercase micro-label, no icon. */
const Label: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div
    style={{
      fontSize: 10,
      letterSpacing: '0.08em',
      textTransform: 'uppercase',
      color: 'var(--slate)',
      marginBottom: 6,
    }}
  >
    {children}
  </div>
);

const Panel: React.FC<{ children: React.ReactNode; style?: React.CSSProperties }> = ({
  children,
  style,
}) => (
  <div
    style={{
      padding: '10px 12px',
      borderBottom: '1px solid var(--border-subtle)',
      ...style,
    }}
  >
    {children}
  </div>
);

export const DemoView: React.FC = () => {
  const [samples, setSamples] = useState<SampleLog[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [ctx, setCtx] = useState<PipelineContext | null>(null);
  const [exports, setExports] = useState<ExportSchemas | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Unknown-source mode
  const [unknownMode, setUnknownMode] = useState(false);
  const [unknownText, setUnknownText] = useState(UNKNOWN_PLACEHOLDER);
  const [learned, setLearned] = useState<
    { template: string; isNew: boolean; matches: number; raw: string }[]
  >([]);

  useEffect(() => {
    fetchSamples()
      .then((s) => {
        setSamples(s);
        if (s.length) run(s[0]);
      })
      .catch((e) => setError(String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function run(sample: SampleLog) {
    setUnknownMode(false);
    setSelectedId(sample.id);
    setBusy(true);
    setError(null);
    try {
      const res = await processEventSync(sample.raw);
      setCtx(res.context);
      setExports(res.exports);
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  /** Feed each line separately so the template miner can be seen converging. */
  async function runUnknown() {
    setBusy(true);
    setError(null);
    const lines = unknownText.split('\n').map((l) => l.trim()).filter(Boolean);
    const out: typeof learned = [];
    try {
      for (const line of lines) {
        const res = await processEventSync(line);
        const f: any = res.context.parsed_event?.extracted_fields || {};
        out.push({
          template: f._template || '(no template)',
          isNew: Boolean(f._template_is_new),
          matches: Number(f._template_match_count || 0),
          raw: line,
        });
        setCtx(res.context);
        setExports(res.exports);
      }
      setLearned(out);
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setBusy(false);
    }
  }

  const norm: any = ctx?.normalized_event;
  const parsed: any = ctx?.parsed_event;
  const cls: any = norm?.classification || {};
  const raw: any = norm?.raw || ctx?.raw_event?.raw;
  const ocsf: any = (exports as any)?.ocsf_1_9_0;
  const dqi = ctx?.validated_event?.data_quality_score;


  const routed = cls.is_security_relevant;

  return (
    <div
      style={{
        border: '1px solid var(--border-subtle)',
        borderRadius: 6,
        overflow: 'hidden',
        background: 'var(--bg-secondary)',
        fontFamily: 'var(--font-main)',
      }}
    >
      {/* ---- source rail + main column ---- */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,150px) minmax(0,1fr)' }}>
        {/* Left rail: vendor picker. Doubles as the demo control. */}
        <div
          style={{
            borderRight: '1px solid var(--border-subtle)',
            background: 'var(--bg-tertiary)',
            padding: 10,
            fontSize: 12,
          }}
        >
          <Label>Sources</Label>
          {samples.map((s) => {
            const active = !unknownMode && s.id === selectedId;
            return (
              <div
                key={s.id}
                onClick={() => run(s)}
                title={s.title}
                style={{
                  padding: '4px 6px',
                  marginBottom: 1,
                  borderRadius: 3,
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  background: active ? 'rgba(99,179,237,0.14)' : 'transparent',
                  color: active ? 'var(--cyan)' : 'var(--text-secondary)',
                }}
              >
                {shortLabel(s)}
              </div>
            );
          })}

          <div
            onClick={() => {
              setUnknownMode(true);
              setLearned([]);
            }}
            style={{
              marginTop: 8,
              paddingTop: 8,
              borderTop: '1px solid var(--border-subtle)',
              padding: '8px 6px 4px',
              cursor: 'pointer',
              color: unknownMode ? 'var(--amber)' : 'var(--text-secondary)',
            }}
          >
            + Unknown source
          </div>
        </div>

        {/* Main column */}
        <div style={{ minWidth: 0 }}>
          {error && (
            <Panel>
              <span style={{ color: 'var(--red)', fontSize: 12 }}>{error}</span>
            </Panel>
          )}

          {unknownMode ? (
            <UnknownSourcePanels
              text={unknownText}
              setText={setUnknownText}
              onRun={runUnknown}
              busy={busy}
              learned={learned}
              parsed={parsed}
              dqi={dqi}
              cls={cls}
            />
          ) : (
            <>
              {/* Raw event */}
              <Panel>
                <Label>Raw event &mdash; exactly as received</Label>
                <div
                  style={{
                    fontFamily: MONO,
                    fontSize: 11,
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 3,
                    padding: 8,
                    color: 'var(--text-primary)',
                    wordBreak: 'break-all',
                    maxHeight: 72,
                    overflow: 'auto',
                  }}
                >
                  {raw?.payload || '--'}
                </div>
                <div
                  style={{
                    fontFamily: MONO,
                    fontSize: 11,
                    color: 'var(--slate)',
                    marginTop: 6,
                  }}
                >
                  sha256 {raw?.sha256_hash?.slice(0, 12) || '--'}&hellip; &middot;{' '}
                  {raw?.length_bytes ?? '--'} bytes &middot;{' '}
                  <span style={{ color: 'var(--emerald)' }}>preserved byte-identical</span>
                </div>
              </Panel>

              {/* Pipeline, as a single line. Five boxes said no more than this. */}
              <Panel>
                <div style={{ fontFamily: MONO, fontSize: 11, color: 'var(--text-secondary)' }}>
                  {PIPELINE_STAGES.join('  →  ')}
                  <span style={{ color: 'var(--slate)' }}>
                    {'   ·   '}
                    {ctx ? `${(ctx.total_duration_us / 1000).toFixed(1)}ms` : '--'}
                    {'   ·   '}
                  </span>
                  <span style={{ color: routed ? 'var(--rose)' : 'var(--emerald)' }}>
                    {ctx ? (routed ? 'SIEM + Data Lake' : 'Data Lake only') : '--'}
                  </span>
                </div>
              </Panel>

              {/* Classification + evidence */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'minmax(0,1fr) minmax(0,1.2fr)',
                  borderBottom: '1px solid var(--border-subtle)',
                }}
              >
                <div
                  style={{ padding: '10px 12px', borderRight: '1px solid var(--border-subtle)' }}
                >
                  <Label>Classification</Label>
                  <div style={{ fontSize: 13, color: 'var(--text-primary)', marginBottom: 3 }}>
                    {cls.ocsf_class_name || '--'}{' '}
                    <span style={{ fontFamily: MONO, fontSize: 11, color: 'var(--slate)' }}>
                      {cls.ocsf_class_uid || ''}
                    </span>
                  </div>
                  <div
                    style={{
                      fontSize: 13,
                      marginBottom: 6,
                      color: routed ? 'var(--amber)' : 'var(--emerald)',
                    }}
                  >
                    {cls.threat_class || '--'}
                  </div>
                  <div style={{ fontFamily: MONO, fontSize: 11, color: 'var(--slate)' }}>
                    {(cls.mitre_techniques || []).join(', ') || 'no technique'} &middot; confidence{' '}
                    {cls.confidence ?? '--'}
                  </div>
                  {typeof dqi === 'number' && (
                    <div
                      style={{
                        fontFamily: MONO,
                        fontSize: 11,
                        color: 'var(--slate)',
                        marginTop: 3,
                      }}
                    >
                      data quality {dqi.toFixed(0)}/100
                    </div>
                  )}
                </div>

                <div style={{ padding: '10px 12px' }}>
                  <Label>Why &mdash; evidence trail</Label>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.65 }}>
                    {(cls.evidence || []).slice(0, 4).map((e: any, i: number) => (
                      <div key={i}>
                        &middot; {e.contributes}{' '}
                        <span style={{ fontFamily: MONO, color: 'var(--slate)' }}>{e.weight}</span>
                      </div>
                    ))}
                    {!(cls.evidence || []).length && (
                      <span style={{ color: 'var(--slate)' }}>no evidence recorded</span>
                    )}
                  </div>
                </div>
              </div>

              {/* OCSF output */}
              <Panel style={{ borderBottom: 'none' }}>
                <Label>Normalized output &mdash; OCSF 1.9.0</Label>
                <pre
                  style={{
                    fontFamily: MONO,
                    fontSize: 11,
                    background: 'var(--bg-primary)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 3,
                    padding: 8,
                    margin: 0,
                    color: 'var(--text-secondary)',
                    maxHeight: 150,
                    overflow: 'auto',
                  }}
                >
                  {ocsf
                    ? JSON.stringify(
                        {
                          class_uid: ocsf.class_uid,
                          class_name: ocsf.class_name,
                          activity_id: ocsf.activity_id,
                          type_uid: ocsf.type_uid,
                          raw_data_hash: ocsf.raw_data_hash,
                          raw_data_size: ocsf.raw_data_size,
                          src_endpoint: ocsf.src_endpoint,
                          dst_endpoint: ocsf.dst_endpoint,
                          unmapped_field_count: Object.keys(ocsf.unmapped || {}).length,
                        },
                        null,
                        2
                      )
                    : '--'}
                </pre>
              </Panel>
            </>
          )}
        </div>
      </div>

      {/* Status bar */}
      <div
        style={{
          padding: '6px 12px',
          borderTop: '1px solid var(--border-subtle)',
          background: 'var(--bg-tertiary)',
          fontFamily: MONO,
          fontSize: 11,
          color: 'var(--slate)',
        }}
      >
        {busy ? 'processing…' : 'idle'} &middot; {samples.length} sample sources &middot;{' '}
        {ctx ? `${(ctx.total_duration_us / 1000).toFixed(1)}ms end-to-end` : 'no event'}
      </div>
    </div>
  );
};

/** Adaptive-parser demonstration: an unseen format, learned with no config. */
const UnknownSourcePanels: React.FC<{
  text: string;
  setText: (v: string) => void;
  onRun: () => void;
  busy: boolean;
  learned: { template: string; isNew: boolean; matches: number; raw: string }[];
  parsed: any;
  dqi?: number;
  cls: any;
}> = ({ text, setText, onRun, busy, learned, parsed, dqi, cls }) => (
  <>
    <Panel>
      <Label>Unknown source &mdash; no parser exists for this format</Label>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
        rows={4}
        style={{
          width: '100%',
          boxSizing: 'border-box',
          fontFamily: MONO,
          fontSize: 11,
          background: 'var(--bg-primary)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 3,
          padding: 8,
          color: 'var(--text-primary)',
          resize: 'vertical',
        }}
      />
      <button
        onClick={onRun}
        disabled={busy}
        className="btn-cyber btn-cyber-primary"
        style={{ marginTop: 8, fontSize: 12 }}
      >
        {busy ? 'Learning…' : 'Infer structure'}
      </button>
    </Panel>

    <Panel>
      <Label>Inferred templates &mdash; Drain, zero configuration</Label>
      {!learned.length && (
        <div style={{ fontSize: 11, color: 'var(--slate)' }}>
          Nothing learned yet. Run the sample above.
        </div>
      )}
      {learned.map((l, i) => (
        <div key={i} style={{ marginBottom: 6 }}>
          <div style={{ fontFamily: MONO, fontSize: 11, color: 'var(--slate)' }}>
            {l.isNew ? (
              <span style={{ color: 'var(--amber)' }}>new template</span>
            ) : (
              <span style={{ color: 'var(--emerald)' }}>matched &times;{l.matches}</span>
            )}
          </div>
          <div
            style={{
              fontFamily: MONO,
              fontSize: 11,
              color: 'var(--text-primary)',
              wordBreak: 'break-all',
            }}
          >
            {l.template}
          </div>
        </div>
      ))}
    </Panel>

    <Panel style={{ borderBottom: 'none' }}>
      <Label>What ULPF will and will not claim</Label>
      <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.65 }}>
        <div>
          &middot; parser:{' '}
          <span style={{ fontFamily: MONO, color: 'var(--text-primary)' }}>
            {parsed?.parser_name || '--'}
          </span>{' '}
          <span style={{ fontFamily: MONO, color: 'var(--slate)' }}>
            confidence {parsed?.confidence_score ?? '--'}
          </span>
        </div>
        <div>
          &middot; raw payload preserved byte-identical, hash unchanged
        </div>
        <div>
          &middot; threat class:{' '}
          <span style={{ color: 'var(--amber)' }}>{cls?.threat_class || 'unclassified'}</span> at
          confidence {cls?.confidence ?? 0} &mdash; structure is known, meaning is not
        </div>
        <div>
          &middot; data quality {typeof dqi === 'number' ? dqi.toFixed(0) : '--'}/100 &mdash; the
          signal that this source needs a field-mapping rule
        </div>
      </div>
    </Panel>
  </>
);
