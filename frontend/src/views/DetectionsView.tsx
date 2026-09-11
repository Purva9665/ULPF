/**
 * DetectionsView - the home screen, written for someone who is not a security
 * engineer.
 *
 * Design rules this follows:
 *
 * 1. **Answer the only question that matters first.** Does anything need me?
 *    That is the hero line. Everything else is supporting detail.
 * 2. **No jargon on the surface.** "reconnaissance" becomes "someone was
 *    checking which doors are open". "T1046" and SHA-256 hashes still exist -
 *    they move behind a "Technical details" toggle, because a judge or an
 *    engineer will want them and a manager will not.
 * 3. **No bare numbers as evidence.** "+0.45" tells a non-specialist nothing.
 *    Strength is shown as a word and a bar.
 * 4. **Say what to do.** Each issue ends with an action, in plain words.
 *
 * Uses the project's real design tokens (--phosphor-amber, --signal-teal,
 * --alert-coral, --confirm-moss, --panel*, --text-*). An earlier version of
 * this file referenced --red/--slate/.glass-panel/.btn-cyber, none of which
 * exist in index.css, so it rendered unstyled.
 */

import React, { useEffect, useState, useCallback } from 'react';
import { ShieldCheck, ShieldAlert, ChevronDown, ChevronRight } from 'lucide-react';
import {
  fetchDetections, fetchDetectionDetail, fetchDetectionSummary,
  replaySamplesIntoDetections, triageDetection,
  type DetectionSummary, type DetectionRow, type DetectionDetail,
} from '../api';

/* ---------- plain language ---------------------------------------------- */

/** What each threat class actually means, without the vocabulary. */
const PLAIN_MEANING: Record<string, { headline: string; explain: string; action: string }> = {
  reconnaissance: {
    headline: 'Someone was checking which doors are open',
    explain: 'An outside computer tried many different entry points on your network in a short time. This is usually the first step before an attack - looking for a way in.',
    action: 'Check whether this address should be talking to you at all. If not, block it.',
  },
  network_attack: {
    headline: 'Attack traffic aimed at your network',
    explain: 'Traffic matching a known attack pattern was sent to your network.',
    action: 'Confirm the targeted machine is patched, and block the source address.',
  },
  authentication_attack: {
    headline: 'Repeated failed login attempts',
    explain: 'Someone tried to log in many times and kept failing - typically an attempt to guess a password.',
    action: 'Check whether the account is real, and turn on multi-factor login for it.',
  },
  web_exploit: {
    headline: 'Someone tried to break in through your website',
    explain: 'A request was sent to your web server designed to make it do something it should not.',
    action: 'Check the web server logs for that address and make sure the software is up to date.',
  },
  malware: {
    headline: 'Traffic linked to malicious software',
    explain: 'A machine communicated in a way that matches known malicious software.',
    action: 'Isolate the machine involved and scan it before putting it back online.',
  },
  data_exfiltration: {
    headline: 'An unusual amount of data left your network',
    explain: 'Far more information than normal was sent out from one machine.',
    action: 'Find out what that machine was sending, and to whom, before it continues.',
  },
  lateral_movement: {
    headline: 'Something moved between machines inside your network',
    explain: 'One internal machine reached another in a way it does not normally do. Attackers do this after getting in, to spread.',
    action: 'Check whether that connection was expected. If not, treat both machines as suspect.',
  },
  privilege_escalation: {
    headline: 'Someone tried to gain higher access',
    explain: 'An attempt was made to get more permissions than the account should have.',
    action: 'Review what that account did before and after this attempt.',
  },
  command_and_control: {
    headline: 'A machine is quietly checking in with an outside server',
    explain: 'One of your machines contacts an outside address on a steady timer. Software controlled by an attacker behaves this way; people do not.',
    action: 'Treat the machine as compromised until you can prove otherwise.',
  },
  dos: {
    headline: 'Someone tried to overwhelm your service',
    explain: 'A flood of traffic was sent to make a service slow or unavailable.',
    action: 'Check whether the service stayed up, and rate-limit the source.',
  },
  policy_violation: {
    headline: 'Something broke an internal rule',
    explain: 'Activity was seen that your own policy does not allow, though it is not necessarily an attack.',
    action: 'Decide whether the rule or the behaviour needs to change.',
  },
  benign_traffic: {
    headline: 'Ordinary traffic, flagged for review',
    explain: 'This looked slightly unusual but resembles normal activity.',
    action: 'Most likely nothing. Mark it fine if you recognise it.',
  },
  unclassified: {
    headline: 'Unusual activity we could not categorise',
    explain: 'This did not match normal behaviour, but also did not match any known pattern well enough to name it.',
    action: 'Have a look and tell the system whether it was real - it learns from that.',
  },
};

/**
 * Signals that are internal bookkeeping rather than something a person would
 * recognise as an observation. The headline already carries the
 * classification, and MITRE lives under Technical details, so repeating them
 * here spends the reader's attention without informing them.
 */
const HIDDEN_SIGNALS = new Set([
  'taxonomy_threat_class', 'mitre_attack', 'cold_baseline',
  'no_event_timestamp', 'benign_classification', 'matches_baseline',
  'no_temporal_anomaly',
]);

/**
 * Plain-English rewrites of detector evidence. The backend phrases these for
 * an analyst; this phrases them for everyone else. Anything not listed falls
 * back to the backend's own wording, which is already reasonably readable.
 */
const PLAIN_SIGNAL: Record<string, string> = {
  device_action: 'Your firewall refused the connection',
  sensitive_port: 'They aimed at a door commonly used for remote control of a machine',
  vendor_signature: 'Your security device recognised this as a known attack pattern',
  port_fanout: 'They tried an unusually wide range of entry points',
  peer_fanout: 'They contacted an unusually large number of your machines',
  peer_fanin: 'An unusually large number of outside machines contacted this one',
  deny_ratio: 'Most of what they attempted was blocked, which suggests probing',
  port_novelty: 'This source has never used this entry point before',
  peer_novelty: 'This source has never contacted this machine before',
  time_novelty: 'This happened at an hour when this source is normally quiet',
  volume_deviation: 'Far more data moved than this machine normally sends',
  protocol_novelty: 'This source does not normally communicate this way',
  event_burst: 'A large number of attempts arrived in a very short time',
  failure_run: 'A run of connections was refused one after another',
  periodic_contact: 'The contact repeats on a steady timer, like an automated check-in rather than a person',
};

/** Readable text for one piece of evidence. */
function plainEvidence(signal: string, fallback: string): string {
  if (PLAIN_SIGNAL[signal]) return PLAIN_SIGNAL[signal];
  if (signal.startsWith('novelty:')) {
    return 'This does not match the normal pattern of traffic on your network';
  }
  return fallback;
}

/** Severity, as urgency a person can act on rather than a label. */
const URGENCY: Record<string, { label: string; color: string; dim: string; order: number }> = {
  critical: { label: 'Act now',       color: 'var(--alert-coral)',   dim: 'var(--alert-coral-dim)',   order: 0 },
  high:     { label: 'Look soon',     color: 'var(--phosphor-amber)', dim: 'var(--phosphor-amber-dim)', order: 1 },
  medium:   { label: 'Worth a look',  color: 'var(--signal-teal)',   dim: 'var(--signal-teal-dim)',   order: 2 },
  low:      { label: 'Low priority',  color: 'var(--text-low)',      dim: 'transparent',              order: 3 },
};

/** Evidence strength as a word, not a decimal. */
function strengthOf(weight: number): { label: string; fill: number } {
  const w = Math.abs(weight);
  if (w >= 0.4) return { label: 'Strong', fill: 1 };
  if (w >= 0.2) return { label: 'Moderate', fill: 0.6 };
  return { label: 'Slight', fill: 0.3 };
}

const ACTIONS = [
  { value: 'investigating', label: "I'm looking into it" },
  { value: 'resolved_true_positive', label: 'This was real' },
  { value: 'resolved_false_positive', label: 'This was fine' },
];

function meaningFor(threatClass: string) {
  return PLAIN_MEANING[threatClass] || PLAIN_MEANING.unclassified;
}

/* ---------- view --------------------------------------------------------- */

export const DetectionsView: React.FC = () => {
  const [summary, setSummary] = useState<DetectionSummary | null>(null);
  const [rows, setRows] = useState<DetectionRow[]>([]);
  const [selected, setSelected] = useState<DetectionDetail | null>(null);
  const [showTech, setShowTech] = useState(false);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    const [s, d] = await Promise.all([fetchDetectionSummary(), fetchDetections(100)]);
    setSummary(s);
    setRows(d.detections);
    return d.detections;
  }, []);

  useEffect(() => { refresh().catch(() => {}); }, [refresh]);

  const select = async (id: string) => {
    try { setSelected(await fetchDetectionDetail(id)); setShowTech(false); } catch { /* */ }
  };

  const runSamples = async () => {
    setBusy(true);
    try {
      await replaySamplesIntoDetections();
      const list = await refresh();
      if (list.length) await select(list[0].detection_id);
    } finally { setBusy(false); }
  };

  const act = async (state: string) => {
    if (!selected) return;
    await triageDetection(selected.detection_id, state);
    await refresh();
    await select(selected.detection_id);
  };

  const needsAttention = rows.filter(r => r.state === 'new' || r.state === 'investigating').length;
  const checked = summary?.events_seen ?? 0;
  const allClear = checked > 0 && needsAttention === 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 1180 }}>

      {/* ---- the only question that matters ---- */}
      <section
        className="panel-machined"
        style={{
          padding: '26px 28px', display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', gap: 24,
          borderLeft: `3px solid ${needsAttention > 0 ? 'var(--alert-coral)'
                        : allClear ? 'var(--confirm-moss)' : 'var(--hairline-bright)'}`,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
          <div style={{
            width: 46, height: 46, borderRadius: '50%', flexShrink: 0,
            display: 'grid', placeItems: 'center',
            background: needsAttention > 0 ? 'var(--alert-coral-dim)'
                        : allClear ? 'var(--confirm-moss-dim)' : 'transparent',
          }}>
            {needsAttention > 0
              ? <ShieldAlert size={24} color="var(--alert-coral)" />
              : <ShieldCheck size={24} color={allClear ? 'var(--confirm-moss)' : 'var(--text-low)'} />}
          </div>
          <div>
            <h1 style={{
              margin: 0, fontFamily: 'var(--font-chrome)', fontSize: '1.5rem',
              fontWeight: 600, color: 'var(--text-high)', letterSpacing: '-0.01em',
            }}>
              {checked === 0
                ? 'Nothing checked yet'
                : needsAttention === 0
                  ? 'Nothing needs your attention'
                  : `${needsAttention} thing${needsAttention === 1 ? '' : 's'} need${needsAttention === 1 ? 's' : ''} your attention`}
            </h1>
            <p style={{ margin: '5px 0 0', color: 'var(--text-mid)', fontSize: '0.9rem' }}>
              {checked === 0
                ? 'Load the example logs to see how this works.'
                : `We read ${checked.toLocaleString()} log entries and found ${needsAttention === 0 ? 'nothing' : `${needsAttention}`} worth showing you.`}
            </p>
          </div>
        </div>

        <button
          className="btn-instrument btn-instrument-primary"
          onClick={runSamples}
          disabled={busy}
          style={{ padding: '10px 18px', fontSize: '0.85rem', whiteSpace: 'nowrap' }}
        >
          {busy ? 'Reading logs…' : checked === 0 ? 'Load example logs' : 'Read them again'}
        </button>
      </section>

      {/* ---- the list, and the explanation ---- */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: selected ? 'minmax(320px, 1fr) 1.25fr' : '1fr',
        gap: 20, alignItems: 'start',
      }}>

        <section style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {rows.length === 0 ? (
            <div className="panel-machined" style={{
              padding: 36, textAlign: 'center', color: 'var(--text-mid)', fontSize: '0.9rem',
            }}>
              Nothing to show yet.<br />
              <span style={{ color: 'var(--text-low)' }}>
                Use “Load example logs” above to try it out.
              </span>
            </div>
          ) : rows.map(r => {
            const urgency = URGENCY[r.severity] || URGENCY.low;
            const meaning = meaningFor(r.threat_class);
            const isOpen = selected?.detection_id === r.detection_id;
            const handled = r.state.startsWith('resolved');
            return (
              <button
                key={r.detection_id}
                onClick={() => select(r.detection_id)}
                className="panel-machined"
                style={{
                  textAlign: 'left', cursor: 'pointer', width: '100%',
                  padding: '16px 18px', font: 'inherit', color: 'inherit',
                  borderLeft: `3px solid ${urgency.color}`,
                  background: isOpen ? 'var(--panel-elevated)' : undefined,
                  opacity: handled ? 0.55 : 1,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between',
                              alignItems: 'flex-start', gap: 14 }}>
                  <span style={{
                    fontFamily: 'var(--font-chrome)', fontWeight: 600,
                    fontSize: '1rem', color: 'var(--text-high)', lineHeight: 1.35,
                  }}>
                    {meaning.headline}
                  </span>
                  <span style={{
                    flexShrink: 0, fontSize: '0.7rem', fontWeight: 600,
                    letterSpacing: '0.04em', textTransform: 'uppercase',
                    color: urgency.color, background: urgency.dim,
                    padding: '4px 9px', borderRadius: 'var(--radius-md)',
                  }}>
                    {handled ? 'Handled' : urgency.label}
                  </span>
                </div>
                <div style={{ marginTop: 7, fontSize: '0.82rem', color: 'var(--text-mid)' }}>
                  From <span className="readout" style={{ color: 'var(--text-high)' }}>{r.entity}</span>
                  {r.event_count > 1 && ` · seen ${r.event_count.toLocaleString()} times`}
                </div>
              </button>
            );
          })}
        </section>

        {selected && (
          <section className="panel-machined" style={{ padding: '24px 26px' }}>
            {(() => {
              const meaning = meaningFor(selected.threat_class);
              const urgency = URGENCY[selected.severity] || URGENCY.low;
              return (
                <>
                  <div style={{
                    fontSize: '0.7rem', fontWeight: 600, letterSpacing: '0.04em',
                    textTransform: 'uppercase', color: urgency.color, marginBottom: 8,
                  }}>
                    {urgency.label}
                  </div>
                  <h2 style={{
                    margin: 0, fontFamily: 'var(--font-chrome)', fontSize: '1.25rem',
                    fontWeight: 600, color: 'var(--text-high)', lineHeight: 1.3,
                  }}>
                    {meaning.headline}
                  </h2>

                  <p style={{ margin: '14px 0 0', fontSize: '0.92rem',
                              lineHeight: 1.6, color: 'var(--text-mid)' }}>
                    {meaning.explain}
                  </p>

                  {/* what we saw, in sentences */}
                  <Heading>What we saw</Heading>
                  <ul style={{ margin: 0, padding: 0, listStyle: 'none',
                               display: 'flex', flexDirection: 'column', gap: 9 }}>
                    {selected.evidence
                      .filter(e => e.weight > 0 && !HIDDEN_SIGNALS.has(e.signal))
                      .slice(0, 4).map((e, i) => {
                      const s = strengthOf(e.weight);
                      return (
                        <li key={i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                          <span style={{
                            flexShrink: 0, width: 52, height: 4, marginTop: 8,
                            borderRadius: 2, background: 'var(--hairline)', overflow: 'hidden',
                          }}>
                            <span style={{
                              display: 'block', height: '100%',
                              width: `${s.fill * 100}%`, background: urgency.color,
                            }} />
                          </span>
                          <span style={{ fontSize: '0.88rem', lineHeight: 1.5,
                                         color: 'var(--text-mid)' }}>
                            {plainEvidence(e.signal, e.argues)}
                          </span>
                        </li>
                      );
                    })}
                  </ul>

                  {selected.evidence_degraded && (
                    <p style={{
                      margin: '16px 0 0', padding: '10px 12px', fontSize: '0.82rem',
                      lineHeight: 1.5, color: 'var(--text-mid)',
                      background: 'var(--panel-sunken)', borderRadius: 'var(--radius-md)',
                      borderLeft: '2px solid var(--phosphor-amber)',
                    }}>
                      Some details in the original log were unclear, so parts of this are
                      less certain than usual.
                    </p>
                  )}

                  <Heading>What to do</Heading>
                  <p style={{ margin: 0, fontSize: '0.92rem', lineHeight: 1.6,
                              color: 'var(--text-high)' }}>
                    {meaning.action}
                  </p>

                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 18 }}>
                    {ACTIONS.map(a => (
                      <button key={a.value} className="btn-instrument"
                              onClick={() => act(a.value)}
                              style={{ padding: '8px 14px', fontSize: '0.8rem' }}>
                        {a.label}
                      </button>
                    ))}
                  </div>

                  {/* everything technical, folded away */}
                  <button
                    onClick={() => setShowTech(v => !v)}
                    className="btn-instrument"
                    style={{
                      marginTop: 22, padding: '7px 12px', fontSize: '0.78rem',
                      border: 'none', background: 'transparent',
                      color: 'var(--text-low)', gap: 6,
                    }}
                  >
                    {showTech ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                    Technical details
                  </button>

                  {showTech && (
                    <div className="panel-sunken" style={{
                      marginTop: 10, padding: '14px 16px', fontSize: '0.78rem',
                      fontFamily: 'var(--font-readout)', color: 'var(--text-mid)',
                      display: 'flex', flexDirection: 'column', gap: 7,
                      overflowX: 'auto',
                    }}>
                      <TechRow k="Classification" v={selected.threat_class} />
                      <TechRow k="Confidence" v={`${(selected.confidence * 100).toFixed(1)}%`} />
                      <TechRow k="Contributing events" v={String(selected.event_count)} />
                      <TechRow
                        k="MITRE ATT&CK"
                        v={selected.mitre_techniques.length
                            ? selected.mitre_techniques.join(', ') : 'none mapped'}
                      />
                      <TechRow k="Detection ID" v={selected.detection_id.slice(0, 18) + '…'} />
                      {selected.events.slice(0, 3).map(ev => (
                        <TechRow
                          key={ev.event_id}
                          k={`${ev.src_ip} → ${ev.dst_ip}:${ev.dst_port ?? '-'}`}
                          v={`sha256 ${ev.raw_sha256.slice(0, 20)}…`}
                        />
                      ))}
                    </div>
                  )}
                </>
              );
            })()}
          </section>
        )}
      </div>
    </div>
  );
};

const Heading: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div style={{
    margin: '22px 0 11px', fontSize: '0.68rem', fontWeight: 600,
    letterSpacing: '0.07em', textTransform: 'uppercase',
    color: 'var(--text-low)', fontFamily: 'var(--font-readout)',
  }}>
    {children}
  </div>
);

const TechRow: React.FC<{ k: string; v: string }> = ({ k, v }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16 }}>
    <span style={{ color: 'var(--text-low)', whiteSpace: 'nowrap' }}>{k}</span>
    <span style={{ color: 'var(--text-high)', textAlign: 'right' }}>{v}</span>
  </div>
);
