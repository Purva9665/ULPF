/**
 * API client for ULPF Backend REST endpoints and WebSocket stream
 */

import type { SampleLog, PipelineContext, EngineStats, ExportSchemas } from './types';

/**
 * Backend port. Defaults to 8000; override with VITE_API_PORT when the
 * backend runs elsewhere (a busy port, or a container publishing a different
 * one). Keeping this configurable avoids hardcoding a port into the bundle.
 */
const API_PORT = (import.meta as any).env?.VITE_API_PORT || '8000';

const getApiBase = () => {
  if (typeof window !== 'undefined' && window.location) {
    if (window.location.port === API_PORT) return window.location.origin;
    if (window.location.port === '8000' || window.location.port === '') {
      return window.location.origin;
    }
    return `${window.location.protocol}//${window.location.hostname}:${API_PORT}`;
  }
  return `http://localhost:${API_PORT}`;
};

const getWsBase = () => {
  if (typeof window !== 'undefined' && window.location) {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    if (window.location.port === '8000' || window.location.port === '') {
      return `${proto}//${window.location.host}`;
    }
    return `${proto}//${window.location.hostname}:${API_PORT}`;
  }
  return `ws://localhost:${API_PORT}`;
};

export const API_BASE = getApiBase();
export const WS_BASE = getWsBase();

export async function fetchExports(eventId?: string): Promise<ExportSchemas> {
  const url = eventId ? `${API_BASE}/api/events/${eventId}/export` : `${API_BASE}/api/exports`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/api/health`);
  return res.json();
}

export async function fetchSamples(): Promise<SampleLog[]> {
  const res = await fetch(`${API_BASE}/api/samples`);
  return res.json();
}

export async function fetchParsers() {
  const res = await fetch(`${API_BASE}/api/parsers`);
  return res.json();
}

export async function fetchStats(): Promise<EngineStats> {
  const res = await fetch(`${API_BASE}/api/stats`);
  return res.json();
}

export async function fetchStoredEvents(
  limitOrOptions?: number | {
    limit?: number;
    offset?: number;
    search?: string;
    action?: string;
    severity?: string;
    vendor?: string;
    isAnomalous?: boolean;
  },
  maybeOffset?: number
) {
  let opts: {
    limit?: number;
    offset?: number;
    search?: string;
    action?: string;
    severity?: string;
    vendor?: string;
    isAnomalous?: boolean;
  } = {};

  if (typeof limitOrOptions === 'number') {
    opts.limit = limitOrOptions;
    opts.offset = maybeOffset ?? 0;
  } else if (limitOrOptions && typeof limitOrOptions === 'object') {
    opts = limitOrOptions;
  }

  const params = new URLSearchParams();
  params.set('limit', String(opts.limit ?? 50));
  params.set('offset', String(opts.offset ?? 0));
  if (opts.search) params.set('search', opts.search);
  if (opts.action && opts.action !== 'ALL') params.set('action', opts.action);
  if (opts.severity && opts.severity !== 'ALL') params.set('severity', opts.severity);
  if (opts.vendor && opts.vendor !== 'ALL') params.set('vendor', opts.vendor);
  if (opts.isAnomalous !== undefined) params.set('is_anomalous', opts.isAnomalous ? '1' : '0');

  const res = await fetch(`${API_BASE}/api/events?${params.toString()}`);
  return res.json();
}

export async function fetchAnalytics() {
  const res = await fetch(`${API_BASE}/api/analytics`);
  return res.json();
}

export async function fetchEventDetail(eventId: string) {
  const res = await fetch(`${API_BASE}/api/events/${eventId}`);
  return res.json();
}

export async function processEventSync(
  rawText: string,
  sourceProtocol = 'SYSLOG_UDP',
  sourceMetadata: Record<string, any> = {},
  explicitParser?: string
): Promise<{ success: boolean; context: PipelineContext; exports: ExportSchemas }> {
  const res = await fetch(`${API_BASE}/api/pipeline/process`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      raw_text: rawText,
      source_protocol: sourceProtocol,
      source_metadata: sourceMetadata,
      explicit_parser: explicitParser || null,
    }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Processing failed');
  }
  return res.json();
}

export async function streamSingleEvent(rawText: string, delayMs = 60) {
  const res = await fetch(`${API_BASE}/api/pipeline/stream-single?delay_ms=${delayMs}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw_text: rawText }),
  });
  return res.json();
}

export async function stepPipelineStage(
  context: PipelineContext,
  targetStage: string
): Promise<{ success: boolean; context: PipelineContext }> {
  const res = await fetch(`${API_BASE}/api/pipeline/step`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      context: context,
      target_stage: targetStage,
    }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || 'Step execution failed');
  }
  return res.json();
}

export async function controlLiveStream(action: 'start' | 'stop' | 'set_eps', eps = 2.0, delayMs = 50) {
  const res = await fetch(`${API_BASE}/api/stream/control`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, eps, delay_ms: delayMs }),
  });
  return res.json();
}

export function connectWebSocket(
  onMessage: (data: any) => void,
  onOpen?: () => void,
  onClose?: () => void,
  onError?: (err: any) => void
): WebSocket {
  const ws = new WebSocket(`${WS_BASE}/ws/live-engine`);
  ws.onopen = () => {
    console.log('[WS] Connected to ULPF Engine Live Stream');
    onOpen?.();
  };
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch (e) {
      console.error('[WS] Failed to parse message', e);
    }
  };
  ws.onclose = () => {
    console.log('[WS] Disconnected from ULPF Engine');
    onClose?.();
  };
  ws.onerror = (err) => {
    console.error('[WS] Error', err);
    onError?.(err);
  };
  return ws;
}

/* ------------------------------------------------------------------ */
/* Detections API - findings an analyst works, not events we scored.   */
/* ------------------------------------------------------------------ */

export interface DetectionSummary {
  mode: 'trained' | 'heuristic';
  model_path: string;
  model_error: string | null;
  threshold: number | null;
  novelty_fitted: boolean;
  entities_tracked: number;
  events_seen: number;
  events_anomalous: number;
  detections_total: number;
  detections_open: number;
  events_per_detection: number;
  alert_volume_reduction_pct: number;
  entities_implicated: number;
  degraded_evidence_detections: number;
  by_severity: Record<string, number>;
}

export interface DetectionRow {
  detection_id: string;
  title: string;
  entity: string;
  threat_class: string;
  severity: string;
  confidence: number;
  state: string;
  event_count: number;
  mitre_techniques: string[];
  evidence_degraded: boolean;
}

export interface DetectionEvidence {
  detector?: string;
  signal: string;
  observed: any;
  argues: string;
  weight: number;
}

export interface ContributingEventRow {
  event_id: string;
  timestamp: string;
  raw_sha256: string;
  probability: number;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  evidence_degraded: boolean;
}

export interface DetectionDetail extends DetectionRow {
  evidence: DetectionEvidence[];
  events: ContributingEventRow[];
  peer_ips: string[];
  ports_touched: number[];
}

export interface EntityRisk {
  entity: string;
  entity_type: string;
  risk_score: number;
  detection_count: number;
  open_count: number;
  max_confidence: number;
}

export async function fetchDetectionSummary(): Promise<DetectionSummary> {
  const r = await fetch(`${getApiBase()}/api/detections/summary`);
  if (!r.ok) throw new Error('Failed to fetch detection summary');
  return r.json();
}

export async function fetchDetections(
  limit = 50, offset = 0
): Promise<{ total: number; detections: DetectionRow[] }> {
  const r = await fetch(`${getApiBase()}/api/detections?limit=${limit}&offset=${offset}`);
  if (!r.ok) throw new Error('Failed to fetch detections');
  return r.json();
}

export async function fetchDetectionDetail(id: string): Promise<DetectionDetail> {
  const r = await fetch(`${getApiBase()}/api/detections/${id}`);
  if (!r.ok) throw new Error('Failed to fetch detection');
  return r.json();
}

export async function fetchDetectionEntities(limit = 25): Promise<EntityRisk[]> {
  const r = await fetch(`${getApiBase()}/api/detections/entities?limit=${limit}`);
  if (!r.ok) throw new Error('Failed to fetch entities');
  return (await r.json()).entities;
}

export async function replaySamplesIntoDetections(): Promise<any> {
  const r = await fetch(`${getApiBase()}/api/detections/replay-samples`, { method: 'POST' });
  if (!r.ok) throw new Error('Failed to replay samples');
  return r.json();
}

export async function triageDetection(id: string, state: string, note = ''): Promise<any> {
  const r = await fetch(`${getApiBase()}/api/detections/${id}/triage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ state, note }),
  });
  if (!r.ok) throw new Error('Failed to update triage state');
  return r.json();
}
