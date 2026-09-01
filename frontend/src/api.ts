/**
 * API client for ULPF Backend REST endpoints and WebSocket stream
 */

import type { SampleLog, PipelineContext, EngineStats, ExportSchemas } from './types';

const getApiBase = () => {
  if (typeof window !== 'undefined' && window.location) {
    if (window.location.port === '8000' || window.location.port === '') {
      return window.location.origin;
    }
    return `${window.location.protocol}//${window.location.hostname}:8000`;
  }
  return 'http://localhost:8000';
};

const getWsBase = () => {
  if (typeof window !== 'undefined' && window.location) {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    if (window.location.port === '8000' || window.location.port === '') {
      return `${proto}//${window.location.host}`;
    }
    return `${proto}//${window.location.hostname}:8000`;
  }
  return 'ws://localhost:8000';
};

const API_BASE = getApiBase();
const WS_BASE = getWsBase();

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

export async function fetchStoredEvents(limit = 50, offset = 0) {
  const res = await fetch(`${API_BASE}/api/events?limit=${limit}&offset=${offset}`);
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
