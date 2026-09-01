import React, { useState, useEffect, useRef } from 'react';
import type { 
  StageEnum, 
  PipelineContext, 
  SampleLog, 
  EngineStats, 
  ExportSchemas,
  TimelineItem,
  ULPFRawEvent,
  RawPayload,
} from './types';
import { 
  fetchSamples, 
  fetchStats, 
  fetchStoredEvents,
  fetchEventDetail,
  processEventSync, 
  streamSingleEvent, 
  stepPipelineStage, 
  controlLiveStream, 
  connectWebSocket 
} from './api';
import { Header } from './components/Header';
import { LeftSidebarScoreCard } from './components/LeftSidebarScoreCard';
import { MainLivePipeline } from './components/MainLivePipeline';
import { CurrentEventCard } from './components/CurrentEventCard';
import { LiveActivityTimeline } from './components/LiveActivityTimeline';
import { SystemHealthCard } from './components/SystemHealthCard';
import { ProcessingMetricsGrid } from './components/ProcessingMetricsGrid';
import { RecentEventsTable } from './components/RecentEventsTable';
import { TestBenchModal } from './components/TestBenchModal';
import { HistoryDrawer } from './components/HistoryDrawer';
import { ExportViewerModal } from './components/ExportViewerModal';

// Phase 2 Detailed Processing Stage Views
import { IngestionView } from './views/IngestionView';
import { ParserView } from './views/ParserView';
import { NormalizationView } from './views/NormalizationView';
import { ValidationView } from './views/ValidationView';
import { StorageView } from './views/StorageView';
import { MLView } from './views/MLView';
import { ExportView } from './views/ExportView';
import { EventJourneyView } from './views/EventJourneyView';

export const App: React.FC = () => {
  // Navigation: 'overview' | 'ingestion' | 'parser' | 'normalization' | 'validation' | 'storage' | 'ml' | 'export' | 'journey'
  const [activeTab, setActiveTab] = useState<string>('overview');

  // Mode & Streaming State
  const [mode, setMode] = useState<'STREAM' | 'DEBUG'>('STREAM');
  const [isStreaming, setIsStreaming] = useState(false);
  const [eps, setEps] = useState(2.0);
  const [stageDelayMs] = useState(50);

  // Pipeline Engine State
  const [context, setContext] = useState<PipelineContext | null>(null);
  const [selectedStage, setSelectedStage] = useState<StageEnum>('INGEST');
  const [activeTransitionStage, setActiveTransitionStage] = useState<StageEnum | null>(null);
  const [exports, setExports] = useState<ExportSchemas | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  // Live Activity Timeline
  const [timelineItems, setTimelineItems] = useState<TimelineItem[]>([]);

  // Recent Stored Events
  const [recentEvents, setRecentEvents] = useState<any[]>([]);

  // Metadata & Stats
  const [samples, setSamples] = useState<SampleLog[]>([]);
  const [selectedSampleId, setSelectedSampleId] = useState<string>('cisco_asa_smb_sweep');
  const [stats, setStats] = useState<EngineStats | null>(null);
  const [isConnected, setIsConnected] = useState(false);

  // Modals
  const [isTestBenchOpen, setIsTestBenchOpen] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [isExportsOpen, setIsExportsOpen] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);

  // Sequence for Step Debugger
  const STAGE_ORDER: StageEnum[] = ['INGEST', 'PARSE', 'NORMALIZE', 'VALIDATE', 'STORE', 'ML', 'STANDARDIZED'];

  // Format local timestamp with ms
  const formatTime = () => {
    const d = new Date();
    return d.toTimeString().split(' ')[0] + '.' + String(d.getMilliseconds()).padStart(3, '0');
  };

  // Initial Data Fetch
  useEffect(() => {
    const init = async () => {
      try {
        const [sampleList, initialStats, storedList] = await Promise.all([
          fetchSamples(),
          fetchStats(),
          fetchStoredEvents(15, 0),
        ]);
        setSamples(sampleList);
        setStats(initialStats);
        setRecentEvents(storedList);

        if (sampleList.length > 0) {
          setSelectedSampleId(sampleList[0].id);
          // Run initial sample synchronously to populate dashboard state immediately
          const initialRes = await processEventSync(sampleList[0].raw);
          setContext(initialRes.context);
          setExports(initialRes.exports);
          
          // Add initial timeline item
          setTimelineItems([
            {
              id: 'init-1',
              eventId: initialRes.context.event_id,
              stage: 'STANDARDIZED',
              status: 'COMPLETED',
              timestamp: formatTime(),
              title: `Pipeline Ready • ${sampleList[0].title}`,
              subtitle: `Parsed with ${initialRes.context.parsed_event?.parser_name || 'cisco_asa'} • DQI 100%`,
            }
          ]);
        }
      } catch (err) {
        console.error('Failed to initialize ULPF engine state', err);
      }
    };
    init();

    // Setup Live WebSocket Connection to Backend Engine
    const ws = connectWebSocket(
      (data) => {
        if (data.type === 'CONNECTION_ESTABLISHED') {
          setIsConnected(true);
          if (data.stats) {
            setStats((prev) => (prev ? { ...prev, storage: data.stats } : prev));
          }
        } else if (data.type === 'STAGE_TRANSITION') {
          setActiveTransitionStage(data.stage);
          setSelectedStage(data.stage);

          // Update context with intermediate stage transition
          setContext((prev) => {
            if (!prev || prev.event_id !== data.event_id) {
              return {
                event_id: data.event_id,
                current_stage: data.stage,
                stages_completed: [data.stage],
                stage_metrics: [data.metric],
                total_duration_us: 0,
                is_completed: false,
                ...(data.snapshot || {}),
              };
            }
            const completed = prev.stages_completed.includes(data.stage)
              ? prev.stages_completed
              : [...prev.stages_completed, data.stage];
            const metrics = [...prev.stage_metrics.filter((m) => m.stage !== data.stage), data.metric];

            return {
              ...prev,
              current_stage: data.stage,
              stages_completed: completed,
              stage_metrics: metrics,
              ...(data.snapshot || {}),
            };
          });

          // Append to Live Activity Timeline
          const newItem: TimelineItem = {
            id: `tl-${Date.now()}-${Math.random()}`,
            eventId: data.event_id,
            stage: data.stage,
            status: data.status || 'COMPLETED',
            timestamp: formatTime(),
            title: data.metric?.message || `Executed Stage ${data.stage}`,
            subtitle: `Latency: ${data.metric?.duration_us || 0} µs`,
            metric: data.metric,
            snapshot: data.snapshot,
          };

          setTimelineItems((prev) => [newItem, ...prev.slice(0, 49)]);

        } else if (data.type === 'EVENT_COMPLETED') {
          setActiveTransitionStage(null);
          setContext(data.context);
          setExports(data.exports);
          setSelectedStage('STANDARDIZED');

          // Append completion to Live Activity Timeline
          const completedItem: TimelineItem = {
            id: `tl-comp-${Date.now()}`,
            eventId: data.event_id,
            stage: 'STANDARDIZED',
            status: 'COMPLETED',
            timestamp: formatTime(),
            title: `Event ${data.event_id.slice(0, 8)}... Fully Standardized`,
            subtitle: `End-to-End Latency: ${data.context.total_duration_us} µs • SIEM Exporters Generated`,
          };
          setTimelineItems((prev) => [completedItem, ...prev.slice(0, 49)]);

          // Refresh stats and recent stored records
          fetchStats().then((s) => setStats(s)).catch(() => {});
          fetchStoredEvents(15, 0).then((evs) => setRecentEvents(evs)).catch(() => {});
        }
      },
      () => setIsConnected(true),
      () => setIsConnected(false),
      () => setIsConnected(false)
    );

    wsRef.current = ws;

    return () => {
      ws.close();
    };
  }, []);

  // Handler: Select Sample Preset
  const handleSelectSample = (sampleId: string) => {
    setSelectedSampleId(sampleId);
    const sample = samples.find((s) => s.id === sampleId);
    if (!sample) return;

    if (mode === 'STREAM') {
      streamSingleEvent(sample.raw, stageDelayMs);
    } else {
      // In debug mode, reset context to Stage 1 INGEST
      const rawPayload: RawPayload = {
        payload: sample.raw,
        sha256_hash: '',
        encoding: 'UTF-8',
        length_bytes: sample.raw.length,
        source_protocol: 'SYSLOG_UDP',
      };
      const rawEv: ULPFRawEvent = {
        event_id: 'debug-' + Date.now(),
        ingested_at: new Date().toISOString(),
        raw: rawPayload,
        source_metadata: { title: sample.title },
      };
      setContext({
        event_id: rawEv.event_id,
        current_stage: 'INGEST',
        stages_completed: ['INGEST'],
        stage_metrics: [],
        raw_event: rawEv,
        total_duration_us: 0,
        is_completed: false,
      });
      setSelectedStage('INGEST');
    }
  };

  // Handler: Toggle Continuous Live Streaming
  const handleToggleStream = async () => {
    const nextStreaming = !isStreaming;
    setIsStreaming(nextStreaming);
    try {
      await controlLiveStream(nextStreaming ? 'start' : 'stop', eps, stageDelayMs);
    } catch (err) {
      console.error('Failed to control live stream', err);
    }
  };

  // Handler: Update EPS
  const handleSetEps = async (newEps: number) => {
    setEps(newEps);
    if (isStreaming) {
      await controlLiveStream('set_eps', newEps, stageDelayMs);
    }
  };

  // Handler: Trigger Single Event
  const handleTriggerSingleEvent = async () => {
    const sample = samples.find((s) => s.id === selectedSampleId) || samples[0];
    if (!sample) return;
    setIsProcessing(true);
    try {
      await streamSingleEvent(sample.raw, stageDelayMs);
    } catch (err) {
      console.error('Failed to trigger single event', err);
    } finally {
      setIsProcessing(false);
    }
  };

  // Step Debugger: Advance exactly 1 stage
  const handleStepForward = async () => {
    if (!context) return;
    const currentIdx = STAGE_ORDER.indexOf(context.current_stage);
    if (currentIdx < 0 || currentIdx >= STAGE_ORDER.length - 1) return;

    const nextStage = STAGE_ORDER[currentIdx + 1];
    setIsProcessing(true);
    try {
      const res = await stepPipelineStage(context, nextStage);
      setContext(res.context);
      setSelectedStage(nextStage);
    } catch (err) {
      console.error('Step execution error', err);
    } finally {
      setIsProcessing(false);
    }
  };

  // Step Debugger: Fast-forward to end
  const handleFastForward = async () => {
    const sample = samples.find((s) => s.id === selectedSampleId) || samples[0];
    if (!sample) return;
    setIsProcessing(true);
    try {
      const res = await processEventSync(sample.raw);
      setContext(res.context);
      setExports(res.exports);
      setSelectedStage('STANDARDIZED');
      fetchStats().then((s) => setStats(s)).catch(() => {});
      fetchStoredEvents(15, 0).then((evs) => setRecentEvents(evs)).catch(() => {});
    } catch (err) {
      console.error('Fast-forward execution error', err);
    } finally {
      setIsProcessing(false);
    }
  };

  // Step Debugger: Reset Stepper
  const handleResetStepper = () => {
    const sample = samples.find((s) => s.id === selectedSampleId) || samples[0];
    if (!sample) return;
    const rawPayload: RawPayload = {
      payload: sample.raw,
      sha256_hash: '',
      encoding: 'UTF-8',
      length_bytes: sample.raw.length,
      source_protocol: 'SYSLOG_UDP',
    };
    const rawEv: ULPFRawEvent = {
      event_id: 'debug-' + Date.now(),
      ingested_at: new Date().toISOString(),
      raw: rawPayload,
      source_metadata: { title: sample.title },
    };
    setContext({
      event_id: rawEv.event_id,
      current_stage: 'INGEST',
      stages_completed: ['INGEST'],
      stage_metrics: [],
      raw_event: rawEv,
      total_duration_us: 0,
      is_completed: false,
    });
    setSelectedStage('INGEST');
  };

  // Inspect Event from Table or Timeline
  const handleInspectEventById = async (eventId: string) => {
    try {
      const detail = await fetchEventDetail(eventId);
      if (detail) {
        if (detail.raw_event || detail.current_stage) {
          setContext(detail);
        } else {
          const rawPayload: RawPayload = {
            payload: detail.raw_payload || '',
            sha256_hash: detail.raw_sha256 || '',
            encoding: 'UTF-8',
            length_bytes: detail.raw_length_bytes || 0,
            source_protocol: detail.protocol || 'SYSLOG_UDP',
          };
          setContext({
            event_id: detail.event_id,
            current_stage: 'STANDARDIZED',
            stages_completed: ['INGEST', 'PARSE', 'NORMALIZE', 'VALIDATE', 'STORE', 'ML', 'STANDARDIZED'],
            stage_metrics: [],
            raw_event: {
              event_id: detail.event_id,
              ingested_at: detail.ingested_at || new Date().toISOString(),
              raw: rawPayload,
              source_metadata: {},
            },
            total_duration_us: 380,
            is_completed: true,
          });
        }
      }
    } catch (err) {
      console.error('Failed to load event detail', err);
    }
  };

  const canStep = context ? STAGE_ORDER.indexOf(context.current_stage) < STAGE_ORDER.length - 1 : false;

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: 'var(--bg-primary)' }}>
      
      {/* 1. UNIVERSAL ENTERPRISE HEADER */}
      <Header
        stats={stats}
        isConnected={isConnected}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onOpenTestBench={() => setIsTestBenchOpen(true)}
        onOpenHistory={() => setIsHistoryOpen(true)}
        onOpenExports={() => setIsExportsOpen(true)}
      />

      {/* Main Container */}
      <main style={{ flex: 1, padding: '16px 20px 32px 20px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
        
        {/* ======================================================== */}
        {/* ROUTE 1: MAIN CONTROL ROOM OVERVIEW                      */}
        {/* ======================================================== */}
        {activeTab === 'overview' && (
          <>
            {/* TOP ROW: LEFT SIDEBAR + MAIN LIVE PIPELINE + LIVE TIMELINE */}
            <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr 340px', gap: '20px', alignItems: 'stretch' }}>
              
              {/* Left Column: Greeting Banner + Quality/DQI Score Card */}
              <LeftSidebarScoreCard
                stats={stats}
                onOpenTestBench={() => setIsTestBenchOpen(true)}
              />

              {/* Center Column: MAIN LIVE PIPELINE CENTERPIECE */}
              <MainLivePipeline
                context={context}
                selectedStage={selectedStage}
                onSelectStage={(st) => {
                  setSelectedStage(st);
                  // Quick shortcut to jump into that specific stage dashboard
                  if (st === 'INGEST') setActiveTab('ingestion');
                  else if (st === 'PARSE') setActiveTab('parser');
                  else if (st === 'NORMALIZE') setActiveTab('normalization');
                  else if (st === 'VALIDATE') setActiveTab('validation');
                  else if (st === 'STORE') setActiveTab('storage');
                  else if (st === 'ML') setActiveTab('ml');
                  else if (st === 'STANDARDIZED') setActiveTab('export');
                }}
                activeTransitionStage={activeTransitionStage}
                mode={mode}
                onSetMode={setMode}
                isStreaming={isStreaming}
                onToggleStream={handleToggleStream}
                eps={eps}
                onSetEps={handleSetEps}
                samples={samples}
                selectedSampleId={selectedSampleId}
                onSelectSample={handleSelectSample}
                onTriggerSingleEvent={handleTriggerSingleEvent}
                onStepForward={handleStepForward}
                onResetStepper={handleResetStepper}
                onFastForward={handleFastForward}
                canStepForward={canStep}
                isProcessing={isProcessing}
              />

              {/* Right Column: LIVE ACTIVITY TIMELINE */}
              <LiveActivityTimeline
                items={timelineItems}
                onSelectItem={(item) => handleInspectEventById(item.eventId)}
                onClear={() => setTimelineItems([])}
                onOpenHistory={() => setIsHistoryOpen(true)}
              />

            </div>

            {/* MIDDLE ROW: CURRENT EVENT FOCUS CARD */}
            <CurrentEventCard
              context={context}
              exports={exports}
            />

            {/* BOTTOM ROW: SYSTEM HEALTH + PROCESSING METRICS */}
            <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: '20px' }}>
              <SystemHealthCard
                stats={stats}
                isConnected={isConnected}
              />

              <ProcessingMetricsGrid
                stats={stats}
              />
            </div>

            {/* 7. RECENT EVENTS TABLE (SQLite WAL Database Journal) */}
            <RecentEventsTable
              events={recentEvents}
              onSelectEvent={handleInspectEventById}
              onOpenHistory={() => setIsHistoryOpen(true)}
            />
          </>
        )}

        {/* ======================================================== */}
        {/* ROUTE 2: STAGE 01 — INGESTION DASHBOARD                  */}
        {/* ======================================================== */}
        {activeTab === 'ingestion' && (
          <IngestionView
            context={context}
            stats={stats}
            onBackToOverview={() => setActiveTab('overview')}
            onRunCustomIngest={async (rawText) => {
              setIsProcessing(true);
              try {
                const res = await processEventSync(rawText);
                setContext(res.context);
                setExports(res.exports);
                fetchStats().then((s) => setStats(s)).catch(() => {});
                fetchStoredEvents(15, 0).then((evs) => setRecentEvents(evs)).catch(() => {});
              } catch (err) {
                console.error('Ingestion error', err);
              } finally {
                setIsProcessing(false);
              }
            }}
            samples={samples}
          />
        )}

        {/* ======================================================== */}
        {/* ROUTE 3: STAGE 02 — PARSER DASHBOARD                     */}
        {/* ======================================================== */}
        {activeTab === 'parser' && (
          <ParserView
            context={context}
            stats={stats}
            onBackToOverview={() => setActiveTab('overview')}
            onSelectSample={handleSelectSample}
            samples={samples}
          />
        )}

        {/* ======================================================== */}
        {/* ROUTE 4: STAGE 03 — NORMALIZATION DASHBOARD (CORE ULPF)  */}
        {/* ======================================================== */}
        {activeTab === 'normalization' && (
          <NormalizationView
            context={context}
            stats={stats}
            onBackToOverview={() => setActiveTab('overview')}
          />
        )}

        {/* ======================================================== */}
        {/* ROUTE 5: STAGE 04 — VALIDATION DASHBOARD                 */}
        {/* ======================================================== */}
        {activeTab === 'validation' && (
          <ValidationView
            context={context}
            stats={stats}
            onBackToOverview={() => setActiveTab('overview')}
          />
        )}

        {/* ======================================================== */}
        {/* ROUTE 6: STAGE 05 — POSTGRESQL / STORAGE DASHBOARD       */}
        {/* ======================================================== */}
        {activeTab === 'storage' && (
          <StorageView
            context={context}
            stats={stats}
            onBackToOverview={() => setActiveTab('overview')}
            onSelectEventId={handleInspectEventById}
          />
        )}

        {/* ======================================================== */}
        {/* ROUTE 7: STAGE 06 — ML / ANALYTICS DASHBOARD             */}
        {/* ======================================================== */}
        {activeTab === 'ml' && (
          <MLView
            context={context}
            stats={stats}
            onBackToOverview={() => setActiveTab('overview')}
          />
        )}

        {/* ======================================================== */}
        {/* ROUTE 8: STAGE 07 — EXPORT DASHBOARD                     */}
        {/* ======================================================== */}
        {activeTab === 'export' && (
          <ExportView
            context={context}
            stats={stats}
            exports={exports}
            onBackToOverview={() => setActiveTab('overview')}
          />
        )}

        {/* ======================================================== */}
        {/* ROUTE 9: EVENT JOURNEY & TRACEABILITY DASHBOARD          */}
        {/* ======================================================== */}
        {activeTab === 'journey' && (
          <EventJourneyView
            context={context}
            stats={stats}
            onBackToOverview={() => setActiveTab('overview')}
            onSelectStage={(st) => {
              if (st === 'INGEST') setActiveTab('ingestion');
              else if (st === 'PARSE') setActiveTab('parser');
              else if (st === 'NORMALIZE') setActiveTab('normalization');
              else if (st === 'VALIDATE') setActiveTab('validation');
              else if (st === 'STORE') setActiveTab('storage');
              else if (st === 'ML') setActiveTab('ml');
              else if (st === 'STANDARDIZED') setActiveTab('export');
            }}
          />
        )}

      </main>

      {/* MODALS */}
      {isTestBenchOpen && (
        <TestBenchModal
          isOpen={isTestBenchOpen}
          onClose={() => setIsTestBenchOpen(false)}
          samples={samples}
          onRunCustom={async (rawText, explicitParser) => {
            setIsTestBenchOpen(false);
            setIsProcessing(true);
            try {
              const res = await processEventSync(rawText, explicitParser === 'auto' ? undefined : explicitParser);
              setContext(res.context);
              setExports(res.exports);
              setSelectedStage('STANDARDIZED');
              fetchStats().then((s) => setStats(s)).catch(() => {});
              fetchStoredEvents(15, 0).then((evs) => setRecentEvents(evs)).catch(() => {});
            } catch (err) {
              console.error('Test bench error', err);
            } finally {
              setIsProcessing(false);
            }
          }}
          onStreamCustom={(rawText) => {
            setIsTestBenchOpen(false);
            streamSingleEvent(rawText, stageDelayMs);
          }}
        />
      )}

      {isHistoryOpen && (
        <HistoryDrawer
          isOpen={isHistoryOpen}
          onClose={() => setIsHistoryOpen(false)}
          onSelectEvent={(eventDetails) => {
            if (eventDetails.event_id) {
              handleInspectEventById(eventDetails.event_id);
            }
          }}
        />
      )}

      {isExportsOpen && (
        <ExportViewerModal
          isOpen={isExportsOpen}
          onClose={() => setIsExportsOpen(false)}
          exports={exports}
          context={context}
        />
      )}

    </div>
  );
};

export default App;
