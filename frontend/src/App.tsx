import React, { useState, useEffect, useRef } from 'react';
import type { 
  StageEnum, 
  PipelineContext, 
  EngineStats, 
  SampleLog, 
  ExportSchemas 
} from './types';
import { 
  fetchStats, 
  fetchSamples, 
  fetchExports, 
  fetchEventDetail,
  streamSingleEvent,
  stepPipelineStage,
  controlLiveStream,
  connectWebSocket,
  processEventSync
} from './api';

// Reusable Application Shell Components
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { TestBenchModal } from './components/TestBenchModal';
import { HistoryDrawer } from './components/HistoryDrawer';
import { ExportViewerModal } from './components/ExportViewerModal';

// Redesigned Workspaces & Views
import { DashboardView } from './views/DashboardView';
import { DemoView } from './views/DemoView';
import { IngestionView } from './views/IngestionView';
import { ParserView } from './views/ParserView';
import { NormalizationView } from './views/NormalizationView';
import { ValidationView } from './views/ValidationView';
import { StorageView } from './views/StorageView';
import { MLView } from './views/MLView';
import { ExportView } from './views/ExportView';
import { AnalyticsView } from './views/AnalyticsView';
import { LogExplorerView } from './views/LogExplorerView';
import { EventJourneyView } from './views/EventJourneyView';

export const App: React.FC = () => {
  // Navigation: 'overview' | 'ingestion' | 'parser' | 'normalization' | 'validation' | 'storage' | 'ml' | 'export' | 'analytics' | 'explorer' | 'journey'
  const [activeTab, setActiveTab] = useState<string>('demo');

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

  // Stats & Real Database Telemetry
  const [stats, setStats] = useState<EngineStats | null>(null);
  const [samples, setSamples] = useState<SampleLog[]>([]);
  const [selectedSampleId, setSelectedSampleId] = useState<string>('cisco_asa_smb_sweep');

  // Modals
  const [isTestBenchOpen, setIsTestBenchOpen] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);

  // Connection State
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  // Initial Data Fetch
  useEffect(() => {
    const loadInitial = async () => {
      try {
        const [statsData, samplesData] = await Promise.all([
          fetchStats(),
          fetchSamples(),
        ]);
        setStats(statsData);
        setSamples(samplesData);
        if (samplesData.length > 0) {
          setSelectedSampleId(samplesData[0].id);
        }
      } catch (err) {
        console.error('Failed to load initial engine data', err);
      }
    };
    loadInitial();
  }, []);

  // WebSocket Connection
  useEffect(() => {
    const ws = connectWebSocket(
      (msg) => {
        handleWebSocketMessage(msg);
      },
      () => setIsConnected(true),
      () => setIsConnected(false),
      (err) => console.error('WS Error:', err)
    );
    wsRef.current = ws;

    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  // Handle incoming WebSocket messages
  const handleWebSocketMessage = (msg: any) => {
    if (msg.type === 'STAGE_TRANSITION') {
      if (msg.stage) {
        setActiveTransitionStage(msg.stage);
        setSelectedStage(msg.stage);
      }
      if (msg.context) {
        setContext(msg.context);
      }
    } else if (msg.type === 'EVENT_COMPLETED') {
      setActiveTransitionStage(null);
      if (msg.context) {
        setContext(msg.context);
      }
      if (msg.stats) {
        setStats(msg.stats);
      }
      if (msg.exports) {
        setExports(msg.exports);
      }
      setIsProcessing(false);
    } else if (msg.type === 'STATS_UPDATE') {
      if (msg.stats) {
        setStats(msg.stats);
      }
    }
  };

  const getActiveSampleRaw = () => {
    const s = samples.find((x) => x.id === selectedSampleId);
    return s ? s.raw : "%ASA-4-106023: Deny tcp src outside:198.51.100.99/50123 dst inside:10.0.0.5/445 by access-group 'OUTSIDE-IN' [0x0, 0x0]";
  };

  // Actions
  const handleTriggerSingle = async () => {
    setIsProcessing(true);
    try {
      const raw = getActiveSampleRaw();
      const res = await streamSingleEvent(raw, stageDelayMs);
      if (res.context) {
        setContext(res.context);
        const exportsData = await fetchExports(res.context.event_id);
        setExports(exportsData);
      }
      const updatedStats = await fetchStats();
      setStats(updatedStats);
    } catch (err) {
      console.error('Single event error', err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleToggleStream = async () => {
    const nextState = !isStreaming;
    setIsStreaming(nextState);
    try {
      await controlLiveStream(nextState ? 'start' : 'stop', eps, stageDelayMs);
    } catch (err) {
      console.error('Stream toggle error', err);
      setIsStreaming(!nextState);
    }
  };

  const handleSetEps = async (newEps: number) => {
    setEps(newEps);
    if (isStreaming) {
      try {
        await controlLiveStream('set_eps', newEps, stageDelayMs);
      } catch (err) {
        console.error('Set EPS error', err);
      }
    }
  };

  const ALL_STAGES: StageEnum[] = ['INGEST', 'PARSE', 'NORMALIZE', 'VALIDATE', 'STORE', 'ML', 'STANDARDIZED'];

  const handleSetMode = (newMode: 'STREAM' | 'DEBUG') => {
    setMode(newMode);
    if (newMode === 'DEBUG') {
      if (isStreaming) {
        setIsStreaming(false);
        controlLiveStream('stop').catch(() => {});
      }
    }
  };

  const handleStepForward = async () => {
    setIsProcessing(true);
    try {
      const raw = getActiveSampleRaw();

      // Case 1: Start a new event stepping at Stage 01: INGEST ONLY
      if (!context || context.is_completed || !context.stages_completed || context.stages_completed.length === 0) {
        const eventId = typeof crypto !== 'undefined' && crypto.randomUUID 
          ? crypto.randomUUID() 
          : 'evt_' + Math.random().toString(36).substring(2, 10);
        
        let sha256Hex = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        if (typeof crypto !== 'undefined' && crypto.subtle) {
          try {
            const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw));
            sha256Hex = Array.from(new Uint8Array(buf))
              .map((b) => b.toString(16).padStart(2, '0'))
              .join('');
          } catch (e) {
            // fallback
          }
        }

        const rawLength = new TextEncoder().encode(raw).length;

        const initialIngestContext: PipelineContext = {
          event_id: eventId,
          current_stage: 'INGEST',
          stages_completed: ['INGEST'],
          raw_event: {
            event_id: eventId,
            ingested_at: new Date().toISOString(),
            raw: {
              payload: raw,
              sha256_hash: sha256Hex,
              encoding: 'UTF-8',
              length_bytes: rawLength,
              source_protocol: 'SYSLOG_UDP',
            },
            source_metadata: {},
          },
          stage_metrics: [
            {
              stage: 'INGEST',
              status: 'COMPLETED',
              start_time_us: 0,
              duration_us: 18,
              message: `Ingested ${rawLength} bytes with SHA-256 cryptographic digest`,
              details: { length: rawLength, protocol: 'SYSLOG_UDP', sha256: sha256Hex },
            },
          ],
          total_duration_us: 18,
          is_completed: false,
        };

        setContext(initialIngestContext);
        setSelectedStage('INGEST');
        setExports(null);
      } else {
        // Case 2: Advance to the NEXT single stage in sequence
        const completed = context.stages_completed || [];
        const completedCount = completed.length;

        if (completedCount < ALL_STAGES.length) {
          const nextStage = ALL_STAGES[completedCount];
          const res = await stepPipelineStage(context, nextStage);
          
          if (res && res.context) {
            setContext(res.context);
            setSelectedStage(nextStage);

            // If final stage reached, load exports
            if (nextStage === 'STANDARDIZED' || res.context.is_completed) {
              try {
                const exp = await fetchExports(res.context.event_id);
                setExports(exp);
              } catch (e) {
                // ignore
              }
            }
          }
        }
      }

      const updatedStats = await fetchStats();
      setStats(updatedStats);
    } catch (err) {
      console.error('Step forward error', err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleFastForward = async () => {
    setIsProcessing(true);
    try {
      const raw = getActiveSampleRaw();
      const res = await processEventSync(raw);
      setContext(res.context);
      setExports(res.exports);
      setSelectedStage('STANDARDIZED');
      const updatedStats = await fetchStats();
      setStats(updatedStats);
    } catch (err) {
      console.error('Fast forward error', err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleReset = async () => {
    setContext(null);
    setSelectedStage('INGEST');
    setExports(null);
    try {
      const updatedStats = await fetchStats();
      setStats(updatedStats);
    } catch (err) {
      console.error('Reset error', err);
    }
  };

  const handleInspectEventById = async (eventId: string) => {
    try {
      const detail = await fetchEventDetail(eventId);
      if (detail && detail.pipeline_context) {
        setContext(detail.pipeline_context);
      }
    } catch (err) {
      console.error('Failed to load event detail', err);
    }
  };

  const canStepForward = !context || (context.stages_completed?.length || 0) < 7 || context.is_completed;

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-app)' }}>
      
      {/* 1. Sleek Left Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        stats={stats}
        isConnected={isConnected}
        onOpenTestBench={() => setIsTestBenchOpen(true)}
        onOpenHistory={() => setIsHistoryOpen(true)}
        onOpenExports={() => setIsExportModalOpen(true)}
      />

      {/* 2. Main Content Container with Sticky TopBar */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        
        <TopBar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          stats={stats}
          isConnected={isConnected}
          onOpenTestBench={() => setIsTestBenchOpen(true)}
          onOpenHistory={() => setIsHistoryOpen(true)}
          onOpenExports={() => setIsExportModalOpen(true)}
        />

        <main style={{ padding: '24px 28px', flex: 1, display: 'flex', flexDirection: 'column' }}>
          
          {/* OVERVIEW / DASHBOARD */}
          {activeTab === 'demo' && <DemoView />}

          {activeTab === 'overview' && (
            <DashboardView
              context={context}
              stats={stats}
              selectedStage={selectedStage}
              onSelectStage={setSelectedStage}
              activeTransitionStage={activeTransitionStage}
              mode={mode}
              onSetMode={handleSetMode}
              isStreaming={isStreaming}
              onToggleStream={handleToggleStream}
              eps={eps}
              onSetEps={handleSetEps}
              samples={samples}
              selectedSampleId={selectedSampleId}
              onSelectSample={setSelectedSampleId}
              onTriggerSingleEvent={handleTriggerSingle}
              onStepForward={handleStepForward}
              onResetStepper={handleReset}
              onFastForward={handleFastForward}
              canStepForward={canStepForward}
              isProcessing={isProcessing}
              onInspectEvent={handleInspectEventById}
              onGoToStage={setActiveTab}
              onGoToJourney={(eventId) => {
                handleInspectEventById(eventId);
                setActiveTab('journey');
              }}
            />
          )}

          {/* STAGE 01: INGESTION */}
          {activeTab === 'ingestion' && (
            <IngestionView
              context={context}
              stats={stats}
              onBackToOverview={() => setActiveTab('overview')}
              onRunCustomIngest={async (raw) => {
                setIsProcessing(true);
                try {
                  const res = await processEventSync(raw);
                  if (res.context) setContext(res.context);
                  if (res.exports) setExports(res.exports);
                  const updatedStats = await fetchStats();
                  setStats(updatedStats);
                } catch (e) {
                  console.error(e);
                } finally {
                  setIsProcessing(false);
                }
              }}
              samples={samples}
            />
          )}

          {/* STAGE 02: PARSER */}
          {activeTab === 'parser' && (
            <ParserView
              context={context}
              stats={stats}
              onBackToOverview={() => setActiveTab('overview')}
              onSelectSample={(sampleId) => {
                setSelectedSampleId(sampleId);
                handleTriggerSingle();
              }}
              samples={samples}
            />
          )}

          {/* STAGE 03: NORMALIZATION */}
          {activeTab === 'normalization' && (
            <NormalizationView
              context={context}
              stats={stats}
              onBackToOverview={() => setActiveTab('overview')}
            />
          )}

          {/* STAGE 04: VALIDATION / DQI */}
          {activeTab === 'validation' && (
            <ValidationView
              context={context}
              stats={stats}
              onBackToOverview={() => setActiveTab('overview')}
            />
          )}

          {/* STAGE 05: STORAGE (SQLITE WAL) */}
          {activeTab === 'storage' && (
            <StorageView
              context={context}
              stats={stats}
              onBackToOverview={() => setActiveTab('overview')}
              onSelectEventId={handleInspectEventById}
            />
          )}

          {/* STAGE 06: ML ANOMALY & ENTROPY */}
          {activeTab === 'ml' && (
            <MLView
              context={context}
              stats={stats}
              onBackToOverview={() => setActiveTab('overview')}
            />
          )}

          {/* STAGE 07: EXPORT */}
          {activeTab === 'export' && (
            <ExportView
              context={context}
              stats={stats}
              exports={exports}
              onBackToOverview={() => setActiveTab('overview')}
            />
          )}

          {/* ANALYTICS VIEW */}
          {activeTab === 'analytics' && (
            <AnalyticsView
              stats={stats}
              onBackToOverview={() => setActiveTab('overview')}
            />
          )}

          {/* LOG EXPLORER VIEW */}
          {activeTab === 'explorer' && (
            <LogExplorerView
              stats={stats}
              onBackToOverview={() => setActiveTab('overview')}
              onInspectEvent={handleInspectEventById}
              onGoToJourney={(eventId) => {
                handleInspectEventById(eventId);
                setActiveTab('journey');
              }}
            />
          )}

          {/* EVENT JOURNEY VIEW */}
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

      </div>

      {/* Global Modals */}
      {isTestBenchOpen && (
        <TestBenchModal
          isOpen={isTestBenchOpen}
          onClose={() => setIsTestBenchOpen(false)}
          samples={samples}
          onRunCustom={async (rawText, explicitParser) => {
            setIsTestBenchOpen(false);
            setIsProcessing(true);
            try {
              const res = await processEventSync(rawText, 'HTTP_REST', {}, explicitParser);
              if (res.context) setContext(res.context);
              if (res.exports) setExports(res.exports);
              const updatedStats = await fetchStats();
              setStats(updatedStats);
            } catch (err) {
              console.error('Test Bench execution failed', err);
            } finally {
              setIsProcessing(false);
            }
          }}
          onStreamCustom={async (rawText) => {
            setIsTestBenchOpen(false);
            setIsProcessing(true);
            try {
              const res = await streamSingleEvent(rawText, stageDelayMs);
              if (res.context) setContext(res.context);
              const updatedStats = await fetchStats();
              setStats(updatedStats);
            } catch (err) {
              console.error('Stream custom error', err);
            } finally {
              setIsProcessing(false);
            }
          }}
        />
      )}

      {isHistoryOpen && (
        <HistoryDrawer
          isOpen={isHistoryOpen}
          onClose={() => setIsHistoryOpen(false)}
          onSelectEvent={handleInspectEventById}
        />
      )}

      {isExportModalOpen && (
        <ExportViewerModal
          isOpen={isExportModalOpen}
          onClose={() => setIsExportModalOpen(false)}
          exports={exports}
          context={context}
        />
      )}

    </div>
  );
};

export default App;
