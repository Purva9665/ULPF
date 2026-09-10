"""
ULPF Main FastAPI Backend Application
Exposes RESTful endpoints and real-time WebSockets for the Live Engine Control Room.
"""

import os
import asyncio
import json
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

# Ensure all parsers are loaded
import backend.parsers  # noqa: F401
from backend.core.models import (
    StageEnum,
    PipelineContext,
)
from backend.core.registry import default_registry
from backend.pipeline.orchestrator import PipelineOrchestrator
from backend.sample_data import SAMPLE_LOGS
from backend.detections.service import DetectionService

# Configurable persistent SQLite WAL DB path from environment
db_path = os.getenv("ULPF_DB_PATH", "ulpf_events.db")

# Global orchestrator instance with persistent disk SQLite WAL DB
orchestrator = PipelineOrchestrator(registry=default_registry, db_path=db_path)
detection_service = DetectionService()

# Background streamer task reference
stream_task: Optional[asyncio.Task] = None
is_streaming_active: bool = False
current_stream_eps: float = 2.0


class IngestRequest(BaseModel):
    raw_text: str = Field(..., description="Raw log text to ingest")
    source_protocol: str = Field(default="SYSLOG_UDP", description="Source protocol (SYSLOG, HTTP, VPC_FLOW, BEAT)")
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
    explicit_parser: Optional[str] = Field(default=None, description="Optional explicit parser override")


class StepRequest(BaseModel):
    context: Dict[str, Any] = Field(..., description="Current PipelineContext object")
    target_stage: StageEnum = Field(..., description="Next stage to execute")


class StreamControlRequest(BaseModel):
    action: str = Field(..., description="'start', 'stop', or 'set_eps'")
    eps: Optional[float] = Field(default=2.0, ge=0.2, le=50.0, description="Events Per Second")
    delay_ms: Optional[int] = Field(default=60, description="Delay between stages in ms")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Setup background tasks if needed
    yield
    # Cleanup background streamer on shutdown
    global is_streaming_active, stream_task
    is_streaming_active = False
    if stream_task and not stream_task.done():
        stream_task.cancel()


app = FastAPI(
    title="ULPF — Universal Log Pre-processing Framework API",
    description="Real-time perimeter network log pre-processing, normalization, validation, and ML anomaly engine",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for frontend Vite development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# REST API Endpoints
# ==========================================

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "ULPF Engine",
        "version": "1.0.0",
        "offline_mode": True,
        "storage_engine": "SQLite WAL (Persistent Volume)",
        "db_path": db_path,
        "ml_engine": "Local Scikit-Learn IsolationForest + Shannon Entropy",
        "parsers_loaded": len(default_registry.list_parsers()),
        "is_streaming": is_streaming_active,
        "current_eps": current_stream_eps,
    }


@app.get("/api/samples")
async def get_samples():
    """Retrieve authentic pre-packaged heterogeneous log samples."""
    return SAMPLE_LOGS


@app.get("/api/parsers")
async def list_parsers():
    """List all registered plug-and-play parsers."""
    return default_registry.list_parsers()


@app.post("/api/pipeline/process")
async def process_event(req: IngestRequest):
    """
    Synchronous end-to-end processing of a raw log.
    Returns complete PipelineContext with all intermediate stage snapshots.
    """
    try:
        ctx = orchestrator.process_sync(
            raw_text=req.raw_text,
            source_protocol=req.source_protocol,
            source_metadata=req.source_metadata,
            explicit_parser=req.explicit_parser,
        )
        exports = orchestrator.exporter_engine.export_all(ctx.final_event) if ctx.final_event else {}
        return {
            "success": ctx.is_completed,
            "context": ctx.model_dump(),
            "exports": exports,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/pipeline/stream-single")
async def stream_single_event(req: IngestRequest, delay_ms: int = Query(default=60, ge=0, le=500)):
    """
    Asynchronously streams an event stage-by-stage over the WebSocket.
    """
    asyncio.create_task(
        orchestrator.process_async_stream(
            raw_text=req.raw_text,
            source_protocol=req.source_protocol,
            source_metadata=req.source_metadata,
            explicit_parser=req.explicit_parser,
            delay_between_stages_ms=delay_ms,
        )
    )
    return {"message": "Streaming event execution dispatched"}


@app.post("/api/pipeline/step")
async def step_pipeline(req: StepRequest):
    """
    Step-by-step interactive debug progression: Advances the context by exactly ONE stage.
    """
    try:
        ctx = PipelineContext.model_validate(req.context)
        updated_ctx = orchestrator.step_stage(ctx, req.target_stage)
        return {
            "success": True,
            "context": updated_ctx.model_dump(),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Step execution error: {str(e)}")


@app.get("/api/events/{event_id}/export")
async def get_event_exports(event_id: str):
    """Export envelopes for a single processed event.

    The frontend fetches these separately from /api/pipeline/process so the
    export panel can be opened for any event still held in the pipeline
    buffer, not only the one just submitted.
    """
    ctx = orchestrator.get_buffered_context(event_id)
    if ctx is None or ctx.final_event is None:
        raise HTTPException(
            status_code=404,
            detail=f"No completed event {event_id} in the pipeline buffer",
        )
    return orchestrator.exporter_engine.export_all(ctx.final_event)


@app.get("/api/exports")
async def get_latest_exports():
    """Export envelopes for the most recently completed event."""
    for ctx in reversed(orchestrator.recent_contexts):
        if ctx.final_event is not None:
            return orchestrator.exporter_engine.export_all(ctx.final_event)
    return {}


@app.get("/api/events")
async def get_stored_events(limit: int = 50, offset: int = 0):
    """Retrieve stored events from SQLite WAL database."""
    return orchestrator.storage_engine.query_events(limit=limit, offset=offset)


@app.get("/api/events/{event_id}")
async def get_event_detail(event_id: str):
    """Retrieve complete event record by event_id."""
    event = orchestrator.storage_engine.get_event_by_id(event_id)
    if not event:
        # Check in memory buffer
        ctx = orchestrator.get_buffered_context(event_id)
        if ctx:
            return ctx.model_dump()
        raise HTTPException(status_code=404, detail="Event not found")
    
    # Parse stored JSON
    if "normalized_json" in event:
        try:
            event["normalized_json"] = json.loads(event["normalized_json"])
        except Exception:
            pass
    return event


@app.get("/api/stats")
async def get_stats():
    """Retrieve real-time engine metrics & storage statistics."""
    storage_stats = orchestrator.storage_engine.get_statistics()
    completed_durations = [
        c.total_duration_us for c in orchestrator.recent_contexts
        if c.is_completed and c.total_duration_us > 0
    ]
    avg_duration_us = (
        round(sum(completed_durations) / len(completed_durations), 1)
        if completed_durations
        else 320.0
    )
    failed_count = sum(1 for c in orchestrator.recent_contexts if c.error)

    return {
        "storage": storage_stats,
        "is_streaming": is_streaming_active,
        "current_eps": current_stream_eps,
        "parsers_count": len(default_registry.list_parsers()),
        "buffered_contexts_count": len(orchestrator.recent_contexts),
        "avg_duration_us": avg_duration_us,
        "total_processed": storage_stats.get("total_events", 0),
        "failed_count": failed_count,
    }


@app.get("/api/routing-stats")
async def get_routing_stats():
    """
    SIEM vs Data Lake routing statistics.
    Shows how many events were routed to SIEM vs Data Lake only.
    """
    return orchestrator.storage_engine.get_routing_stats()


@app.get("/api/events/siem")
async def get_siem_events(limit: int = 50, offset: int = 0):
    """Retrieve events from the SIEM database (security-relevant only)."""
    return orchestrator.storage_engine.query_siem_events(limit=limit, offset=offset)


@app.get("/api/events/datalake")
async def get_datalake_events(limit: int = 50, offset: int = 0):
    """Retrieve events from the Data Lake database (all events)."""
    return orchestrator.storage_engine.query_datalake_events(limit=limit, offset=offset)


@app.post("/api/stream/control")
async def control_stream(req: StreamControlRequest):
    """Controls the continuous live simulation stream."""
    global is_streaming_active, stream_task, current_stream_eps

    if req.action == "start":
        if not is_streaming_active:
            is_streaming_active = True
            current_stream_eps = req.eps or 2.0
            stream_task = asyncio.create_task(_background_streamer(current_stream_eps, req.delay_ms or 50))
        return {"status": "started", "eps": current_stream_eps}

    elif req.action == "stop":
        is_streaming_active = False
        if stream_task and not stream_task.done():
            stream_task.cancel()
        return {"status": "stopped"}

    elif req.action == "set_eps":
        current_stream_eps = req.eps or 2.0
        return {"status": "updated", "eps": current_stream_eps}

    else:
        raise HTTPException(status_code=400, detail=f"Unknown action '{req.action}'")


async def _background_streamer(eps: float, delay_ms: int):
    """Background task continuously feeding heterogeneous logs through the pipeline."""
    sample_index = 0
    while is_streaming_active:
        try:
            sample = SAMPLE_LOGS[sample_index % len(SAMPLE_LOGS)]
            sample_index += 1
            await orchestrator.process_async_stream(
                raw_text=sample["raw"],
                source_protocol="SYSLOG_UDP",
                source_metadata={"sample_id": sample["id"], "title": sample["title"]},
                delay_between_stages_ms=delay_ms,
            )
            # Sleep according to EPS
            sleep_time = max(0.01, 1.0 / max(0.1, current_stream_eps))
            await asyncio.sleep(sleep_time)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(0.5)


# ==========================================
# WebSocket Live Engine Endpoint
# ==========================================

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                dead_connections.append(connection)
        for dead in dead_connections:
            self.disconnect(dead)


ws_manager = ConnectionManager()

# Hook orchestrator broadcasts into WebSocket manager
async def _ws_listener(msg: Dict[str, Any]):
    await ws_manager.broadcast(msg)

orchestrator.add_listener(_ws_listener)


@app.websocket("/ws/live-engine")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send initial welcome and state
        await websocket.send_text(json.dumps({
            "type": "CONNECTION_ESTABLISHED",
            "message": "Connected to ULPF Live Engine Control Room",
            "parsers": default_registry.list_parsers(),
            "stats": orchestrator.storage_engine.get_statistics(),
        }))
        while True:
            # Handle incoming WebSocket commands from frontend
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                cmd = msg.get("command")
                if cmd == "PING":
                    await websocket.send_text(json.dumps({"type": "PONG"}))
                elif cmd == "TRIGGER_SAMPLE":
                    sample_id = msg.get("sample_id")
                    sample = next((s for s in SAMPLE_LOGS if s["id"] == sample_id), SAMPLE_LOGS[0])
                    asyncio.create_task(
                        orchestrator.process_async_stream(
                            raw_text=sample["raw"],
                            source_protocol="SYSLOG_UDP",
                            source_metadata={"sample_id": sample["id"], "title": sample["title"]},
                            delay_between_stages_ms=msg.get("delay_ms", 60),
                        )
                    )
            except Exception as e:
                await websocket.send_text(json.dumps({"type": "ERROR", "error": str(e)}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ==========================================
# Static Files & Offline Single-Port SPA Serving
# ==========================================
# Priority: ULPF_STATIC_DIR environment variable -> /app/static -> frontend/dist

# ---------------------------------------------------------------------------
# Detections API
#
# The product surface. Everything above this line reports on *events* the
# pipeline processed; these endpoints report on *findings* an analyst works.
# Registered before the SPA catch-all route, which would otherwise shadow them.
# ---------------------------------------------------------------------------

@app.post("/api/detections/analyse")
async def analyse_for_detections(req: IngestRequest):
    """Run one raw log line through the full detection stack."""
    try:
        ctx = orchestrator.process_sync(
            raw_text=req.raw_text,
            source_protocol=req.source_protocol,
            source_metadata=req.source_metadata,
            explicit_parser=req.explicit_parser,
            skip_ml=True,
        )
        if ctx.normalized_event is None:
            raise HTTPException(status_code=422, detail="Event could not be normalized")
        epoch = _epoch_of_event(ctx.normalized_event)
        return detection_service.analyse(ctx.normalized_event, epoch=epoch)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/detections")
async def list_detections(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    state: Optional[str] = None,
    severity: Optional[str] = None,
):
    """Prioritised detection queue - the product's home screen."""
    return detection_service.detections(limit=limit, offset=offset,
                                        state=state, severity=severity)


@app.get("/api/detections/summary")
async def detections_summary():
    """Volume, reduction ratio, and whether a trained model is in use."""
    return detection_service.summary()


@app.get("/api/detections/entities")
async def detection_entities(limit: int = Query(default=25, ge=1, le=200)):
    """Entities ranked by risk, for investigating by host rather than by alert."""
    return {"entities": detection_service.entities(limit=limit)}


@app.get("/api/detections/{detection_id}")
async def detection_detail(detection_id: str):
    detail = detection_service.detection(detection_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    return detail


@app.get("/api/detections/{detection_id}/evidence")
async def detection_evidence(detection_id: str):
    """Independently verifiable evidence bundle (raw bytes + hash chain)."""
    bundle = detection_service.evidence_bundle(detection_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    return bundle


class TriageRequest(BaseModel):
    state: str = Field(..., description="new | investigating | resolved_true_positive "
                                        "| resolved_false_positive | suppressed")
    note: str = Field(default="", description="Analyst note")


@app.post("/api/detections/{detection_id}/triage")
async def triage_detection(detection_id: str, req: TriageRequest):
    updated = detection_service.set_state(detection_id, req.state, req.note)
    if updated is None:
        raise HTTPException(status_code=404,
                            detail="Detection not found, or invalid state")
    return updated


@app.post("/api/detections/replay-samples")
async def replay_samples_into_detections():
    """Push the bundled sample logs through the detection stack.

    Gives the UI something real to show on a fresh start without needing the
    training corpus, which is not shipped in the repository.
    """
    processed, failed = 0, 0
    for sample in SAMPLE_LOGS:
        try:
            ctx = orchestrator.process_sync(raw_text=sample["raw"], skip_ml=True)
            if ctx.normalized_event is None:
                failed += 1
                continue
            detection_service.analyse(ctx.normalized_event,
                                      epoch=_epoch_of_event(ctx.normalized_event))
            processed += 1
        except Exception:
            failed += 1
    return {"processed": processed, "failed": failed,
            "summary": detection_service.summary()}


@app.post("/api/detections/reset")
async def reset_detections():
    detection_service.reset()
    return {"reset": True, "summary": detection_service.summary()}


def _epoch_of_event(norm) -> float:
    from backend.ml.features import _timestamp_parts
    try:
        return _timestamp_parts(norm)[0]
    except Exception:
        return 0.0


static_dir_candidate = os.getenv("ULPF_STATIC_DIR")
if not static_dir_candidate or not os.path.exists(static_dir_candidate):
    dist_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
    if os.path.exists(dist_path):
        static_dir_candidate = dist_path
    elif os.path.exists("/app/static"):
        static_dir_candidate = "/app/static"

if static_dir_candidate and os.path.exists(static_dir_candidate):
    assets_dir = os.path.join(static_dir_candidate, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        if full_path.startswith("api/") or full_path.startswith("ws/") or full_path.startswith("docs") or full_path.startswith("openapi.json"):
            raise HTTPException(status_code=404, detail="Not Found")
        
        target = os.path.join(static_dir_candidate, full_path)
        if full_path and os.path.isfile(target):
            return FileResponse(target)
        
        index_file = os.path.join(static_dir_candidate, "index.html")
        if os.path.isfile(index_file):
            return FileResponse(index_file)
        raise HTTPException(status_code=404, detail="Static index.html not found")

