"""
ULPF Pipeline Orchestrator
Master state machine coordinating real stage executions, microsecond telemetry, and live WebSocket streaming.
"""

import time
import asyncio
from typing import Dict, Any, List, Optional, Callable, Awaitable
from backend.core.models import (
    StageEnum,
    StageStatus,
    PipelineContext,
    StageExecutionMetrics,
    ULPFRawEvent,
    ULPFParsedEvent,
    ULPFNormalizedEvent,
    ULPFValidatedEvent,
    ULPFStoredEvent,
    ULPFMLEvent,
    ULPFFinalEvent,
)
from backend.core.registry import default_registry, ParserRegistry
from backend.ingestion.engine import IngestionEngine
from backend.normalizer.engine import NormalizationEngine
from backend.validator.engine import ValidationEngine
from backend.storage.engine import StorageEngine
from backend.ml.anomaly_engine import MLAnomalyEngine
from backend.exporter.engine import ExporterEngine


class PipelineOrchestrator:
    """
    Master coordinator of the ULPF processing pipeline.
    Executes real backend stage transitions, computes microsecond benchmarks, and broadcasts live state updates.
    """

    def __init__(
        self,
        registry: Optional[ParserRegistry] = None,
        db_path: str = ":memory:",
    ):
        self.registry = registry or default_registry
        self.ingestion_engine = IngestionEngine()
        self.normalizer_engine = NormalizationEngine()
        self.validator_engine = ValidationEngine()
        self.storage_engine = StorageEngine(db_path=db_path)
        self.ml_engine = MLAnomalyEngine()
        self.exporter_engine = ExporterEngine()

        # Ring buffer for recent event contexts (for UI playback/inspection)
        self.recent_contexts: List[PipelineContext] = []
        self.max_buffer_size = 200

        # Optional listener callbacks for WebSocket streaming
        self.listeners: List[Callable[[Dict[str, Any]], Awaitable[None]]] = []

    def add_listener(self, callback: Callable[[Dict[str, Any]], Awaitable[None]]) -> None:
        self.listeners.append(callback)

    def remove_listener(self, callback: Callable[[Dict[str, Any]], Awaitable[None]]) -> None:
        if callback in self.listeners:
            self.listeners.remove(callback)

    async def _broadcast(self, msg: Dict[str, Any]) -> None:
        """Broadcast state event to all connected WebSocket clients."""
        for listener in list(self.listeners):
            try:
                await listener(msg)
            except Exception:
                pass

    def process_sync(
        self,
        raw_text: str,
        source_protocol: str = "SYSLOG_UDP",
        source_metadata: Optional[Dict[str, Any]] = None,
        explicit_parser: Optional[str] = None,
    ) -> PipelineContext:
        """
        Executes the entire pipeline synchronously from INGEST to EXPORT.
        Returns complete PipelineContext with all intermediate stage snapshots.
        """
        pipeline_t0 = time.perf_counter_ns()

        # Initialize Context
        raw_event = self.ingestion_engine.ingest(
            raw_text=raw_text,
            source_protocol=source_protocol,
            source_metadata=source_metadata,
        )
        
        ctx = PipelineContext(
            event_id=raw_event.event_id,
            current_stage=StageEnum.INGEST,
            raw_event=raw_event,
        )

        # Stage 1: INGEST
        t0 = time.perf_counter_ns()
        # Ingestion already produced raw_event
        t1 = time.perf_counter_ns()
        ctx.stages_completed.append(StageEnum.INGEST)
        ctx.stage_metrics.append(
            StageExecutionMetrics(
                stage=StageEnum.INGEST,
                status=StageStatus.COMPLETED,
                start_time_us=0,
                duration_us=(t1 - t0) // 1000,
                message=f"Ingested {raw_event.raw.length_bytes} bytes with SHA-256 integrity hash",
                details={
                    "sha256": raw_event.raw.sha256_hash,
                    "length": raw_event.raw.length_bytes,
                    "protocol": raw_event.raw.source_protocol,
                }
            )
        )

        try:
            # Stage 2: PARSE
            ctx.current_stage = StageEnum.PARSE
            t0 = time.perf_counter_ns()
            if explicit_parser:
                parsed_event = self.registry.parse_with(raw_event, explicit_parser)
            else:
                parsed_event, _, confidence = self.registry.auto_detect_and_parse(raw_event)
            t1 = time.perf_counter_ns()
            ctx.parsed_event = parsed_event
            ctx.stages_completed.append(StageEnum.PARSE)
            ctx.stage_metrics.append(
                StageExecutionMetrics(
                    stage=StageEnum.PARSE,
                    status=StageStatus.COMPLETED,
                    start_time_us=(t0 - pipeline_t0) // 1000,
                    duration_us=(t1 - t0) // 1000,
                    message=f"Parsed using {parsed_event.parser_name} ({len(parsed_event.extracted_fields)} fields)",
                    details={
                        "parser": parsed_event.parser_name,
                        "vendor": parsed_event.parser_vendor,
                        "fields_count": len(parsed_event.extracted_fields),
                        "tokens_count": len(parsed_event.tokens),
                    }
                )
            )

            # Stage 3: NORMALIZE
            ctx.current_stage = StageEnum.NORMALIZE
            t0 = time.perf_counter_ns()
            norm_event = self.normalizer_engine.normalize(parsed_event)
            t1 = time.perf_counter_ns()
            ctx.normalized_event = norm_event
            ctx.stages_completed.append(StageEnum.NORMALIZE)
            ctx.stage_metrics.append(
                StageExecutionMetrics(
                    stage=StageEnum.NORMALIZE,
                    status=StageStatus.COMPLETED,
                    start_time_us=(t0 - pipeline_t0) // 1000,
                    duration_us=(t1 - t0) // 1000,
                    message=f"Normalized to canonical schema with {len(norm_event.unmapped_fields)} unmapped attributes preserved",
                    details={
                        "action": norm_event.event.action.value,
                        "severity": norm_event.event.severity.value,
                        "src": f"{norm_event.source.ip}:{norm_event.source.port}",
                        "dst": f"{norm_event.destination.ip}:{norm_event.destination.port}",
                        "unmapped_count": len(norm_event.unmapped_fields),
                    }
                )
            )

            # Stage 4: VALIDATE
            ctx.current_stage = StageEnum.VALIDATE
            t0 = time.perf_counter_ns()
            val_event = self.validator_engine.validate(norm_event)
            t1 = time.perf_counter_ns()
            ctx.validated_event = val_event
            ctx.stages_completed.append(StageEnum.VALIDATE)
            ctx.stage_metrics.append(
                StageExecutionMetrics(
                    stage=StageEnum.VALIDATE,
                    status=StageStatus.COMPLETED if val_event.is_valid else StageStatus.WARNING,
                    start_time_us=(t0 - pipeline_t0) // 1000,
                    duration_us=(t1 - t0) // 1000,
                    message=f"Validated with DQI score {val_event.data_quality_score}% ({len(val_event.validation_checks)} rules evaluated)",
                    details={
                        "dqi": val_event.data_quality_score,
                        "hash_verified": val_event.hash_verified,
                        "checks_passed": sum(1 for c in val_event.validation_checks if c.passed),
                        "total_checks": len(val_event.validation_checks),
                    }
                )
            )

            # Stage 5: STORE
            ctx.current_stage = StageEnum.STORE
            t0 = time.perf_counter_ns()
            stored_event = self.storage_engine.store(val_event)
            t1 = time.perf_counter_ns()
            ctx.stored_event = stored_event
            ctx.stages_completed.append(StageEnum.STORE)
            ctx.stage_metrics.append(
                StageExecutionMetrics(
                    stage=StageEnum.STORE,
                    status=StageStatus.COMPLETED,
                    start_time_us=(t0 - pipeline_t0) // 1000,
                    duration_us=(t1 - t0) // 1000,
                    message=f"Stored in SQLite WAL (Compression: {stored_event.storage.compression_ratio}% reduction)",
                    details={
                        "raw_bytes": stored_event.storage.raw_size_bytes,
                        "comp_bytes": stored_event.storage.compressed_size_bytes,
                        "compression_ratio": stored_event.storage.compression_ratio,
                    }
                )
            )

            # Stage 6: ML
            ctx.current_stage = StageEnum.ML
            t0 = time.perf_counter_ns()
            ml_event = self.ml_engine.analyze(stored_event)
            t1 = time.perf_counter_ns()
            ctx.ml_event = ml_event
            ctx.stages_completed.append(StageEnum.ML)
            
            # Update storage with anomaly score
            self.storage_engine.update_ml_scores(
                event_id=ctx.event_id,
                anomaly_score=ml_event.ml.anomaly_score,
                is_anomalous=ml_event.ml.is_anomalous,
            )

            ctx.stage_metrics.append(
                StageExecutionMetrics(
                    stage=StageEnum.ML,
                    status=StageStatus.COMPLETED,
                    start_time_us=(t0 - pipeline_t0) // 1000,
                    duration_us=(t1 - t0) // 1000,
                    message=f"ML Anomaly Score: {ml_event.ml.anomaly_score:.2f} ({ml_event.ml.risk_level.value} Risk, Entropy: {ml_event.ml.shannon_entropy})",
                    details={
                        "anomaly_score": ml_event.ml.anomaly_score,
                        "is_anomalous": ml_event.ml.is_anomalous,
                        "risk_level": ml_event.ml.risk_level.value,
                        "entropy": ml_event.ml.shannon_entropy,
                        "top_factors": [f.feature for f in ml_event.ml.feature_contributions[:2]],
                    }
                )
            )

            # Stage 7: FINAL STANDARDIZED & EXPORT READY
            ctx.current_stage = StageEnum.STANDARDIZED
            t_final = time.perf_counter_ns()
            total_duration_us = (t_final - pipeline_t0) // 1000
            ctx.total_duration_us = total_duration_us
            ctx.is_completed = True

            final_event = ULPFFinalEvent(
                ulpf_version="1.0.0",
                event_id=ctx.event_id,
                event=norm_event.event,
                source=norm_event.source,
                destination=norm_event.destination,
                network=norm_event.network,
                threat=norm_event.threat,
                observer=norm_event.observer,
                raw_event=raw_event.raw,
                unmapped_fields=norm_event.unmapped_fields,
                ml_analysis=ml_event.ml,
                validation={
                    "is_valid": val_event.is_valid,
                    "data_quality_score": val_event.data_quality_score,
                    "hash_verified": val_event.hash_verified,
                },
                storage=stored_event.storage,
                pipeline_telemetry={
                    "total_duration_us": total_duration_us,
                    "stages_count": len(ctx.stages_completed),
                },
            )
            ctx.final_event = final_event
            ctx.stages_completed.append(StageEnum.STANDARDIZED)

        except Exception as e:
            ctx.error = str(e)
            ctx.stage_metrics.append(
                StageExecutionMetrics(
                    stage=ctx.current_stage,
                    status=StageStatus.ERROR,
                    start_time_us=0,
                    duration_us=0,
                    message=f"Pipeline exception: {str(e)}",
                )
            )

        # Store in buffer
        self._add_to_buffer(ctx)
        return ctx

    async def process_async_stream(
        self,
        raw_text: str,
        source_protocol: str = "SYSLOG_UDP",
        source_metadata: Optional[Dict[str, Any]] = None,
        explicit_parser: Optional[str] = None,
        delay_between_stages_ms: int = 40,
    ) -> PipelineContext:
        """
        Executes pipeline stage-by-stage with real state dispatches over WebSocket.
        Gives the frontend a genuine visual feed of the backend engine moving through each stage.
        """
        pipeline_t0 = time.perf_counter_ns()

        # Step 1: Ingest
        raw_event = self.ingestion_engine.ingest(
            raw_text=raw_text,
            source_protocol=source_protocol,
            source_metadata=source_metadata,
        )
        ctx = PipelineContext(
            event_id=raw_event.event_id,
            current_stage=StageEnum.INGEST,
            raw_event=raw_event,
        )
        t0 = time.perf_counter_ns()
        t1 = time.perf_counter_ns()
        ctx.stages_completed.append(StageEnum.INGEST)
        ingest_metric = StageExecutionMetrics(
            stage=StageEnum.INGEST,
            status=StageStatus.COMPLETED,
            start_time_us=0,
            duration_us=(t1 - t0) // 1000,
            message=f"Ingested {raw_event.raw.length_bytes} bytes (SHA-256: {raw_event.raw.sha256_hash[:8]}...)",
            details={"sha256": raw_event.raw.sha256_hash, "length": raw_event.raw.length_bytes}
        )
        ctx.stage_metrics.append(ingest_metric)

        await self._broadcast({
            "type": "STAGE_TRANSITION",
            "event_id": ctx.event_id,
            "stage": StageEnum.INGEST,
            "status": StageStatus.COMPLETED,
            "metric": ingest_metric.model_dump(),
            "snapshot": {"raw": raw_event.raw.model_dump()},
        })

        if delay_between_stages_ms > 0:
            await asyncio.sleep(delay_between_stages_ms / 1000.0)

        # Step 2: Parse
        ctx.current_stage = StageEnum.PARSE
        t0 = time.perf_counter_ns()
        if explicit_parser:
            parsed_event = self.registry.parse_with(raw_event, explicit_parser)
        else:
            parsed_event, _, _ = self.registry.auto_detect_and_parse(raw_event)
        t1 = time.perf_counter_ns()
        ctx.parsed_event = parsed_event
        ctx.stages_completed.append(StageEnum.PARSE)
        parse_metric = StageExecutionMetrics(
            stage=StageEnum.PARSE,
            status=StageStatus.COMPLETED,
            start_time_us=(t0 - pipeline_t0) // 1000,
            duration_us=(t1 - t0) // 1000,
            message=f"Parsed with {parsed_event.parser_name}",
            details={"parser": parsed_event.parser_name, "fields": len(parsed_event.extracted_fields)}
        )
        ctx.stage_metrics.append(parse_metric)

        await self._broadcast({
            "type": "STAGE_TRANSITION",
            "event_id": ctx.event_id,
            "stage": StageEnum.PARSE,
            "status": StageStatus.COMPLETED,
            "metric": parse_metric.model_dump(),
            "snapshot": {"extracted_fields": parsed_event.extracted_fields, "tokens": parsed_event.tokens[:8]},
        })

        if delay_between_stages_ms > 0:
            await asyncio.sleep(delay_between_stages_ms / 1000.0)

        # Step 3: Normalize
        ctx.current_stage = StageEnum.NORMALIZE
        t0 = time.perf_counter_ns()
        norm_event = self.normalizer_engine.normalize(parsed_event)
        t1 = time.perf_counter_ns()
        ctx.normalized_event = norm_event
        ctx.stages_completed.append(StageEnum.NORMALIZE)
        norm_metric = StageExecutionMetrics(
            stage=StageEnum.NORMALIZE,
            status=StageStatus.COMPLETED,
            start_time_us=(t0 - pipeline_t0) // 1000,
            duration_us=(t1 - t0) // 1000,
            message=f"Normalized ({norm_event.event.action.value} / {norm_event.event.severity.value})",
            details={"action": norm_event.event.action.value, "unmapped": len(norm_event.unmapped_fields)}
        )
        ctx.stage_metrics.append(norm_metric)

        await self._broadcast({
            "type": "STAGE_TRANSITION",
            "event_id": ctx.event_id,
            "stage": StageEnum.NORMALIZE,
            "status": StageStatus.COMPLETED,
            "metric": norm_metric.model_dump(),
            "snapshot": {
                "event": norm_event.event.model_dump(),
                "source": norm_event.source.model_dump(),
                "destination": norm_event.destination.model_dump(),
                "unmapped": norm_event.unmapped_fields,
            }
        })

        if delay_between_stages_ms > 0:
            await asyncio.sleep(delay_between_stages_ms / 1000.0)

        # Step 4: Validate
        ctx.current_stage = StageEnum.VALIDATE
        t0 = time.perf_counter_ns()
        val_event = self.validator_engine.validate(norm_event)
        t1 = time.perf_counter_ns()
        ctx.validated_event = val_event
        ctx.stages_completed.append(StageEnum.VALIDATE)
        val_metric = StageExecutionMetrics(
            stage=StageEnum.VALIDATE,
            status=StageStatus.COMPLETED if val_event.is_valid else StageStatus.WARNING,
            start_time_us=(t0 - pipeline_t0) // 1000,
            duration_us=(t1 - t0) // 1000,
            message=f"Validated (DQI: {val_event.data_quality_score}%)",
            details={"dqi": val_event.data_quality_score, "passed": sum(1 for c in val_event.validation_checks if c.passed)}
        )
        ctx.stage_metrics.append(val_metric)

        await self._broadcast({
            "type": "STAGE_TRANSITION",
            "event_id": ctx.event_id,
            "stage": StageEnum.VALIDATE,
            "status": StageStatus.COMPLETED if val_event.is_valid else StageStatus.WARNING,
            "metric": val_metric.model_dump(),
            "snapshot": {
                "dqi": val_event.data_quality_score,
                "checks": [c.model_dump() for c in val_event.validation_checks],
            }
        })

        if delay_between_stages_ms > 0:
            await asyncio.sleep(delay_between_stages_ms / 1000.0)

        # Step 5: Store
        ctx.current_stage = StageEnum.STORE
        t0 = time.perf_counter_ns()
        stored_event = self.storage_engine.store(val_event)
        t1 = time.perf_counter_ns()
        ctx.stored_event = stored_event
        ctx.stages_completed.append(StageEnum.STORE)
        store_metric = StageExecutionMetrics(
            stage=StageEnum.STORE,
            status=StageStatus.COMPLETED,
            start_time_us=(t0 - pipeline_t0) // 1000,
            duration_us=(t1 - t0) // 1000,
            message=f"Indexed in SQLite WAL ({stored_event.storage.compression_ratio}% reduction)",
            details={"compression": stored_event.storage.compression_ratio}
        )
        ctx.stage_metrics.append(store_metric)

        await self._broadcast({
            "type": "STAGE_TRANSITION",
            "event_id": ctx.event_id,
            "stage": StageEnum.STORE,
            "status": StageStatus.COMPLETED,
            "metric": store_metric.model_dump(),
            "snapshot": stored_event.storage.model_dump(),
        })

        if delay_between_stages_ms > 0:
            await asyncio.sleep(delay_between_stages_ms / 1000.0)

        # Step 6: ML
        ctx.current_stage = StageEnum.ML
        t0 = time.perf_counter_ns()
        ml_event = self.ml_engine.analyze(stored_event)
        t1 = time.perf_counter_ns()
        ctx.ml_event = ml_event
        ctx.stages_completed.append(StageEnum.ML)

        self.storage_engine.update_ml_scores(
            event_id=ctx.event_id,
            anomaly_score=ml_event.ml.anomaly_score,
            is_anomalous=ml_event.ml.is_anomalous,
        )

        ml_metric = StageExecutionMetrics(
            stage=StageEnum.ML,
            status=StageStatus.COMPLETED,
            start_time_us=(t0 - pipeline_t0) // 1000,
            duration_us=(t1 - t0) // 1000,
            message=f"Anomaly: {ml_event.ml.anomaly_score:.2f} ({ml_event.ml.risk_level.value})",
            details={"score": ml_event.ml.anomaly_score, "entropy": ml_event.ml.shannon_entropy}
        )
        ctx.stage_metrics.append(ml_metric)

        await self._broadcast({
            "type": "STAGE_TRANSITION",
            "event_id": ctx.event_id,
            "stage": StageEnum.ML,
            "status": StageStatus.COMPLETED,
            "metric": ml_metric.model_dump(),
            "snapshot": ml_event.ml.model_dump(),
        })

        # Step 7: Standardized Final Event
        t_final = time.perf_counter_ns()
        ctx.total_duration_us = (t_final - pipeline_t0) // 1000
        ctx.is_completed = True
        ctx.current_stage = StageEnum.STANDARDIZED
        ctx.stages_completed.append(StageEnum.STANDARDIZED)

        final_event = ULPFFinalEvent(
            ulpf_version="1.0.0",
            event_id=ctx.event_id,
            event=norm_event.event,
            source=norm_event.source,
            destination=norm_event.destination,
            network=norm_event.network,
            threat=norm_event.threat,
            observer=norm_event.observer,
            raw_event=raw_event.raw,
            unmapped_fields=norm_event.unmapped_fields,
            ml_analysis=ml_event.ml,
            validation={
                "is_valid": val_event.is_valid,
                "data_quality_score": val_event.data_quality_score,
                "hash_verified": val_event.hash_verified,
            },
            storage=stored_event.storage,
            pipeline_telemetry={"total_duration_us": ctx.total_duration_us},
        )
        ctx.final_event = final_event

        exports = self.exporter_engine.export_all(final_event)

        await self._broadcast({
            "type": "EVENT_COMPLETED",
            "event_id": ctx.event_id,
            "context": ctx.model_dump(),
            "exports": exports,
        })

        self._add_to_buffer(ctx)
        return ctx

    def step_stage(self, ctx: PipelineContext, next_stage: StageEnum) -> PipelineContext:
        """
        Step-by-step debugger progression: Executes just ONE stage and returns the updated context.
        """
        if next_stage == StageEnum.PARSE and ctx.raw_event:
            parsed, _, _ = self.registry.auto_detect_and_parse(ctx.raw_event)
            ctx.parsed_event = parsed
            ctx.current_stage = StageEnum.PARSE
            if StageEnum.PARSE not in ctx.stages_completed:
                ctx.stages_completed.append(StageEnum.PARSE)

        elif next_stage == StageEnum.NORMALIZE and ctx.parsed_event:
            norm = self.normalizer_engine.normalize(ctx.parsed_event)
            ctx.normalized_event = norm
            ctx.current_stage = StageEnum.NORMALIZE
            if StageEnum.NORMALIZE not in ctx.stages_completed:
                ctx.stages_completed.append(StageEnum.NORMALIZE)

        elif next_stage == StageEnum.VALIDATE and ctx.normalized_event:
            val = self.validator_engine.validate(ctx.normalized_event)
            ctx.validated_event = val
            ctx.current_stage = StageEnum.VALIDATE
            if StageEnum.VALIDATE not in ctx.stages_completed:
                ctx.stages_completed.append(StageEnum.VALIDATE)

        elif next_stage == StageEnum.STORE and ctx.validated_event:
            stored = self.storage_engine.store(ctx.validated_event)
            ctx.stored_event = stored
            ctx.current_stage = StageEnum.STORE
            if StageEnum.STORE not in ctx.stages_completed:
                ctx.stages_completed.append(StageEnum.STORE)

        elif next_stage == StageEnum.ML and ctx.stored_event:
            ml_res = self.ml_engine.analyze(ctx.stored_event)
            ctx.ml_event = ml_res
            self.storage_engine.update_ml_scores(ctx.event_id, ml_res.ml.anomaly_score, ml_res.ml.is_anomalous)
            ctx.current_stage = StageEnum.ML
            if StageEnum.ML not in ctx.stages_completed:
                ctx.stages_completed.append(StageEnum.ML)

        elif next_stage == StageEnum.STANDARDIZED and ctx.ml_event and ctx.normalized_event and ctx.raw_event:
            final_event = ULPFFinalEvent(
                ulpf_version="1.0.0",
                event_id=ctx.event_id,
                event=ctx.normalized_event.event,
                source=ctx.normalized_event.source,
                destination=ctx.normalized_event.destination,
                network=ctx.normalized_event.network,
                threat=ctx.normalized_event.threat,
                observer=ctx.normalized_event.observer,
                raw_event=ctx.raw_event.raw,
                unmapped_fields=ctx.normalized_event.unmapped_fields,
                ml_analysis=ctx.ml_event.ml,
                validation={"is_valid": ctx.validated_event.is_valid if ctx.validated_event else True},
                storage=ctx.stored_event.storage if ctx.stored_event else StorageMetadata(raw_size_bytes=0, compressed_size_bytes=0, compression_ratio=0),
                pipeline_telemetry={"total_duration_us": ctx.total_duration_us},
            )
            ctx.final_event = final_event
            ctx.current_stage = StageEnum.STANDARDIZED
            ctx.is_completed = True
            if StageEnum.STANDARDIZED not in ctx.stages_completed:
                ctx.stages_completed.append(StageEnum.STANDARDIZED)

        return ctx

    def _add_to_buffer(self, ctx: PipelineContext):
        self.recent_contexts.append(ctx)
        if len(self.recent_contexts) > self.max_buffer_size:
            self.recent_contexts.pop(0)

    def get_buffered_context(self, event_id: str) -> Optional[PipelineContext]:
        for ctx in reversed(self.recent_contexts):
            if ctx.event_id == event_id:
                return ctx
        return None
