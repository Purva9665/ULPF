"""
ULPF Ingestion Engine (Stage 1)
Preserves pristine raw event data with zero information loss and cryptographic hash integrity.
"""

import time
import uuid
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from backend.core.models import ULPFRawEvent, RawPayload


class IngestionEngine:
    """
    Stage 1: INGESTION
    Captures raw event stream, calculates SHA-256 integrity hash, records ingestion telemetry.
    """

    def __init__(self, default_protocol: str = "SYSLOG_UDP"):
        self.default_protocol = default_protocol

    def ingest(
        self,
        raw_text: str,
        source_protocol: Optional[str] = None,
        source_metadata: Optional[Dict[str, Any]] = None,
        custom_event_id: Optional[str] = None,
    ) -> ULPFRawEvent:
        """
        Ingests a raw string payload, computing cryptographic digest and packaging into ULPFRawEvent.
        """
        t0 = time.perf_counter_ns()
        
        # Ensure exact string preservation
        raw_bytes = raw_text.encode("utf-8")
        sha256_digest = hashlib.sha256(raw_bytes).hexdigest()
        
        protocol = source_protocol or self.default_protocol
        meta = source_metadata or {}
        event_id = custom_event_id or str(uuid.uuid4())
        
        raw_payload = RawPayload(
            payload=raw_text,
            sha256_hash=sha256_digest,
            encoding="UTF-8",
            length_bytes=len(raw_bytes),
            source_protocol=protocol,
        )
        
        raw_event = ULPFRawEvent(
            event_id=event_id,
            ingested_at=datetime.now(timezone.utc).isoformat(),
            raw=raw_payload,
            source_metadata=meta,
        )
        
        return raw_event
