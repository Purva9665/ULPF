"""
ULPF Storage Engine (Stage 5) - Dual-Database Edition
Writes to two SQLite WAL databases:
  ulpf_events.db   - original unified store (backward-compat)
  ulpf_siem.db     - SIEM events (security-relevant only)
  ulpf_datalake.db - ALL events (long-retention Data Lake)

PostgreSQL backend can be swapped in via ULPF_DB_BACKEND=postgres.
"""

import contextlib
import os
import re
import sqlite3
import json
import zlib
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from backend.core.models import ULPFValidatedEvent, ULPFStoredEvent, StorageMetadata
from backend.router.event_router import default_router, RoutingDecision


def _make_conn(path: str) -> sqlite3.Connection:
    if path != ":memory:":
        db_dir = os.path.dirname(path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def _sync_columns(conn: sqlite3.Connection, table: str, ddl: str) -> None:
    """Add any columns present in the CREATE TABLE ddl but missing from an
    existing table. SQLite's CREATE TABLE IF NOT EXISTS silently keeps an old
    schema, so a database created by an earlier ULPF version would otherwise
    fail once new columns are referenced."""
    existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    if not existing:
        return
    body = ddl[ddl.index("(") + 1: ddl.rindex(")")]
    depth = 0
    current = ""
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            _add_if_missing(conn, table, current.strip(), existing)
            current = ""
            continue
        current += ch
    _add_if_missing(conn, table, current.strip(), existing)


def _add_if_missing(conn: sqlite3.Connection, table: str, coldef: str, existing: set) -> None:
    if not coldef:
        return
    name = coldef.split()[0]
    if name.upper() in ("PRIMARY", "UNIQUE", "FOREIGN", "CHECK", "CONSTRAINT"):
        return
    if name in existing:
        return
    # A backfilled column cannot be NOT NULL without a default, and cannot be
    # UNIQUE or PRIMARY KEY; strip those constraints for the ALTER.
    spec = re.sub(r"PRIMARY KEY|UNIQUE|AUTOINCREMENT", "", coldef, flags=re.I)
    if "DEFAULT" not in spec.upper():
        spec = re.sub(r"NOT NULL", "", spec, flags=re.I)
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {spec.strip()}")
    existing.add(name)


class StorageEngine:
    """
    Stage 5: STORAGE - Dual-database routing edition.

    Every event is written to:
      - ulpf_datalake.db (ALL events)
      - ulpf_siem.db     (security-relevant events only, based on EventRouter)

    The original ulpf_events table is kept for backward compatibility with
    existing API endpoints (/api/events, /api/stats).
    """

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path

        # Derive sibling paths for SIEM and Data Lake databases
        base_dir = os.path.dirname(db_path) if db_path != ":memory:" else ""
        siem_path = os.path.join(base_dir, "ulpf_siem.db") if base_dir else ":memory:"
        lake_path = os.path.join(base_dir, "ulpf_datalake.db") if base_dir else ":memory:"

        # Primary (unified, backward-compat)
        self.conn = _make_conn(db_path)
        # SIEM (security events only)
        self.siem_conn = _make_conn(siem_path)
        # Data Lake (all events)
        self.lake_conn = _make_conn(lake_path)

        self._init_primary()
        self._init_siem()
        self._init_datalake()
        self._columnar_buffer: List[Dict[str, Any]] = []
        self._batch_depth = 0

    # --------------------------------------------------------------
    # Transaction batching
    # --------------------------------------------------------------

    @contextlib.contextmanager
    def batch_writes(self):
        """Defer commits until the block exits.

        Each stored event otherwise commits three times - primary, Data Lake,
        and SIEM - and every commit on a WAL database is a durability barrier.
        At ingest volume that barrier, not the insert, is the cost: it was 68%
        of pipeline time before this existed. Committing once per batch keeps
        the same durability guarantee at the batch boundary, which is the right
        granularity for a bulk-ingest path.
        """
        self._batch_depth += 1
        try:
            yield self
        finally:
            self._batch_depth -= 1
            if self._batch_depth == 0:
                self.flush()

    def flush(self) -> None:
        """Commit any deferred writes on all three databases."""
        for conn in (self.conn, self.siem_conn, self.lake_conn):
            try:
                conn.commit()
            except Exception:
                pass

    def _txn(self, conn: sqlite3.Connection):
        """Auto-commit per statement, unless a batch is in progress."""
        if self._batch_depth:
            return contextlib.nullcontext()
        return conn

    # --------------------------------------------------------------
    # Schema initialisation
    # --------------------------------------------------------------

    def _init_primary(self):
        with self.conn:
            ddl_ulpf_events = """
                CREATE TABLE IF NOT EXISTS ulpf_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    product TEXT NOT NULL,
                    category TEXT NOT NULL,
                    action TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    src_ip TEXT, src_port INTEGER,
                    dst_ip TEXT, dst_port INTEGER,
                    protocol TEXT,
                    raw_payload TEXT NOT NULL,
                    raw_sha256 TEXT NOT NULL,
                    raw_length_bytes INTEGER NOT NULL,
                    compressed_bytes INTEGER NOT NULL,
                    data_quality_score REAL NOT NULL,
                    anomaly_score REAL DEFAULT 0.0,
                    is_anomalous INTEGER DEFAULT 0,
                    normalized_json TEXT NOT NULL,
                    routed_to_siem INTEGER DEFAULT 0,
                    routing_label TEXT DEFAULT 'Data Lake only',
                    routing_reasons TEXT DEFAULT '[]',
                    stored_at TEXT NOT NULL
                );
            """
            self.conn.execute(ddl_ulpf_events)
            _sync_columns(self.conn, "ulpf_events", ddl_ulpf_events)
            for idx in [
                "CREATE INDEX IF NOT EXISTS idx_ts   ON ulpf_events(timestamp);",
                "CREATE INDEX IF NOT EXISTS idx_sip  ON ulpf_events(src_ip);",
                "CREATE INDEX IF NOT EXISTS idx_dip  ON ulpf_events(dst_ip);",
                "CREATE INDEX IF NOT EXISTS idx_dport ON ulpf_events(dst_port);",
                "CREATE INDEX IF NOT EXISTS idx_act  ON ulpf_events(action);",
                "CREATE INDEX IF NOT EXISTS idx_sev  ON ulpf_events(severity);",
                "CREATE INDEX IF NOT EXISTS idx_anom ON ulpf_events(anomaly_score);",
                "CREATE INDEX IF NOT EXISTS idx_siem_flag ON ulpf_events(routed_to_siem);",
            ]:
                self.conn.execute(idx)

    def _init_siem(self):
        with self.siem_conn:
            ddl_siem_events = """
                CREATE TABLE IF NOT EXISTS siem_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    raw_event_ref TEXT,
                    received_at TEXT NOT NULL,
                    event_timestamp TEXT,
                    severity TEXT NOT NULL DEFAULT 'LOW',
                    category TEXT NOT NULL DEFAULT 'UNKNOWN',
                    action TEXT,
                    src_ip TEXT, src_port INTEGER,
                    dst_ip TEXT, dst_port INTEGER,
                    protocol TEXT,
                    parser_name TEXT,
                    vendor TEXT,
                    anomaly_score REAL NOT NULL DEFAULT 0.0,
                    risk_level TEXT,
                    is_anomalous INTEGER NOT NULL DEFAULT 0,
                    routing_reasons TEXT NOT NULL DEFAULT '[]',
                    normalized_json TEXT NOT NULL,
                    raw_sha256 TEXT,
                    data_quality_score REAL NOT NULL DEFAULT 100.0,
                    alert_generated INTEGER NOT NULL DEFAULT 0
                );
            """
            self.siem_conn.execute(ddl_siem_events)
            _sync_columns(self.siem_conn, "siem_events", ddl_siem_events)
            for idx in [
                "CREATE INDEX IF NOT EXISTS idx_siem_ts   ON siem_events(received_at);",
                "CREATE INDEX IF NOT EXISTS idx_siem_sev  ON siem_events(severity, anomaly_score);",
                "CREATE INDEX IF NOT EXISTS idx_siem_sip  ON siem_events(src_ip);",
                "CREATE INDEX IF NOT EXISTS idx_siem_cat  ON siem_events(category);",
                "CREATE INDEX IF NOT EXISTS idx_siem_anom ON siem_events(anomaly_score);",
            ]:
                self.siem_conn.execute(idx)

    def _init_datalake(self):
        with self.lake_conn:
            ddl_datalake_events = """
                CREATE TABLE IF NOT EXISTS datalake_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    received_at TEXT NOT NULL,
                    event_timestamp TEXT,
                    severity TEXT,
                    category TEXT,
                    action TEXT,
                    src_ip TEXT, src_port INTEGER,
                    dst_ip TEXT, dst_port INTEGER,
                    protocol TEXT,
                    parser_name TEXT,
                    vendor TEXT,
                    anomaly_score REAL DEFAULT 0.0,
                    is_anomalous INTEGER DEFAULT 0,
                    routed_to_siem INTEGER NOT NULL DEFAULT 0,
                    routing_label TEXT,
                    normalized_json TEXT NOT NULL,
                    raw_sha256 TEXT,
                    raw_byte_length INTEGER,
                    compressed_bytes INTEGER,
                    compression_ratio REAL,
                    data_quality_score REAL DEFAULT 100.0
                );
            """
            self.lake_conn.execute(ddl_datalake_events)
            _sync_columns(self.lake_conn, "datalake_events", ddl_datalake_events)
            for idx in [
                "CREATE INDEX IF NOT EXISTS idx_dl_ts   ON datalake_events(received_at);",
                "CREATE INDEX IF NOT EXISTS idx_dl_siem ON datalake_events(routed_to_siem);",
                "CREATE INDEX IF NOT EXISTS idx_dl_anom ON datalake_events(anomaly_score);",
            ]:
                self.lake_conn.execute(idx)

    # --------------------------------------------------------------
    # Store
    # --------------------------------------------------------------

    def store(self, validated_event: ULPFValidatedEvent) -> ULPFStoredEvent:
        t0 = time.perf_counter_ns()
        norm = validated_event.normalized
        raw_payload = norm.raw.payload
        raw_bytes = raw_payload.encode("utf-8")
        raw_len = len(raw_bytes)
        compressed = zlib.compress(raw_bytes, level=6)
        comp_len = len(compressed)
        compression_ratio = round((1.0 - (comp_len / max(raw_len, 1))) * 100.0, 1) if raw_len > 0 else 0.0
        normalized_json_str = json.dumps(norm.model_dump())
        now_str = datetime.now(timezone.utc).isoformat()

        # Routing decision (uses default anomaly_score=0 at storage time;
        # updated once ML runs via update_ml_scores)
        routing = default_router.classify(
            anomaly_score=0.0,
            category=norm.event.category or "",
            action=norm.event.action.value if norm.event.action else "",
            dst_port=norm.destination.port if norm.destination else None,
            severity=norm.event.severity.value if norm.event.severity else "",
        )
        routing_reasons_json = json.dumps(routing.reasons)

        # 1. Write to primary (unified / backward-compat)
        with self._txn(self.conn):
            cursor = self.conn.execute("""
                INSERT OR REPLACE INTO ulpf_events (
                    event_id, timestamp, ingested_at, vendor, product, category,
                    action, severity, src_ip, src_port, dst_ip, dst_port,
                    protocol, raw_payload, raw_sha256, raw_length_bytes,
                    compressed_bytes, data_quality_score, normalized_json,
                    routed_to_siem, routing_label, routing_reasons, stored_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                validated_event.event_id,
                norm.event.timestamp or now_str,
                norm.event.ingested_at,
                norm.observer.vendor, norm.observer.product,
                norm.event.category, norm.event.action.value,
                norm.event.severity.value,
                norm.source.ip, norm.source.port,
                norm.destination.ip if norm.destination else None,
                norm.destination.port if norm.destination else None,
                norm.network.protocol,
                raw_payload, norm.raw.sha256_hash, raw_len, comp_len,
                validated_event.data_quality_score, normalized_json_str,
                1 if routing.siem else 0, routing.label, routing_reasons_json,
                now_str,
            ))
            row_id = cursor.lastrowid

        # 2. Write to Data Lake (ALL events)
        with self._txn(self.lake_conn):
            self.lake_conn.execute("""
                INSERT OR REPLACE INTO datalake_events (
                    event_id, received_at, event_timestamp, severity, category, action,
                    src_ip, src_port, dst_ip, dst_port, protocol, parser_name, vendor,
                    routed_to_siem, routing_label, normalized_json,
                    raw_sha256, raw_byte_length, compressed_bytes,
                    compression_ratio, data_quality_score
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                validated_event.event_id, now_str, norm.event.timestamp,
                norm.event.severity.value, norm.event.category, norm.event.action.value,
                norm.source.ip, norm.source.port,
                norm.destination.ip if norm.destination else None,
                norm.destination.port if norm.destination else None,
                norm.network.protocol, norm.observer.product, norm.observer.vendor,
                1 if routing.siem else 0, routing.label, normalized_json_str,
                norm.raw.sha256_hash, raw_len, comp_len, compression_ratio,
                validated_event.data_quality_score,
            ))

        # 3. Write to SIEM (only if security-relevant)
        if routing.siem:
            with self._txn(self.siem_conn):
                self.siem_conn.execute("""
                    INSERT OR REPLACE INTO siem_events (
                        event_id, received_at, event_timestamp, severity, category, action,
                        src_ip, src_port, dst_ip, dst_port, protocol, vendor,
                        routing_reasons, normalized_json, raw_sha256, data_quality_score
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    validated_event.event_id, now_str, norm.event.timestamp,
                    norm.event.severity.value, norm.event.category, norm.event.action.value,
                    norm.source.ip, norm.source.port,
                    norm.destination.ip if norm.destination else None,
                    norm.destination.port if norm.destination else None,
                    norm.network.protocol, norm.observer.vendor,
                    routing_reasons_json, normalized_json_str, norm.raw.sha256_hash,
                    validated_event.data_quality_score,
                ))

        # Columnar buffer
        self._columnar_buffer.append({
            "event_id": validated_event.event_id,
            "timestamp": norm.event.timestamp or now_str,
            "vendor": norm.observer.vendor,
            "action": norm.event.action.value,
            "severity": norm.event.severity.value,
            "src_ip": norm.source.ip, "src_port": norm.source.port,
            "dst_ip": norm.destination.ip if norm.destination else None,
            "dst_port": norm.destination.port if norm.destination else None,
            "protocol": norm.network.protocol,
            "bytes": norm.network.bytes_total,
            "dqi": validated_event.data_quality_score,
        })
        if len(self._columnar_buffer) > 10000:
            self._columnar_buffer.pop(0)

        t1 = time.perf_counter_ns()
        duration_us = (t1 - t0) // 1000

        storage_meta = StorageMetadata(
            storage_engine="SQLite-WAL-Dual",
            table_name="ulpf_events + siem_events + datalake_events",
            row_id=row_id,
            raw_size_bytes=raw_len,
            compressed_size_bytes=comp_len,
            compression_ratio=compression_ratio,
            indexed_fields=["timestamp", "src_ip", "dst_ip", "dst_port", "action", "severity", "anomaly_score"],
            stored_at=now_str,
        )

        return ULPFStoredEvent(
            event_id=validated_event.event_id,
            validated=validated_event,
            storage=storage_meta,
            storage_duration_us=duration_us,
        )

    # --------------------------------------------------------------
    # ML score update (called AFTER ML stage)
    # --------------------------------------------------------------

    def update_ml_scores(self, event_id: str, anomaly_score: float, is_anomalous: bool):
        """
        Update ML scores in all three databases.
        Also re-runs routing: if anomaly_score now >= 0.60, promote to SIEM.
        """
        is_int = 1 if is_anomalous else 0
        for conn in (self.conn, self.lake_conn):
            with conn:
                conn.execute(
                    "UPDATE ulpf_events SET anomaly_score=?, is_anomalous=? WHERE event_id=?",
                    (anomaly_score, is_int, event_id),
                ) if conn is self.conn else conn.execute(
                    "UPDATE datalake_events SET anomaly_score=?, is_anomalous=? WHERE event_id=?",
                    (anomaly_score, is_int, event_id),
                )

        with self.siem_conn:
            self.siem_conn.execute(
                "UPDATE siem_events SET anomaly_score=?, is_anomalous=? WHERE event_id=?",
                (anomaly_score, is_int, event_id),
            )

        # If anomaly now >= threshold and not yet in SIEM, promote it
        if anomaly_score >= default_router.ANOMALY_THRESHOLD:
            row = self.conn.execute(
                "SELECT * FROM ulpf_events WHERE event_id=? AND routed_to_siem=0", (event_id,)
            ).fetchone()
            if row:
                now_str = datetime.now(timezone.utc).isoformat()
                reasons = [f"ML anomaly score {anomaly_score:.3f} >= {default_router.ANOMALY_THRESHOLD} (post-ML promotion)"]
                with self.siem_conn:
                    self.siem_conn.execute("""
                        INSERT OR REPLACE INTO siem_events (
                            event_id, received_at, event_timestamp, severity, category,
                            action, src_ip, src_port, dst_ip, dst_port, protocol, vendor,
                            anomaly_score, is_anomalous, routing_reasons, normalized_json,
                            raw_sha256, data_quality_score
                        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        event_id, now_str, dict(row).get("timestamp"),
                        dict(row).get("severity", "LOW"), dict(row).get("category", "UNKNOWN"),
                        dict(row).get("action", ""), dict(row).get("src_ip"), dict(row).get("src_port"),
                        dict(row).get("dst_ip"), dict(row).get("dst_port"), dict(row).get("protocol"),
                        dict(row).get("vendor"), anomaly_score, is_int,
                        json.dumps(reasons), dict(row).get("normalized_json", "{}"),
                        dict(row).get("raw_sha256"), dict(row).get("data_quality_score", 100.0),
                    ))
                with self.conn:
                    self.conn.execute(
                        "UPDATE ulpf_events SET routed_to_siem=1, routing_label=? WHERE event_id=?",
                        ("SIEM + Data Lake (promoted by ML)", event_id),
                    )

    # --------------------------------------------------------------
    # Query helpers
    # --------------------------------------------------------------

    def query_events(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        cursor = self.conn.execute("""
            SELECT event_id, timestamp, ingested_at, vendor, product, category,
                   action, severity, src_ip, src_port, dst_ip, dst_port,
                   protocol, raw_length_bytes, compressed_bytes,
                   data_quality_score, anomaly_score, is_anomalous,
                   routed_to_siem, routing_label, stored_at
            FROM ulpf_events
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        return [dict(row) for row in cursor.fetchall()]

    def query_siem_events(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        cursor = self.siem_conn.execute("""
            SELECT event_id, received_at, event_timestamp, severity, category,
                   action, src_ip, src_port, dst_ip, dst_port, protocol, vendor,
                   anomaly_score, is_anomalous, routing_reasons, data_quality_score
            FROM siem_events
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        return [dict(row) for row in cursor.fetchall()]

    def query_datalake_events(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        cursor = self.lake_conn.execute("""
            SELECT event_id, received_at, severity, category, action,
                   src_ip, dst_ip, dst_port, vendor, anomaly_score,
                   routed_to_siem, routing_label
            FROM datalake_events
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        return [dict(row) for row in cursor.fetchall()]

    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        cursor = self.conn.execute("SELECT * FROM ulpf_events WHERE event_id=?", (event_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_statistics(self) -> Dict[str, Any]:
        cursor = self.conn.execute("""
            SELECT COUNT(*) as total_events,
                   SUM(raw_length_bytes) as total_raw_bytes,
                   SUM(compressed_bytes) as total_compressed_bytes,
                   AVG(data_quality_score) as avg_dqi,
                   SUM(is_anomalous) as total_anomalies,
                   SUM(routed_to_siem) as total_siem_events
            FROM ulpf_events
        """)
        row = cursor.fetchone()
        if not row or row["total_events"] == 0:
            return {
                "total_events": 0, "total_raw_bytes": 0,
                "total_compressed_bytes": 0, "overall_compression_ratio": 0.0,
                "avg_data_quality_score": 100.0, "total_anomalies": 0,
                "total_siem_events": 0, "total_datalake_events": 0,
                "siem_rate_pct": 0.0,
            }
        raw_b = row["total_raw_bytes"] or 0
        comp_b = row["total_compressed_bytes"] or 0
        ratio = round((1.0 - (comp_b / max(raw_b, 1))) * 100.0, 1) if raw_b > 0 else 0.0
        total = row["total_events"]
        siem = row["total_siem_events"] or 0
        dl_row = self.lake_conn.execute("SELECT COUNT(*) as c FROM datalake_events").fetchone()
        dl_total = dl_row["c"] if dl_row else total
        return {
            "total_events": total,
            "total_raw_bytes": raw_b,
            "total_compressed_bytes": comp_b,
            "overall_compression_ratio": ratio,
            "avg_data_quality_score": round(row["avg_dqi"] or 100.0, 1),
            "total_anomalies": row["total_anomalies"] or 0,
            "total_siem_events": siem,
            "total_datalake_events": dl_total,
            "siem_rate_pct": round((siem / max(total, 1)) * 100.0, 1),
        }

    def get_routing_stats(self) -> Dict[str, Any]:
        """Routing-specific statistics for the dashboard."""
        stats = self.get_statistics()
        return {
            "total_processed": stats["total_events"],
            "siem_count": stats["total_siem_events"],
            "datalake_count": stats["total_datalake_events"],
            "siem_rate_pct": stats["siem_rate_pct"],
            "anomaly_threshold": default_router.ANOMALY_THRESHOLD,
        }