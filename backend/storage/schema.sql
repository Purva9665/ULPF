-- ULPF Schema: ulpf_raw tables (run in ulpf_raw context)
-- The Docker entrypoint runs this; for multi-db we rely on init_roles.sql order.
-- In production, run each section against its target database separately.

-- Raw events landing zone
CREATE TABLE IF NOT EXISTS raw_events (
    id              BIGSERIAL PRIMARY KEY,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip       TEXT,
    source_port     INTEGER,
    source_proto    TEXT NOT NULL DEFAULT 'HTTP_REST',
    raw_payload     TEXT NOT NULL,
    sha256_hash     CHAR(64) NOT NULL,
    byte_length     INTEGER NOT NULL,
    processed       BOOLEAN NOT NULL DEFAULT FALSE,
    processed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_raw_unprocessed ON raw_events (received_at ASC) WHERE processed = FALSE;
CREATE INDEX IF NOT EXISTS idx_raw_received ON raw_events (received_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_raw_dedup ON raw_events (sha256_hash, source_ip, source_proto);