<<<<<<< HEAD
# ULPF — Universal Log Pre-processing Framework

> **A functional, zero-loss log pre-processing pipeline and visual engine control room for heterogeneous perimeter network telemetry.**

---

## 1. Overview & Pipeline Flow

```
Heterogeneous Perimeter Logs (Cisco ASA, Palo Alto, Suricata, AWS VPC, Zeek, CEF, Syslog)
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │         [01] INGESTION            │  Zero-loss Raw Capture & SHA-256 Digest
                     └─────────────────┬─────────────────┘
                                       ▼
                     ┌───────────────────────────────────┐
                     │          [02] PARSING             │  Multi-Dialect Plug-and-Play AST
                     └─────────────────┬─────────────────┘
                                       ▼
                     ┌───────────────────────────────────┐
                     │       [03] NORMALIZATION          │  Canonical ULPF Schema & Unmapped Retain
                     └─────────────────┬─────────────────┘
                                       ▼
                     ┌───────────────────────────────────┐
                     │        [04] VALIDATION            │  Semantic Rules & DQI Scoring
                     └─────────────────┬─────────────────┘
                                       ▼
                     ┌───────────────────────────────────┐
                     │          [05] STORAGE             │  Dual SQLite WAL & Columnar Storage
                     └─────────────────┬─────────────────┘
                                       ▼
                     ┌───────────────────────────────────┐
                     │      [06] ML ANOMALY ENGINE       │  Local Isolation Forest & Entropy
                     └─────────────────┬─────────────────┘
                                       ▼
                     ┌───────────────────────────────────┐
                     │     [07] STANDARDIZED EVENT       │  SIEM (Elastic ECS, Splunk HEC, OCSF)
                     └───────────────────────────────────┘
```

---

## 2. 15 Non-Negotiable Functional Requirements

| # | Functional Requirement | Technical Implementation |
|---|---|---|
| 1 | **Preserve complete raw event data** | Pristine byte sequence preserved with SHA-256 cryptographic digest. |
| 2 | **Parse heterogeneous log formats** | Built-in parsers for Cisco ASA, Palo Alto PAN-OS, Suricata EVE, AWS VPC Flow, Zeek, CEF, Key-Value, Syslog, Windows Event. |
| 3 | **Extract source-specific fields** | Intermediate AST token dictionaries captured in `ULPFParsedEvent`. |
| 4 | **Normalize fields into a common schema** | Canonical namespace taxonomy: `event.*`, `source.*`, `destination.*`, `network.*`, `threat.*`, `observer.*`, `unmapped_fields`. |
| 5 | **Validate normalized events** | Semantic constraint engine, IP format, port range (0-65535), Data Quality Index (0-100%). |
| 6 | **Maintain traceability** | Event UUID, SHA-256 hash match, transformation history, microsecond stage latencies. |
| 7 | **Support plug-and-play parser architecture** | `BaseParser` abstract class with dynamic capability detection, confidence scoring, and `ParserRegistry`. |
| 8 | **Store raw and normalized representations** | Dual storage in SQLite WAL and in-memory columnar dataframe layout. |
| 9 | **Provide analytics-ready output** | Splunk HEC, Elastic ECS 8.x, OCSF v1.1, S3 Parquet format exporters. |
| 10 | **Provide ML-ready output** | Numeric vectorizer, categorical encodings, Shannon entropy, Isolation Forest anomaly score, feature attribution. |
| 11 | **Support local/offline execution** | 100% self-contained, zero cloud or external API dependencies. |
| 12 | **Support Docker/container deployment** | Multi-stage `Dockerfile` and `docker-compose.yml`. |
| 13 | **Avoid dependency on cloud AI APIs** | Local Scikit-learn Isolation Forest + Statistical Z-score + Shannon Entropy running locally. |
| 14 | **Use real backend processing** | Real cryptographic hashing, parsing, normalizations, schema validations, SQLite transactions, and ML scoring. |
| 15 | **Never hardcode fake processing results** | Live state transitions and intermediate payloads reflect actual computed state. |

---

## 3. Quick Start

### Option A: Local Execution (Recommended)

1. **Install Backend Dependencies**:
   ```bash
   pip install -r backend/requirements.txt
   ```

2. **Install Frontend Dependencies**:
   ```bash
   cd frontend
   npm install
   ```

3. **Start the System**:
   - **Windows**: Double-click `run.bat` or run:
     ```bash
     python -m uvicorn backend.main:app --port 8000 --reload
     # In another terminal:
     cd frontend && npm run dev
     ```
   - **Linux / macOS**:
     ```bash
     chmod +x run.sh && ./run.sh
     ```

4. Open **`http://localhost:5173`** in your browser to access the **ULPF Live Engine Control Room**.
5. Backend REST & Swagger docs: **`http://localhost:8000/docs`**.

---

### Option B: Offline Docker Deployment (Zero Internet Required)

1. **Initial Build (Once with Internet)**:
   ```bash
   docker compose build
   ```

2. **Offline Local Startup (No Internet Required)**:
   ```bash
   docker compose up -d
   ```

3. **Access Control Room & Services**:
   - **Full UI & Engine**: [http://localhost:8000](http://localhost:8000)
   - **Health Check Endpoint**: [http://localhost:8000/api/health](http://localhost:8000/api/health)
   - **API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

4. **Persistent Data Storage**:
   - Normalized events and SQLite database are persisted inside the named volume `ulpf-data` (`/data/ulpf_events.db`).
   - Stopping and restarting containers (`docker compose restart` or `docker compose down && docker compose up -d`) preserves all stored events and ML telemetry.

---

## 4. Running Automated Tests

Run the full automated test suite verifying all 15 requirements:

```bash
python -m pytest tests/ -v
```

---

## 5. Live Engine Control Room Features

- **Live Streaming Mode**: Continuous stream with adjustable EPS slider (1–20 EPS) and real-time WebSocket state machine pulses.
- **Interactive Step-by-Step Debugger**: Step through individual stages (`Step ➔`, `Reset ↺`, `Fast-Forward ⏩`) and inspect intermediate artifacts at each node.
- **Stage Drill-Down Inspectors**: Deep technical inspection for Raw Payload / Hex View, AST Token Matrix, Canonical Schema Mapping, Validation DQI Rules, SQLite WAL storage, and Explainable ML Feature Contribution Waterfall.
- **Custom Ingestion Test Bench**: Paste any custom firewall or security log, choose auto-detection or explicit parser, and test the pipeline live.
- **SIEM & Data Lake Exporter**: Live preview and download for Elastic Common Schema (ECS), Splunk HEC, OCSF v1.1, and Parquet flat columnar JSON.
=======
# ulpf
>>>>>>> 076c845efbad95e56934b0dbf2f9d229828c70e7
