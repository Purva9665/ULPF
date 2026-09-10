# PPT vs. Code — Fact Check

**Checked 2026-09-03** against `C:\Users\purva\Desktop\ulpf1` (the merged repo).
Every row below was verified by grepping or running the code, not by reading docs.

---

## A. Must fix — a judge can disprove these

These are claims the slides make that the code does not support. Each is
checkable in under a minute by anyone who opens the repo.

| # | Slide | Claim | Reality | Evidence |
|---|---|---|---|---|
| A1 | 2 | **"Security Enhanced — RAG with controlled, trusted knowledge retrieval"** | **There is no RAG.** No retrieval, no embeddings, no vector store, no knowledge base anywhere in the backend. | `grep -ri "rag\|retrieval\|embedding\|vector store" backend/` → 0 matches |
| A2 | 3 | **PostgreSQL** as the storage layer (named twice, plus logo) | **SQLite WAL.** `psycopg2`/`asyncpg` sit in requirements.txt but are never imported. Only a docstring mentions a possible future switch. | `backend/storage/engine.py:30` → `sqlite3.connect(...)` |
| A3 | 3 | **"Persistent Volumes (PostgreSQL Data)"** | SQLite database files | same as A2 |
| A4 | 3 | **"Analytics Engine (Pandas, NumPy)"** + pandas logo | **Pandas is never imported.** NumPy is, once, in the ML engine. | `grep -rn "import pandas" backend/` → 0 matches |
| A5 | 3 | **"Schema Validation (JSON Schema)"** | **`jsonschema` is never used.** The validator runs hand-written checks: IP parseability, SHA-256 re-verification, required-field presence, DQI scoring. | `grep -n jsonschema backend/validator/engine.py` → 0 matches |
| A6 | 3 | **"Alerts & Notifications"** under Visualization | **Not implemented.** No SMTP, no webhook, no alerting code path. | `grep -ri "smtp\|webhook\|notification" backend/` → only port-name lookups in `mappings.py` |
| A7 | 4 | **"Parallel processing for high volumes"** | **Single process, single thread.** No `multiprocessing`, no `ThreadPoolExecutor`, no `concurrent.futures`. | `grep -rn "multiprocessing\|ThreadPool\|concurrent.futures" backend/` → 0 matches |
| A8 | 2, 3 | Pipeline shown as **INGEST → DETECT → PARSE → NORMALIZE → VALIDATE → STANDARDIZE** | Actual `StageEnum` is **INGEST, PARSE, NORMALIZE, VALIDATE, STORE, ML, STANDARDIZED, EXPORT**. "DETECT" is not a stage — format detection happens *inside* PARSE via the registry. **STORE and ML are missing from the slide entirely**, and ML is one of our strongest points. | `backend/core/models.py:14-22` |

**A1 is the most damaging.** "RAG" is a specific, well-known technique. A
cybersecurity judge who asks "show me the retrieval layer" will find nothing,
and everything else on the slide becomes suspect. Delete it.

---

## B. Numbers with nothing behind them

| # | Slide | Claim | Problem |
|---|---|---|---|
| B1 | 5 | **"Reduces parser development & manual mapping effort by >70%"** | No measurement supports this. Nothing in the repo measures parser development effort. |
| B2 | 5 | **"improve ML accuracy & reduce false positives"** | Never measured. Worse — the literature contradicts the implied mechanism: Khan et al., *Impact of Log Parsing on Deep Learning-Based Anomaly Detection*, EMSE 29:139 (2024) found **no strong correlation between log parsing accuracy and anomaly detection accuracy**. Claiming better parsing ⇒ better detection is refuted, and a judge who knows this literature will say so. |
| B3 | 4 | Feasibility scores **4.8/5, 4.7/5, 4.6/5, 4.5/5, 4.8/5, 4.4/5** | Self-assigned with no stated methodology. Scoring your own project 4.4–4.8 out of 5 reads as marketing, not assessment. |
| B4 | 4 | **Four stat boxes are empty**: "Global SIEM Market Size (2023)", "Projected CAGR (2024-2030)", "Enterprises Struggling with Log Integration", "Avg. Time Saved with Standardization" | Labels present, **no values at all**. This looks unfinished on a submitted deck. Either fill with cited figures or delete the box. |
| B5 | 6 | Prototype screenshot shows **PIPELINE LATENCY 259590 µs** | That is **260 ms per event ≈ 4 events/sec**. Our measured figure is ~500 µs mean, ~895 EPS median. The screenshot is from a pre-merge run. It actively undersells the project by ~200x. |

---

## C. What we can actually prove — and it is not on the slides

This is the bigger problem. The strongest, *measured* material is missing.

| Provable claim | Evidence in repo |
|---|---|
| **OCSF 1.9.0 alignment** — real `class_uid` per event type, `type_uid` computed per spec, required `metadata` block | `backend/exporter/engine.py`, `tests/test_taxonomy.py` |
| **Lossless preservation is verifiable, not asserted** — `raw_data`, `raw_data_hash` (SHA-256), `raw_data_size`, `unmapped` are OCSF base-event fields, so a consumer can check it themselves | `TestLossless` in `tests/test_taxonomy.py` |
| **MITRE ATT&CK technique mapping** — T1046, T1110, T1190, T1071.004, T1048.003 | `backend/normalizer/taxonomy.py` |
| **Explainable classification** — every decision ships an evidence list (signal, observed value, what it argues for, weight) | visible in the Demo view |
| **SIEM/Data Lake routing measured at 11.5%** on a realistic traffic mix → **~88% reduction in SIEM ingest volume** | `scripts/benchmark.py`, `docs/benchmark_results.json` |
| **Measured throughput: 895 EPS median** (range 875–927 over 5 runs, 0 failures) | same |
| **Adaptive parser (Drain, He et al. ICWS 2017)** learns unseen formats with zero configuration — this is the answer to "reduced parser effort", and it is real | `backend/parsers/adaptive.py` |
| **10 parsers, not 9** | `default_registry.list_parsers()` |
| **68 passing tests** | `pytest tests/ -q` |

Not built yet, but the strongest *enterprise* differentiators (see
`SOLUTION_ARCHITECTURE.md`): chain of custody starting at collection, CERT-In
Direction 20(3)/2022 compliance profile, BSA §63 certificate generation,
data-diode ingestion.

---

## D. Cosmetic

| # | Slide | Issue |
|---|---|---|
| D1 | 3 | Heading typo: "1.ULPF **Architecturel**" |
| D2 | 3 | Heading typo: "3.**Storag** and Schema" |
| D3 | 3 | Heading typo: "6.DEPLOYMENT & **INFRASTRUCTUREE**" |
| D4 | 4 | "**Pen O-source** friendly" → "Open-source friendly" |
| D5 | 4 | "Strong Technical **Foundatiion**" |
| D6 | 4 | "Key Value **Preposition**" → "Proposition" |
| D7 | 4 | "Overall **Assesment**" → "Assessment" |
| D8 | 2 | "Collect logs from diverse **sour**" — text is cut off |
| D9 | 6 | "BMC LINK" box is empty |

---

## E. Recommended edits, in priority order

**Delete outright**
1. "RAG with controlled, trusted knowledge retrieval" (A1)
2. "Parallel processing for high volumes" (A7)
3. "Alerts & Notifications" (A6)
4. ">70%" parser-effort figure (B1)
5. The four empty stat boxes, or fill them with cited numbers (B4)

**Correct**
6. PostgreSQL → **"SQLite WAL (prototype); PostgreSQL + TimescaleDB is the
   enterprise target"**. Saying both is honest *and* still sounds enterprise. (A2, A3)
7. Remove Pandas from the stack and the logo strip (A4)
8. "JSON Schema" → **"Rule-based validation + Data Quality Index (0–100)"** (A5)
9. Pipeline diagram → **INGEST → PARSE → NORMALIZE → VALIDATE → STORE → ML → STANDARDIZE**.
   Adding STORE and ML makes the diagram *stronger*, not longer. (A8)
10. Re-take the prototype screenshot on the merged build — the current one shows
    260 ms/event (B5)

**Add — this is where the enterprise story actually lives**
11. **OCSF 1.9.0** as the canonical schema, with the vendor-neutrality argument
    (Linux Foundation governance since Nov 2024)
12. **The measured numbers**: 895 EPS median, 11.5% SIEM routing, 68 tests,
    10 parsers, byte-identical preservation verified
13. **MITRE ATT&CK mapping** and the **evidence trail** — nothing else in this
    category explains *why* it classified something
14. **Air-gap topologies** including the data diode — this is the slide that
    answers "how do logs even reach an isolated system?"

**Fix typos** (D1–D9)

---

## F. One framing note

The deck currently argues *"we parse many formats"*. That is the weakest
available position: Vector, Fluent Bit, Cribl, Logstash and the OpenTelemetry
Collector all do it, and Elastic ships 300+ prebuilt integrations.

The defensible position, argued in full in `SOLUTION_ARCHITECTURE.md`, is:

> ULPF is not a faster log shipper. It is the **evidence layer** — every event
> provably unmodified, explainably classified, and legally certifiable,
> starting at the moment of collection.

Everything in section C supports that claim and is already built.
