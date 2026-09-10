# ULPF — Implementation Plan

**SIH26156 · NTRO · Universal Log Pre-processing Framework**
Written 2026-09-08. Supersedes the ad-hoc plan in `PROJECT_CONTEXT.md` §13.

> Read this before writing code. Every technology choice below is a *decision*
> with a stated alternative that was rejected and a reason. Where a claim can be
> measured, the acceptance criterion says how.

---

## 0. Verified starting state

Not taken from docs — re-verified on 2026-09-08:

| Fact | Value | How verified |
|---|---|---|
| Test suite | **68 passed / 7.63s** | `pytest tests/ -q` |
| Registered parsers | **10** | `default_registry.list_parsers()` |
| Code size | 15,116 lines (Python + TS) | `wc -l` |
| Throughput | 895 EPS median, 0 failures over 5 runs | `docs/benchmark_results.json` |
| Storage | SQLite WAL, 3 databases | `backend/storage/engine.py:30` |
| Detection model | IsolationForest, 6 per-event features | `backend/ml/anomaly_engine.py` |
| Training data | **none — model has never been trained on labelled data** | no corpus in repo |
| Accuracy measurement | **none** | no precision/recall anywhere |

The last two rows are the whole problem. Everything else is sound.

---

## 1. The USP — what makes this different from what already exists

### 1.1 The honest baseline

Universal log parsing is a solved commercial problem. Vector, Fluent Bit,
Logstash, Cribl Stream, OTel Collector, NiFi, Wazuh and Graylog all do it, and
Elastic ships 300+ prebuilt integrations. Detection is equally crowded: Splunk,
Elastic Security, Sentinel, QRadar, Chronicle, plus UEBA specialists like
Exabeam and Securonix.

**Claiming "we parse many formats and detect anomalies" is not a USP.** It is
the entry ticket, and a judge who knows the market will say so.

### 1.2 The seam nobody occupies

Every product on that list treats **parsing** and **detection** as separate
systems — usually separate *vendors*. A pipeline parses and ships; a SIEM
detects. The interface between them is a wire format (ECS, CEF, OCSF JSON).

That interface throws away two things, permanently:

1. **The parser's uncertainty.** If a parser mis-extracts a field — column
   misalignment, a truncated CSV, an unrecognised vendor extension — the event
   still ships and looks identical to a perfectly-parsed one. The SIEM then
   detects on corrupted values with full confidence. No wire format carries
   per-field parse confidence, so this information cannot survive the hop.

2. **The detection's feedback.** The SIEM knows which fields actually drove its
   detections. The parser never learns this. So parser development is
   prioritised by whoever files a ticket, not by what detection actually needs.

Both losses are *structural*: they exist because the two stages are different
products. A framework that owns both stages does not have to lose either.

### 1.3 Our USP — three mechanisms, one loop

> **ULPF is the only log pipeline where parse uncertainty is a first-class
> detection input, detection outcomes automatically improve the parsers, and
> every detection is verifiable back to the original raw bytes.**

**USP-1 — Confidence-aware detection.**
Every normalized field carries a provenance record: which parser produced it,
at what confidence, and whether it was directly extracted, inferred, or
defaulted. The detection model consumes that as input. A detection resting on
low-confidence fields is downranked and explicitly labelled *evidence
degraded*, instead of being presented with the same authority as a clean one.
*Measurable:* false-positive rate with confidence features on vs. off, on the
same labelled corpus.

**USP-2 — The residue loop.**
Fields that end up in `unmapped_fields` are precisely the ones no mapping rule
covers. We rank unmapped keys by frequency × correlation with confirmed
detections, and surface: *"`threat_id` appears in 82% of your detections and is
not mapped. Proposed rule: `threat_id → threat.signature_id`. Accept?"* One
click writes a declarative mapping rule. The parser improves because detection
told it what mattered.
*Measurable:* mapped-field coverage before vs. after N events, unattended.

**USP-3 — Verifiable detections, not just verifiable events.**
Custody of a single log line is a compliance checkbox. Custody of a
*conclusion* is what an auditor or a court actually needs. Every ULPF detection
ships an evidence bundle: the raw bytes and SHA-256 of every contributing
event, the parse confidence of every field used, and the per-detector
contribution to the score. A reviewer can re-derive the verdict independently.

**Why this is defensible as novel:** each ingredient exists somewhere — NiFi has
provenance, Exabeam has UEBA, Splunk has index-time integrity. What does not
exist is a system where the parser's uncertainty flows *into* the detector and
the detector's outcomes flow *back into* the parser. That loop is only possible
when one framework owns both stages, which is exactly what the problem
statement asks us to build.

### 1.4 Mapping to the problem statement's requirements

| Req | USP mechanism that satisfies it |
|---|---|
| a — no information loss | USP-3 evidence bundle; `unmapped` residue kept, not dropped |
| b — extract source attributes | 10 parsers + Drain adaptive tier |
| c — normalize to taxonomy | OCSF 1.9.0 + ULPF threat class |
| d — traceability | USP-3, verified by hash at detection level |
| e — plug-and-play onboarding | USP-2 residue loop + Drain tier |
| h — AI/ML-ready | trained, calibrated, evaluated model (§3) |
| i — reduced parser effort | USP-2: rules are proposed, not hand-written |

---

## 2. Hand-picked stack

Each row states what was chosen, what it beat, and why.

### 2.1 Storage — **ClickHouse** (primary), DuckDB (portable), SQLite (demo)

| Candidate | Verdict |
|---|---|
| **ClickHouse** | **CHOSEN.** Apache-2.0, single static binary, trivially air-gapped. Columnar with 10–30× compression on log data. The credible answer to "billions of events per day" — it is what large-scale log platforms actually run. |
| PostgreSQL + TimescaleDB | Rejected. Fine at millions/day, not billions. Row-store scan cost is wrong for wide analytical queries over log data. This is what the old deck claimed and the code never implemented. |
| Elasticsearch / OpenSearch | Rejected. JVM footprint, heavy ops burden, and the Elastic licence history is a procurement risk for a 10-year government deployment. |
| DuckDB | **Adopted for a second role** — embedded, zero-server analytics over Parquet, for portable forensic export from an air-gapped enclave. |
| SQLite | **Retained as the zero-dependency demo fallback only.** |

Design: one ClickHouse instance, two tables differing in TTL and column set —
`siem_events` (hot, short TTL, full detail) and `datalake_events` (cold, long
TTL, compressed). This is a truer expression of the SIEM/Data-Lake split than
three separate databases, and it is one system to operate in an enclave.

### 2.2 Unsupervised detector — **ECOD** (primary) + IsolationForest (secondary)

| Candidate | Verdict |
|---|---|
| **ECOD** — Li et al., *ECOD: Unsupervised Outlier Detection Using Empirical Cumulative Distribution Functions*, IEEE TKDE 2022 | **CHOSEN.** Parameter-free (nothing to tune, therefore nothing to defend as arbitrary), deterministic, and it yields a **per-dimension outlier contribution for free** — which feeds our explainability requirement directly rather than needing a post-hoc explainer. |
| IsolationForest — Liu, Ting & Zhou, ICDM 2008 | **Retained as secondary.** Well understood, linear time. Kept so the ensemble does not depend on one estimator's failure modes. |
| AutoEncoder / DeepLog / LogBERT | Rejected. Need GPU or long CPU training; and the evidence is against them here — Landauer et al. (FSE 2024) found most log anomalies do not require sequence modelling, and Le & Zhang (ICSE 2022) showed reported deep-model gains largely vanish once data leakage is controlled. Choosing a deep model would be following fashion against the published evidence. |

### 2.3 Supervised fusion — **HistGradientBoostingClassifier + isotonic calibration**

| Candidate | Verdict |
|---|---|
| **sklearn `HistGradientBoostingClassifier`** | **CHOSEN.** LightGBM-class algorithm already inside sklearn 1.9 — no new dependency, which matters for an air-gapped offline bundle. Gradient-boosted trees remain the strongest family on tabular data. |
| XGBoost / LightGBM | Rejected — marginal gain over the above, at the cost of another binary dependency in the offline bundle. |
| Logistic regression | Rejected as the primary; **kept as an interpretable reference model** to quantify what the extra complexity actually buys. |
| Deep tabular (TabNet, FT-Transformer) | Rejected. Consistently fails to beat boosted trees on tabular data at this scale, and costs GPU. |

Wrapped in `CalibratedClassifierCV` (isotonic) so the output is a **probability
an analyst can act on** — "73% likely malicious" — not an uncalibrated score.
Uncalibrated scores are the reason analysts stop trusting SIEM risk numbers.

### 2.4 Training corpus — **CIC-IDS2017 (GeneratedLabelledFlows)**

Downloaded and verified on 2026-09-08.

| Property | Value |
|---|---|
| Total flows | 3,119,345 raw → **2,830,743 usable** |
| Empty padding rows removed | 288,602 (known defect in the WebAttacks file) |
| Provenance check | 2,830,743 **exactly matches the published CIC-IDS2017 flow count** — mirror is faithful |
| Benign | 2,273,097 (80.3% of usable) |
| Attack classes | 14 |
| Retains | Source/Destination IP, ports, protocol, timestamp, bytes, packets — everything entity profiling needs |

Class distribution (usable flows):

| Class | Count | Class | Count |
|---|---|---|---|
| DoS Hulk | 231,073 | Web Attack – Brute Force | 1,507 |
| PortScan | 158,930 | Web Attack – XSS | 652 |
| DDoS | 128,027 | Infiltration | 36 |
| DoS GoldenEye | 10,293 | Web Attack – SQL Injection | 21 |
| FTP-Patator | 7,938 | Heartbleed | 11 |
| SSH-Patator | 5,897 | | |
| DoS slowloris | 5,796 | | |
| DoS Slowhttptest | 5,499 | | |
| Bot | 1,966 | | |

**Why this corpus:** it is labelled, public, citable, and it is *perimeter
network traffic* — which is exactly the problem statement's declared scope. The
IP-bearing variant was chosen specifically because entity behaviour profiling
is impossible without source and destination addresses, and the more common
`MachineLearningCSV` variant strips them.

**Stated limitations, up front:** CIC-IDS2017 has documented label-quality
defects (Engelen et al., 2021). Extreme minority classes (Heartbleed n=11,
SQL Injection n=21) cannot support a per-class accuracy claim and we will not
make one. A single-network 2017 capture is not proof of 2026 generalisation.
These go on the slide, not in a footnote.

### 2.5 Rejected outright

- **LLM-based log parsing / RAG.** No offline model of useful size fits an
  air-gapped enclave's constraints, inference cost is orders of magnitude above
  our latency budget, and the previous deck already claimed a RAG layer that
  did not exist. Not repeating that.
- **Kafka in the prototype.** Correct at enterprise scale, pure overhead for a
  demo. Architecture stays partition-ready; deployment stays single-node.

---

## 3. Evaluation protocol — decided *before* we see results

This section is fixed in advance so results cannot be chosen after the fact.

**Split: temporal, not random.** A random split leaks near-duplicate flows from
the same attack burst into both sides and inflates every metric — the exact
failure Le & Zhang (ICSE 2022) identified across the published literature.

**Revised 2026-09-11, after loading the corpus.** The plan originally specified
a single Mon–Wed / Thu–Fri split. Loading the data showed why that alone is the
wrong headline: each attack family appears on exactly one day.

| Day | Attack families introduced |
|---|---|
| Monday | none — benign only |
| Tuesday | FTP-Patator, SSH-Patator |
| Wednesday | DoS Hulk / GoldenEye / slowloris / Slowhttptest, Heartbleed |
| Thursday | Web Attack (Brute Force, XSS, SQL Injection), Infiltration |
| Friday | Bot, PortScan, DDoS |

So a Mon–Wed / Thu–Fri split puts PortScan (158,930), DDoS (128,027), Bot and
all Web Attacks in test having **never appeared in training**. The supervised
layer cannot learn a class it has never seen; reported as a single headline
number that would look like failure rather than what it is — a zero-shot task.

We therefore run **both protocols and report both**:

**Protocol A — chronological within day (headline).** Per capture day, the
earliest 70% of flows by timestamp train, the latest 30% test. No shuffle
leakage, every class represented in both halves. This is the honest
"does it work" number.

**Protocol B — cross-day, zero-shot (generalisation bound).** Train Mon–Wed,
test Thu–Fri, where every test-set attack family is unseen. This measures the
question a SOC actually cares about: *will it catch tomorrow's attack, which is
not in any training set?*

**Protocol B is where the ensemble architecture has to earn its place.** The
behavioural and unsupervised layers need no labels, so they should still fire
on a PortScan the supervised layer has never seen. If ensemble recall under
Protocol B is no better than the supervised layer alone, the ensemble is
decoration and we will say so.

**Entity profiles are built on training days only,** then frozen for test. A
profile that has already seen the test day's attack is not a baseline.

**Primary metrics:**
- Area under the **precision–recall** curve (not ROC — with 20% positives and
  some classes at 0.001%, ROC-AUC flatters everything)
- Precision, recall, F1 at the chosen operating threshold
- **False positives per 10,000 benign flows** — the number a SOC actually feels
- Per-attack-class recall, with n reported alongside; classes with n < 100 are
  reported as *insufficient data*, never as a percentage
- **Alerts per day after correlation** — the product metric

**Ablation (this is what proves the USP):**

| Configuration | Purpose |
|---|---|
| Rules only | the baseline the current system effectively is |
| + entity behaviour | value of profiling |
| + ECOD/IForest novelty | value of unsupervised layer |
| + calibrated fusion | value of supervised fusion |
| **+ parse-confidence features** | **isolates USP-1's contribution** |

If the confidence features do not reduce false positives, we report that. A
measured null result stated plainly is worth more than an unmeasured claim.

---

## 4. Phases

Each phase is independently demoable and independently defensible.

### Phase 1 — Feature & profile foundation
- `backend/ml/profiles.py` — entity baselines: decaying categorical counters,
  Welford stats, LRU-bounded store
- `backend/ml/features.py` — feature extraction incl. parse-confidence features
- `backend/core/models.py` — add `FieldProvenance` so confidence survives
  normalization (this is the schema change USP-1 depends on)
- **Accept:** profiles update in O(1); memory bounded under 1M distinct entities

### Phase 2 — Corpus & replay
- `backend/ml/eval/corpus.py` — CIC-IDS2017 → `ULPFNormalizedEvent`, labels preserved
- `backend/ml/eval/replay.py` — render flows as **real device log lines**
  (Cisco ASA, PAN-OS, Suricata EVE) and push them through the *actual* pipeline
- **Accept:** replayed events are parsed by the real parsers, not injected
  post-parse. The demo must exercise the product, not bypass it.

### Phase 3 — Detectors
- `backend/ml/detectors/{base,rules,behavior,temporal,novelty}.py`
- Temporal layer includes **beaconing detection** — coefficient of variation of
  inter-arrival times per (src,dst) pair; low jitter is the classic C2 signature
- Every detector returns a score **and** its evidence. No bare numbers.
- **Accept:** each detector independently unit-tested against known positives

### Phase 4 — Training & calibration
- `scripts/train_model.py` — temporal split, fit, calibrate, persist
- `scripts/evaluate_model.py` — full §3 protocol incl. the ablation table
- `docs/MODEL_EVALUATION.md` — results, honestly, including failures
- **Accept:** a reproducible one-command run producing the metrics table

### Phase 5 — Detections layer (the product shift)
- `backend/detections/` — a **Detection** is a grouped, deduplicated,
  entity-scoped finding with title, severity, calibrated confidence,
  contributing-event timeline, evidence bundle, MITRE mapping, triage state
- Correlation so 158,930 PortScan flows become *one* detection, not 158,930 alerts
- Analyst feedback (confirm / false-positive) persisted and fed back
- **Accept:** the alert-volume reduction ratio is a measured number

### Phase 6 — Residue loop (USP-2)
- Rank unmapped fields by frequency × detection correlation
- Propose declarative mapping rules; one click to accept
- **Accept:** measured coverage improvement, unattended, over a replay run

### Phase 7 — ClickHouse migration
- `backend/storage/clickhouse_engine.py`, backend selected by env var
- SQLite retained as fallback so the demo never depends on a container
- **Accept:** identical pipeline results on both backends; throughput reported

### Phase 8 — UI (last, deliberately)
- Simplest possible. **Detections is the home screen**, not the pipeline
  animation. The pipeline view becomes a secondary "system health" tab.
- Screens: Detections → Detection detail (evidence) → Entities → Health → Search
- **Accept:** an analyst can answer "what happened, why do you think so, what do
  I do" without leaving the detail screen

---

## 5. Risks

| Risk | Mitigation |
|---|---|
| Cross-day generalisation is poor | That is a *finding*, reported as one. Fallback claim narrows to same-network baselining, which is what a real deployment does anyway. |
| ClickHouse migration overruns | Phase 7 is deliberately late; SQLite fallback means the demo is never blocked. |
| Correlation over-groups, hides real attacks | Per-class recall measured *after* correlation, not before. |
| Trained model is treated as air-gap-incompatible | Training is offline and shipped as frozen weights; runtime does no training and needs no network. |
| 2017 data challenged as stale | Conceded openly. The *method* is dataset-independent; the shipped weights are a starting prior that on-site profiles adapt away from. |

---

## 6. What we will not claim

- Not "better than Splunk/Elastic at detection"
- Not a per-class accuracy figure for any class with n < 100
- Not "billions of events/day" until measured — we report measured EPS and the
  scaling curve
- Not "novel ML". The models are established and cited; the novelty is the
  **loop between parsing and detection**, not the estimators
