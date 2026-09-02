# ULPF — Session 6 Change Report

**Date:** 2026-09-02
**Scope:** Correctness audit of the existing pipeline, then research-grounded fixes.

Everything below was verified by running the code, not by reading it. Each entry
records what was wrong, the evidence, what changed, and why it matters to a
specific requirement (a–k) of the problem statement.

---

## 0. Summary

| # | Area | Severity | Status |
|---|------|----------|--------|
| 1 | Backend would not start (encoding) | Blocker | Fixed |
| 2 | Existing DB broke startup (no migration) | Blocker | Fixed |
| 3 | Event taxonomy was not implemented (req c) | Critical | Implemented |
| 4 | Router category rule was dead code | Critical | Fixed |
| 5 | `is_private` mislabelled every external IP | Critical | Fixed |
| 6 | Palo Alto parser silently mis-mapped columns | Critical | Fixed |
| 7 | ML score was rules wearing a model's name | Critical | Rewritten |
| 8 | OCSF export was not valid OCSF | High | Rewritten to 1.9.0 |
| 9 | Vendor status codes unmapped (ASA, Zeek) | Medium | Fixed |
| 10 | Throughput 10x below design target | High | 96 → 895 EPS (still short of 1,000) |

Test suite: **20 passed → 58 passed.** Two existing tests were updated because
they asserted the old, incorrect behaviour (noted individually below); 38 new
regression tests were added in `tests/test_taxonomy.py`, one per defect found.

Measured throughput: **96 EPS → 895 EPS median** (~9.3x), single process, single core.
That is just **below** the 1,000 EPS design-target lower bound - see §10b.

---

## 1. Backend would not start — non-UTF-8 source file

**Evidence**

```
SyntaxError: Non-UTF-8 code starting with '\x97' on line 2 (engine.py, line 2)
```

`PROJECT_CONTEXT.md` attributed this to `backend/router/event_router.py`. That
file was actually fine (valid UTF-8 with BOM). The real culprit was
`backend/storage/engine.py`, which contained a Windows-1252 em-dash (`0x97`) —
the byte PowerShell here-strings emit for `—`.

**Change** — re-encoded the file as UTF-8 and replaced smart punctuation with
ASCII equivalents.

**Why it matters** — a judge cloning the repo and running `uvicorn` gets an
immediate crash. This is a first-impression blocker.

**Teaching note.** `0x97` is only a valid byte in Windows-1252, never in UTF-8.
Python 3 requires source to be UTF-8 unless a PEP 263 coding declaration says
otherwise, so the file was unparseable. On Windows, `Out-File` and here-strings
default to the ANSI codepage. Use
`[System.IO.File]::WriteAllText($path, $text, [System.Text.UTF8Encoding]::new($false))`
or write files from Python with `encoding='utf-8'`.

---

## 2. Pre-existing database broke startup — no schema migration

**Evidence**

```
sqlite3.OperationalError: no such column: routed_to_siem
```

**Root cause** — `CREATE TABLE IF NOT EXISTS` does exactly what it says: if the
table exists, it does nothing at all. It does **not** reconcile columns. The
2.6 MB `ulpf_events.db` in the repo predated the routing columns, so index
creation referencing `routed_to_siem` failed.

**Change** — added `_sync_columns()` in `backend/storage/engine.py`. It parses
the column list out of the `CREATE TABLE` DDL, compares against
`PRAGMA table_info`, and issues `ALTER TABLE ... ADD COLUMN` for anything
missing. Constraints that SQLite cannot backfill (`PRIMARY KEY`, `UNIQUE`,
`NOT NULL` without a default) are stripped from the generated `ALTER`.

**Why it matters** — the alternative "fix" is deleting the database, which
destroys the demo data and would fail again on the judge's machine.

---

## 3. Requirement (c) — the event taxonomy did not exist

This was the single most serious finding. Requirement (c) is *"normalize fields
into a common event taxonomy"* — arguably the core of the whole problem
statement.

**Evidence** — the entire taxonomy implementation was one line
(`normalizer/engine.py:52`):

```python
category=str(fields.get("category", "NETWORK_TRAFFIC")).upper(),
```

That takes whatever a vendor happened to put in a field named `category`,
uppercases it, and otherwise defaults. Running all 12 samples produced exactly
three distinct categories:

```
['0', 'ANY', 'NETWORK_TRAFFIC']
```

`ANY` is Palo Alto's *URL filtering* category. `0` is a literal zero. There was
no taxonomy — only a passthrough of an accidentally-named vendor field.

**Change** — new module `backend/normalizer/taxonomy.py` implementing two
aligned classification axes:

- **OCSF class** — what kind of activity this is (DNS Activity 4003, SMB
  Activity 4006, Authentication 3002, Detection Finding 2004, …).
- **ULPF threat class** — what it *means* for security (`reconnaissance`,
  `web_exploit`, `data_exfiltration`, `benign_traffic`, …), plus MITRE ATT&CK
  technique IDs.

Design properties, chosen deliberately:

- **Declarative.** Rules live in tables (`PORT_TO_CLASS`, `APP_TO_CLASS`,
  `SIGNATURE_PATTERNS`, `URI_ATTACK_PATTERNS`, `WINDOWS_EVENT_IDS`). Onboarding
  a source means adding rows, not editing control flow — this is what makes
  requirements (e) and (i) real rather than aspirational.
- **Explainable.** Every classification returns an `evidence` list: which
  signal fired, what value was seen, what it argued for, and its weight.
- **Honest.** Below `MIN_CONFIDENCE = 0.30` the result is `UNCLASSIFIED` with
  confidence 0.0. It never guesses confidently.

**Result** — all 12 samples now classify correctly:

| Sample | OCSF class | Threat class | Conf | MITRE |
|---|---|---|---|---|
| cisco_asa_smb_sweep | SMB Activity | reconnaissance | 0.75 | T1046 |
| cisco_asa_normal_http | HTTP Activity | benign_traffic | 0.60 | — |
| palo_alto_threat_sqli | Detection Finding | web_exploit | 0.95 | T1190 |
| palo_alto_traffic_normal | DNS Activity | benign_traffic | 0.60 | — |
| suricata_dns_tunneling | Detection Finding | data_exfiltration | 0.95 | T1071.004, T1048.003 |
| aws_vpc_flow_ssh_brute | SSH Activity | reconnaissance | 0.65 | T1046 |
| zeek_conn_log | HTTP Activity | benign_traffic | 0.60 | — |
| arcsight_cef_checkpoint | Detection Finding | reconnaissance | 0.75 | T1046 |
| fortinet_kv_traffic | HTTP Activity | policy_violation | 0.55 | — |
| linux_iptables_syn_flood | HTTP Activity | policy_violation | 0.55 | — |
| windows_failed_logon | Authentication | authentication_attack | 0.98 | T1110 |
| nginx_path_traversal | HTTP Activity | web_exploit | 0.90 | T1083, T1190 |

**Deliberate restraint worth defending in the viva.** `aws_vpc_flow_ssh_brute`
is labelled `reconnaissance`, not `authentication_attack`, even though the
sample is *named* "ssh brute". A single rejected flow record cannot evidence a
brute-force attempt — that requires *N* failures in a time window. Calling it
brute force from one event would be exactly the overclaiming to avoid. The
honest upgrade path is stateful correlation, listed under remaining work.

---

## 4. The router's category rule was dead code

**Evidence**

```
Categories the normalizer emits : ['0', 'ANY', 'NETWORK_TRAFFIC']
Categories the router looks for : ['authentication_attack', 'data_exfiltration',
                                   'dos', 'intrusion', 'malware', ...]
Overlap                         : []
Router category rule fired on 0/12 events
```

Two hand-maintained lists had drifted apart. The router checked lowercase
underscore names; the normalizer emitted uppercase vendor strings. Rule #2 of
five could never fire.

**Change** — `EventRouter.SIEM_CATEGORIES` is now *derived* from the taxonomy:

```python
SIEM_CATEGORIES: frozenset = frozenset(t.value for t in SECURITY_RELEVANT)
```

The router and the classifier can no longer drift, because there is only one
definition.

Also: events classified `benign_traffic` or `unclassified` are no longer forced
into the SIEM by the high-risk-port heuristic. Permitted DNS to port 53 is not
a security event.

**Why it matters** — requirement (g), efficient SIEM integration. The entire
economic argument for a SIEM/Data-Lake split is that SIEM ingest is expensive
and Data Lake storage is cheap. A router that sends everything to the SIEM
saves nothing.

---

## 5. Every external IP was labelled internal

This is the subtlest bug found, and the most instructive.

**Evidence**

```
_is_private_ip('203.0.113.45')  ->  True     # expected False
direction for 203.0.113.45 -> 10.0.1.20  ->  'INTERNAL'   # expected INBOUND
```

**Root cause** — `ipaddress.ip_address(x).is_private` follows the IANA
special-purpose registry, which includes the **RFC 5737 documentation ranges**:
`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (and RFC 2544's
`198.18.0.0/15`). Those are precisely the ranges every vendor uses to represent
*external attackers* in sample logs. So `is_private` reported inbound attacks
as internal traffic.

`direction` was wrong on **11 of 12** samples.

**Change** — new module `backend/normalizer/netscope.py`. "Internal" is treated
as a property of a *deployment*, not of an address — the same approach as
Zeek's `local_nets` and the Splunk CIM. The operator declares internal prefixes
via `ULPF_INTERNAL_NETWORKS`; the default is RFC 1918 + loopback + link-local +
CGNAT + IPv6 ULA. Documentation ranges are tracked separately so demo traffic
can be labelled honestly.

**Result** — direction is now correct on all 12 samples, and every downstream
consumer (taxonomy, routing, ML features) improved as a consequence.

**Teaching note.** `is_private` is not a security predicate. It answers "is this
address special-purpose per IANA", not "is this host mine". Those differ in
exactly the ranges that matter for testing.

---

## 6. Palo Alto parser silently corrupted every traffic log

**Evidence** — for `palo_alto_traffic_normal`:

```
action   = '142'        (actually the byte count)
protocol = 'allow'      (actually the action)
src_port = 53           (actually the destination port)
```

**Root cause — two layers.**

1. `backend/sample_data.py` had a malformed PAN-OS TRAFFIC log: 46 columns
   where the spec has 47+, because the `dst_user` field was missing. One
   missing column shifts every field after it by one.
2. The parser mapped columns **positionally with no arity check**, so it
   accepted the shifted row and emitted confident, plausible, wrong values.

Layer 2 is the real defect. Layer 1 is the kind of thing that happens in
production constantly — truncated lines, vendor version drift, a field added in
a firmware release.

**Change**

- Fixed the sample log (inserted the missing `dst_user` column).
- Added `EXPECTED_ARITY = {"TRAFFIC": 47, "THREAT": 53}` to the parser. Rows
  shorter than expected set `_field_alignment_verified = False`, attach a
  `_parse_warning`, and drop parser confidence from 0.98 to 0.45 — which flows
  into the DQI score rather than being silently accepted.

Longer rows are still accepted, because PAN-OS only ever *appends* columns
across releases.

**Why it matters** — this is a lossless-normalization framework. Confidently
emitting `action = "142"` is worse than failing, because nothing downstream can
detect it. Requirement (b) is not "extract fields", it is "extract fields
*correctly*", and correctness you cannot verify is not correctness.

---

## 7. The ML engine was a rule engine wearing a model's name

**Evidence**

```
scores across 12 samples: [0.271, 0.53, 0.573, 0.58, 0.668, 0.724,
                           0.78, 0.81, 0.85, 0.85, 0.85, 0.85]
count at exactly 0.850: 4
```

Four events pinned to an identical value is not a model output. The cause, in
the old `anomaly_engine.py`:

```python
if norm.threat and norm.threat.signature:
    normalized_anomaly_score = max(normalized_anomaly_score, 0.85)
if norm.destination.port in (445, 3389, 135, 6379) and action in ("DENY","DROP"):
    normalized_anomaly_score = max(normalized_anomaly_score, 0.78)
if entropy > 5.4:
    normalized_anomaly_score = max(normalized_anomaly_score, 0.72)
```

Three problems:

1. **The floors override the model.** The Isolation Forest could raise a score
   but never lower one. The reported "ML anomaly score" was mostly rules.
2. **The model had never seen a real log.** `_fit_baseline_model()` fitted on
   530 vectors drawn from `np.random` with a fixed seed. It described nothing.
3. **The entropy heuristic measured log format, not threat.** Demonstrated:

   | Sample | Format | Entropy | Threat class |
   |---|---|---|---|
   | suricata_dns_tunneling | JSON | 5.40 | data_exfiltration |
   | arcsight_cef_checkpoint | CEF | 5.07 | reconnaissance |
   | zeek_conn_log | TSV | 4.40 | **benign_traffic** |
   | aws_vpc_flow_ssh_brute | CSV | 4.04 | reconnaissance |

   Entropy tracked the *serialization format* — JSON has a wider character
   distribution than syslog regardless of content. `zeek_conn_log`, benign
   traffic, was scored 0.81 and routed to the SIEM as a result.

Plus `confidence` was hardcoded to `0.94` on every event, forever.

**Change** — `backend/ml/anomaly_engine.py` rewritten. Two axes, reported
separately and never silently merged:

- `rule_risk_score` — deterministic risk derived from the taxonomy class,
  scaled by classifier confidence. Explainable by construction.
- `model_anomaly_score` — pure Isolation Forest novelty, fitted on a rolling
  window of **actually observed** events (`MIN_FIT_SAMPLES = 200`,
  `WINDOW_SIZE = 5000`), calibrated on the observed 1st/99th percentiles rather
  than hardcoded constants.

Until enough events are seen, the engine reports `model_state = "cold_start"`,
returns the rule score alone, and lowers confidence accordingly. It does not
present synthetic-data output as learned behaviour.

`confidence` is now computed from model state and window saturation.
Entropy is computed over extracted **field values**, not the raw line, so it is
comparable across formats.

**Result**

| Sample | Before | After | Class |
|---|---|---|---|
| cisco_asa_normal_http | 0.580 | **0.040** | benign_traffic |
| palo_alto_traffic_normal | 0.573 | **0.040** | benign_traffic |
| zeek_conn_log | 0.810 | **0.040** | benign_traffic |
| suricata_dns_tunneling | 0.850 | 0.829 | data_exfiltration |
| palo_alto_threat_sqli | 0.850 | 0.799 | web_exploit |

Reported confidence dropped from a fabricated 0.94 to an honest 0.41–0.45 at
cold start.

**Research support** — this is a literature-driven choice, not a capability gap,
and should be defended as such:

- Landauer, Skopik & Wurzenberger, *A Critical Review of Common Log Data Sets
  Used for Evaluation of Sequence-Based Anomaly Detection Techniques*, Proc.
  ACM Softw. Eng. 1 (FSE 2024), DOI 10.1145/3660768 — "most anomalies are not
  directly related to sequential manifestations and … advanced detection
  techniques are not required to achieve high detection rates."
- Le & Zhang, *Log-based Anomaly Detection with Deep Learning: How Far Are We?*,
  ICSE 2022, DOI 10.1145/3510003.3510155 — random train/test splits cause data
  leakage; "the problem of log-based anomaly detection has not been solved yet."
- Khan, Shin, Bianculli & Briand, *Impact of Log Parsing on Deep Learning-Based
  Anomaly Detection*, Empirical Software Engineering 29:139 (2024) — "there is
  no strong correlation between log parsing accuracy and anomaly detection
  accuracy." **Do not claim parser accuracy improves detection.**
- Liu, Ting & Zhou, *Isolation Forest*, ICDM 2008, DOI 10.1109/ICDM.2008.17 —
  linear time, low memory, unsupervised. Right baseline for CPU-only air-gap.

---

## 8. The OCSF export was not valid OCSF

**Evidence** — the old `to_ocsf()` hardcoded `class_uid: 4001` for every event
regardless of type, and omitted fields OCSF marks **required**: `metadata`
(with `version` and `product`) and `type_uid`.

**Change** — rewritten against **OCSF 1.9.0** (released 2026-08-03; verified
against the `ocsf/ocsf-schema` release feed — note the previous code claimed
"v1.1", and many vendor glossary pages still incorrectly say 1.4.0).

Now emitted correctly:

- `class_uid` from the taxonomy classifier — a DNS event exports as DNS
  Activity (4003), a Suricata alert as Detection Finding (2004).
- `type_uid = class_uid * 100 + activity_id`, per the OCSF definition.
- Required `metadata` block with schema version, product, and profiles.
- **The lossless primitives OCSF defines on `base_event`:**
  `raw_data`, `raw_data_hash` (SHA-256, `algorithm_id: 3`), `raw_data_size`,
  and `unmapped`.
- `observables[]` so a consumer can pivot on IOCs without reparsing.
- ULPF anomaly and classification results as `enrichments[]`.

**Why this is strategically important.** Requirements (a) *preserve complete raw
event data* and (d) *maintain traceability* were previously satisfied only
inside ULPF's own model — a reviewer had to take our word for it. They are now
satisfied **by the exported schema itself**, and a consumer can verify the hash
independently. That converts an assertion into a checkable property.

OCSF 1.9.0 also added a `record_integrity` profile carrying cryptographic
attestation at the base-event level. It is declared in `metadata.profiles` and
is the natural home for the chain-of-custody work listed as remaining.

---

## 9. Vendor status codes left the canonical action UNKNOWN

**Evidence**

```
cisco_asa_normal_http    mnemonic='302013'   -> action UNKNOWN
zeek_conn_log            conn_state='SF'     -> action UNKNOWN
```

Several devices never emit a literal action word. Cisco ASA emits a numeric
message ID; Zeek emits a connection-state code. Without a mapping the canonical
`action` field — the strongest single routing signal — stayed UNKNOWN.

**Change** — added two documented tables to `normalizer/mappings.py`:

- `ASA_MNEMONIC_ACTION` — 20 Cisco ASA syslog mnemonics (302013 "Built" → ALLOW,
  106023 "Deny by access-group" → DENY, …).
- `ZEEK_CONN_STATE` — all 13 Zeek `conn_state` codes with their documented
  meaning (`SF` → ALLOW "normal establishment and termination", `S0` → DROP
  "connection attempt seen, no reply", `REJ` → REJECT, …).

`106100` is deliberately mapped to UNKNOWN because that single mnemonic covers
both "permitted" and "denied" — the message text decides. Guessing would be
wrong half the time.

Also added `ZEEK_SCAN_STATES` (`S0`, `REJ`, `RSTOS0`, `SH`) — the states that
indicate scanning when aggregated per source. Not yet consumed; it belongs to
the correlation work.

---

## 10. Net effect on routing (requirement g)

| Metric | Session start | Now |
|---|---|---|
| Events routed to SIEM | 10/12 (83%) | 9/12 (75%) |
| Routing driven by a working category rule | 0/12 | 3/12 |
| Benign events wrongly sent to SIEM | 3 | **0** |
| Routing decisions with a stated reason | partial | 12/12 |

The headline percentage moved modestly because the 12 sample logs are
deliberately attack-heavy demo data. The meaningful change is that **all three
benign events are now correctly excluded**, and every decision carries an
explanation. On a realistic traffic mix (predominantly benign) the SIEM
reduction is far larger — quantifying that on realistic data is part of the
benchmark work.


---

## 10b. Throughput: measured, not claimed (design target 1,000-10,000 EPS)

`scripts/benchmark.py` was written to **measure** throughput rather than assert
it. It reports the machine it ran on, uses a warm-up phase, and labels any
multi-worker figure as an arithmetic projection.

**Starting point: 96.4 EPS** - an order of magnitude below the target's lower
bound. The stage breakdown identified the cause immediately: **ML was 87.3% of
pipeline time** at 8,597 us/event.

### Diagnosis

Profiling isolated the cost to scikit-learn's per-call overhead, which is
**fixed cost, not per-sample work**:

| Batch size | Cost per event |
|---|---|
| 1 (per-event) | 2,830 us |
| 8 | 342 us |
| 32 | 94 us |
| 64 | 49 us |

A ~58x difference driven entirely by call granularity. Implementing the isolation
path-length computation directly against the fitted trees was tested and was
*slower* (4,175 us vs 3,256 us), confirming the cost is the 50-tree Python loop
itself - which only batching amortizes.

### Fixes

1. **Batched model inference** (`MLAnomalyEngine.score_batch`,
   `PipelineOrchestrator.process_batch`). Stages INGEST..STORE run per event
   because each depends on the previous one; only the model call is batched.
2. **A real bug in the first attempt.** Profiling after the change showed
   `analyze()` running **1,600 times for 800 events** and `_model_score` still
   firing per event - the `skip_ml` early-return had been inserted at a pattern
   that did not match, so it silently never applied. Worth recording because the
   benchmark, not the code review, is what caught it.
3. **Batched storage commits** (`StorageEngine.batch_writes`). Each event
   previously committed three times - primary, Data Lake, SIEM - and every WAL
   commit is a durability barrier. That was 68.5% of pipeline time once ML was
   fixed. Committing once per batch keeps the same guarantee at the batch
   boundary, which is the correct granularity for bulk ingest.
4. `n_estimators` 100 -> 50 and refit cadence 250 -> 500 events.

### Result

| Stage of work | EPS | Dominant cost |
|---|---|---|
| Baseline | 96.4 | ML 87.3% |
| + batched inference (guard broken) | 191.5 | ML 76.2% |
| + `skip_ml` guard fixed | 789.1 | STORE 68.5% |
| + batched commits | **~895 median** | balanced |

Those intermediate figures are single runs and should be read as
order-of-magnitude steps, not precise measurements - see the methodology
correction below.

### Methodology correction - and why the headline number went down

The first reported figure was **1,112 EPS from a single 20,000-event run**. An
A/B test intended to measure the cost of the new adaptive parser showed that
number was not reproducible: repeated runs of an identical configuration landed
anywhere between ~850 and ~1,225 EPS. The parser cost nothing (994 / 946 / 950
EPS with it registered, removed, and re-registered); the spread was **run-to-run
variance on a general-purpose OS**.

A single run of this workload is a *sample*, not a measurement, and quoting the
best sample is the most common way benchmarks mislead. The harness now takes
`--repeat` independent runs, reports the **median with the observed range**, and
assesses the design target against the **slowest** run.

**Final measured figure - 10,000 events, batch 512, 5 independent runs:**

```
MEASURED THROUGHPUT          895.0 events/sec   (median, 1 process, 1 core)
Range over 5 runs            874.7 - 926.8 EPS   [875, 889, 895, 906, 927]
Failures                              0

Per-event latency (us)   mean 669.1  p50 505.0  p95 820.0  p99 1,274.1

Mean time per stage (us)
  STORE       206.2   34.7%
  PARSE       153.0   25.7%
  NORMALIZE   125.7   21.1%
  VALIDATE    109.7   18.4%
  INGEST        0.0    0.0%
```

**~9.3x improvement**, and the profile is now balanced rather than dominated by
one stage. **895 EPS is short of the 1,000 EPS lower bound** - approximately 1.1
workers, i.e. two processes, would clear it.

### What may and may not be claimed

- **May claim:** "895 events/sec median (range 875-927 across 5 independent
  runs of 10,000 events, zero failures), single process, single core, CPython
  3.14 on Windows 11. That is marginally below our 1,000 EPS design floor;
  clearing it needs two processes, and the 10,000 EPS ceiling needs roughly 11."
- **May not claim:** "over 1,000 EPS" from a single process, and no multi-worker
  number at all. The benchmark prints projections but labels them
  `(unverified)`, because CPython releases the GIL only around I/O so real
  scaling will be sub-linear.
- **The honest framing for judges:** we set a 1,000-10,000 EPS target, measured
  895, and can say precisely what closes the gap. That is a stronger position
  than an unverified claim of meeting it.

Research context (see `RESEARCH_AND_REFERENCES.md`): pure-Python per-event hot
loops sit in the 10^4-10^5 events/sec/core range, and there is **no credible
published benchmark** for Python log-parsing throughput - which is precisely why
this measures rather than cites. For comparison, Rust single-threaded parsers
reach 90,000-700,000 EPS. That argument is not winnable in Python and should be
conceded openly, with the msgspec / free-threaded 3.14 / PyO3 mitigation path
presented as a conscious trade-off.

### Routing on realistic traffic

The benchmark's `realistic_mix` corpus weights benign samples to ~92% of
traffic, because the 12 demo samples are deliberately attack-heavy and any
routing rate measured on them would mislead.

**Measured: 2,306 of 20,000 events security-relevant = 11.5% to SIEM, 100% to
Data Lake.** That is the number to quote for requirement (g) - an ~88% reduction
in SIEM ingest volume - not the 75% figure from the demo samples.

---

## 11. Files changed

**New**

| File | Purpose |
|---|---|
| `backend/normalizer/taxonomy.py` | OCSF + threat classification, declarative rules, evidence output |
| `backend/normalizer/netscope.py` | Deployment-aware internal/external resolution |
| `docs/SESSION6_CHANGES.md` | This report |
| `docs/RESEARCH_AND_REFERENCES.md` | Graded bibliography and design justifications |
| `docs/benchmark_results.json` | Machine-readable benchmark output |
| `scripts/benchmark.py` | Throughput benchmark harness |
| `tests/test_taxonomy.py` | 38 regression tests for the defects fixed this session |

**Modified**

| File | Change |
|---|---|
| `backend/storage/engine.py` | UTF-8 re-encode; `_sync_columns()` migration |
| `backend/normalizer/engine.py` | Taxonomy + netscope wiring; vendor status-code resolution |
| `backend/normalizer/mappings.py` | `ASA_MNEMONIC_ACTION`, `ZEEK_CONN_STATE`, `ZEEK_SCAN_STATES` |
| `backend/ml/anomaly_engine.py` | Rewritten: two-axis scoring, observed-data fitting, honest confidence |
| `backend/exporter/engine.py` | OCSF rewritten to 1.9.0 with lossless primitives |
| `backend/router/event_router.py` | Categories derived from taxonomy; benign-traffic exemption |
| `backend/parsers/palo_alto.py` | Column-arity validation |
| `backend/core/models.py` | `classification` field on `ULPFNormalizedEvent` |
| `backend/pipeline/orchestrator.py` | Classification threaded into the final event |
| `backend/sample_data.py` | Fixed malformed PAN-OS TRAFFIC log |
| `tests/test_pipeline.py` | Updated two tests to new behaviour; added OCSF and two-axis assertions |
| `backend/storage/engine.py` | `batch_writes()` deferred-commit context manager |
| `backend/pipeline/orchestrator.py` | `process_batch()`, `skip_ml` flag, `_finish_ml()` |
| `backend/ml/anomaly_engine.py` | `score_batch()`, `features_for()`, precomputed-score path |

---

## 12. Requirement coverage after this session

| Req | Description | Before | After |
|---|---|---|---|
| a | Preserve raw event losslessly | Working | Working, now provable in the export |
| b | Extract source-specific attributes | Working, silently wrong on PAN-OS | Working, misalignment detected |
| c | Normalize into common taxonomy | **Not implemented** | **Implemented** |
| d | Traceability normalized ↔ original | Internal only | In-schema via `raw_data_hash` |
| e | Plug-and-play onboarding | Hand-written parsers only | Declarative rule tables; adaptive parser still to do |
| f | Unified visibility | Partial | Improved; UI not yet updated |
| g | SIEM / Data Lake integration | Router partly dead code | Working and explained |
| h | AI/ML-ready analytics | Overclaimed | Honest two-axis scoring |
| i | Reduced parser effort | Not addressed | Partly; adaptive parser still to do |
| j | Air-gap deployable | Claimed | Claimed; needs offline-bundle verification |
| k | Containerized | Working | Working |

---

## 13. Remaining work

**Correctness / capability**

1. Adaptive template-mining parser (Drain-style) for unknown sources — the real
   answer to (e) and (i). Currently an unknown format falls back to
   `generic_keyvalue`. Drain is the best-performing parser in the large-scale
   ISSTA 2024 benchmark and needs no training.
2. Stateful correlation over a time window — the honest path from
   "blocked SSH probe" to "brute force", and from "dropped SYN" to "SYN flood".
3. Frontend: surface `classification`, evidence, and the two ML axes. The UI
   still shows a single anomaly score.

**Deliverables**

4. ~~Throughput benchmark~~ — **done**: 895 EPS median measured. Multi-worker
   execution is **not implemented and not measured**; it is what would close the
   gap to the 1,000-10,000 EPS target and is the highest-value performance work
   remaining.
5. Architecture document (2 pages), demo video (2 min), technical deck (5 slides).
6. Offline bundle verification — prove the air-gap claim rather than asserting it.

**Compliance differentiators identified in research (not yet built)**

7. CERT-In Direction 20(3)/2022 profile — NIC/NPL-traceable clock offset per
   event, 180-day rolling retention enforcement, Indian-jurisdiction assertion.
8. Bharatiya Sakshya Adhiniyam 2023 §63 Schedule Part A certificate generation
   for exported log sets. **Note: the Indian Evidence Act §65B is repealed —
   BSA came into force 1 July 2024. Citing 65B would be a visible error.**
9. Replace MaxMind GeoLite2 with a CC-BY-SA database (IP2Location LITE or
   DB-IP Lite). GeoLite2's EULA forbids redistribution and requires destroying
   old versions within 30 days — unsatisfiable inside an air gap.
