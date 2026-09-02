# ULPF — Research Foundation & Reference Bibliography

**Compiled 2026-09-02.** Every version number and citation below was checked
against a primary source (RFC Editor, GitHub release feeds, NIST CSRC, ACM/IEEE
DL, arXiv, CERT-In). Where something could not be verified it is marked
**[UNVERIFIED]** — do not cite those in the submission without checking.

Evidence is graded throughout:
**[PEER-REVIEWED]** · **[WORKSHOP]** · **[PREPRINT]** · **[SPEC]** · **[VENDOR]**

---

## Part 1 — Which schema should ULPF target?

### 1.1 Verified current versions

| Standard | Version | Released | Verified against |
|---|---|---|---|
| **OCSF** | **1.9.0** | 2026-08-03 | `ocsf/ocsf-schema` releases |
| ECS | 9.5.0 | 2026-08-04 | `elastic/ecs` releases |
| OTel Semantic Conventions | 1.44.0 | 2026-08-04 | `open-telemetry/semantic-conventions` |
| OTel Specification | 1.60.0 | 2026-08-07 | `open-telemetry/opentelemetry-specification` |
| Sigma Specification | 2.1.0 | 2025-09-12 | `SigmaHQ/sigma-specification` |
| Splunk CIM | 8.5.0 | 2026-04-01 | **[VENDOR]** help.splunk.com |

> **Trap:** several vendor glossary pages (Splunk, Deepwatch, Databahn) still
> state OCSF's latest is 1.4.0 — five releases stale. The ULPF exporter
> previously claimed "OCSF v1.1". Both are wrong. Never cite a vendor blog for a
> version number.

### 1.2 Why OCSF is the right canonical target

This is the single most defensible technical decision in the project, and it
rests on four checkable facts.

**(1) OCSF is the only candidate with lossless primitives as standard
base-event fields.** From `ocsf/ocsf-schema` `dictionary.json` and
`events/base_event.json`:

| Field | Purpose (per OCSF dictionary) |
|---|---|
| `raw_data` | The original event as received, before normalization — "verbatim log line, JSON payload, or other native format for forensic and debugging purposes" |
| `raw_data_hash` | Verify integrity of the original event data (added in **1.6.0**, 2025-08-01) |
| `raw_data_size` | Original size in bytes, pre-normalization |
| `unmapped` | "Preserve valuable source data that would otherwise be lost during normalization" |
| `observables[]` | IOC extraction without full reparsing |
| `metadata` | **Required.** Must carry `metadata.product` and `metadata.version` |

This matters enormously: **requirements (a) and (d) become properties of the
exported schema rather than claims about our internal model.** A consumer can
recompute the SHA-256 and verify losslessness themselves.

**(2) OCSF 1.7.0** (2025-11-14) added `log_source`, `log_source_uid` and
`log_format` — provenance fields designed for exactly a pre-processing
framework's needs.

**(3) OCSF 1.9.0** (2026-08-03) added the **`record_integrity` profile**:
cryptographic attestation over the event applied at base-event level, so any
class can carry it. This maps directly onto an air-gapped chain-of-custody
requirement and is four weeks old.

**(4) Governance.** OCSF joined the **Linux Foundation on 2024-11-19**. The
problem statement demands "vendor-agnostic". Of the five candidates, OCSF is
the only one you can defend on governance grounds — CEF is OpenText's, LEEF is
IBM's, CIM is Splunk's, ECS is Elastic's.

**Industrial existence proof [VENDOR]:** Amazon Security Lake normalizes to
OCSF and stores as Apache Parquet; custom sources *must* conform to OCSF+Parquet.

### 1.3 Recommended two-layer model

- **Layer 1 — envelope:** OpenTelemetry Logs Data Model (spec 1.60.0, Stable).
  Its written design goal is *"translating log data from an arbitrary log format
  to this Data Model and back should ideally result in identical data"* — a
  lossless round-trip objective in a stable CNCF spec. Gives `Timestamp` vs
  `ObservedTimestamp`, which matters in air-gapped batch transfer where source
  time and ingest time diverge by days.
- **Layer 2 — semantics:** OCSF 1.9.0 (as implemented in
  `backend/normalizer/taxonomy.py` and `backend/exporter/engine.py`).
- **Layer 3 — egress adapters:** CEF / LEEF / ECS / Splunk HEC on the way out.
  Interoperability is an output concern, not a schema-choice concern.

### 1.4 The counter-argument you must pre-empt

**[PREPRINT]** Holeman, R., Hastings, J., & Vaidyan, V. M. (2026). *Beyond
Collection: Measuring the Detection Efficacy of Modern Security Logging
Standards.* arXiv:2605.05531 [cs.CR].

Measured **CIM 63% vs OCSF 58% vs ECS 57%** overall effectiveness — and found
all three had **identical detection scores** (20% full kill-chain, 26% Initial
Access, 76% Execution, 90% C2).

**How to use this honestly:** the schema is not the bottleneck; capture
completeness is. That *supports* ULPF's positioning — because no schema wins on
semantics, the value is in lossless raw preservation, provenance and routing,
not in schema cleverness. Saying this before a judge does is worth more than
the point costs.

### 1.5 Syslog RFCs — get the status right

| RFC | Title | Date | **Status** |
|---|---|---|---|
| 5424 | The Syslog Protocol | Mar 2009 | Standards Track |
| 5425 | TLS Transport Mapping for Syslog | Mar 2009 | Standards Track |
| 5426 | Syslog over UDP | Mar 2009 | Standards Track |
| **6587** | Syslog over TCP | Apr 2012 | **HISTORIC** |
| **3164** | BSD syslog | Aug 2001 | **Informational** |

Two precision points most submissions get wrong:

- **RFC 6587 is Historic, not a standard.** It documents octet-counting vs
  non-transparent framing as found in the wild. A TCP syslog listener must
  handle **both**, and saying so demonstrates real familiarity.
- **RFC 3164 is Informational** — it describes observed behaviour, it does not
  standardize. Real-world "BSD syslog" is non-conformant constantly.

RFC 5424 details worth knowing: `PRI = Facility × 8 + Severity`; receivers
**MUST** accept ≥480 octets and **SHOULD** support 2048; `APP-NAME` ≤48,
`PROCID` ≤128, `MSGID` ≤32; STRUCTURED-DATA SD-IDs are IANA-registered or
`name@<private-enterprise-number>`.

---

## Part 2 — Log parsing: what the literature actually says

### 2.1 Foundational parsers

**[PEER-REVIEWED]** He, P., Zhu, J., Zheng, Z., & Lyu, M. R. (2017). *Drain: An
Online Log Parsing Approach with Fixed Depth Tree.* ICWS 2017, pp. 33–40.
DOI: 10.1109/ICWS.2017.13
> Fixed-depth parse tree; first layer by token count, later layers by leading
> tokens, leaves hold log groups. Online, streaming, **no training required**.
> `Drain3` (IBM, `logpai/Drain3`) is the maintained production fork adding
> persistence, masking and parameter extraction.

**[PEER-REVIEWED]** Du, M., & Li, F. (2016). *Spell: Streaming Parsing of System
Event Logs.* IEEE ICDM 2016. Extended: IEEE TKDE, 2019.
> Longest Common Subsequence. Two lines from the same print statement differing
> only in parameters have an LCS very likely equal to the constant portion.

**[PEER-REVIEWED]** Le, V.-H., & Zhang, H. (2023). *Log Parsing with
Prompt-based Few-shot Learning.* ICSE 2023. DOI: 10.1109/ICSE48619.2023.00204

**[PEER-REVIEWED]** Liu, Y., Zhang, X., et al. (2022). *UniParser: A Unified Log
Parser for Heterogeneous Log Data.* WWW 2022. DOI: 10.1145/3485447.3511993

### 2.2 ⭐ The benchmark that should drive ULPF's parser choice

**[PEER-REVIEWED]** Jiang, Z., Liu, J., Huang, J., Li, Y., Huo, Y., Gu, J., Chen,
Z., Zhu, J., & Lyu, M. R. (2024). *A Large-Scale Evaluation for Log Parsing
Techniques: How Far Are We?* ISSTA 2024, Vienna, pp. 223–234. arXiv:2308.10828

14 datasets, 15 parsers, 12-hour timeout. Loghub-2.0 averages **3,601,187
annotated lines and 249 templates per system** — versus 82 templates in the
2,000-line samples everyone previously benchmarked on.

Verbatim findings:

- **Finding 3:** results on Loghub-2k "do not consistently hold" at scale;
  parsers show performance drops and increased variance.
- **Finding 5:** **9 of 15 parsers could not process all datasets within 12
  hours.** Only 6 finished: Drain, IPLoM, LFA, LogCluster, LogSig, UniParser,
  LogPPT.
- **Finding 7:** on logs with **>5 parameters, LogPPT reaches only 0.16 average
  FGA and every other parser stays below 0.03.** On zero-parameter logs Drain
  exceeds 0.95 on all four metrics.
- **Overall:** "**Drain is the most performant parser**" — **+28.3% GA, +38.1%
  FGA, +18.6% FTA** over semantic-based parsers.

**[PEER-REVIEWED]** Zhu, J., He, S., Liu, J., He, P., Xie, Q., Zheng, Z., & Lyu,
M. R. (2019). *Tools and Benchmarks for Automated Log Parsing.* ICSE-SEIP 2019.
arXiv:1811.03509 — origin of Grouping Accuracy and the 2,000-line convention.

**[PEER-REVIEWED]** Zhu, J., He, S., He, P., Liu, J., & Lyu, M. R. (2023).
*Loghub: A Large Collection of System Log Datasets.* IEEE ISSRE 2023.
arXiv:2008.06448

### 2.3 ⭐ Metrics — how not to overclaim

**[PEER-REVIEWED]** Khan, Z. A., Shin, D., Bianculli, D., & Briand, L. (2022).
*Guidelines for Assessing the Accuracy of Log Message Template Identification
Techniques.* ICSE 2022. DOI: 10.1145/3510003.3510101

Three guidelines: use appropriate metrics; **perform oracle template
correction** (published ground-truth templates are themselves wrong); analyse
incorrect templates. Source of the FTA/PTA/RTA template-level metrics.

| Metric | Level | Meaning |
|---|---|---|
| GA | message | Correct grouping of messages |
| PA | message | All static/dynamic tokens correctly identified |
| FGA | template | Harmonic mean of PGA/RGA |
| FTA | template | Harmonic mean of PTA/RTA |

**Jiang et al. Finding 2:** message-level metrics inflate results relative to
template-level ones because of frequency imbalance. **Report FGA and FTA, not
just GA.** Reporting GA alone is the most common overclaim in this literature.

### 2.4 LLM-based parsing (2024–2026) — and why not in the hot path

**[PREPRINT]** Beck, V., Landauer, M., Wurzenberger, M., Skopik, F., & Rauber, A.
(2025). *System Log Parsing with Large Language Models: A Review.*
arXiv:2504.04877
> Reviews 29 LLM-based methods, benchmarks 7. Two quotable conclusions: LLM
> parsers "can achieve runtime performance comparable with fast parsers like
> Drain" **only when caching is used**; and **"45% of papers provide no
> reproducible artifacts."**

**[PREPRINT]** Ma, Z., Yang, J., & Chen, T.-H. (2026). *LLM4Log: A Systematic
Review of Large Language Model-based Log Analysis.* arXiv:2604.16359
> 145 papers. Named deployment barriers: **context limits, latency, cost,
> privacy constraints, hallucinations.** The privacy/air-gap barrier is directly
> citable for ULPF.

**[PREPRINT]** Wan, L. J., Ho, C.-T., Liang, R., Yu, C., Chen, D., & Ren, H.
(2025). *SchemaCoder: Automatic Log Schema Extraction Coder with Residual Q-Tree
Boosting.* arXiv:2508.18554
> Closest published work to ULPF's core problem. Claims the first fully
> automated schema extraction framework needing no human customization; reports
> **+21.3% over SOTA on LogHub-2.0**. Under AAAI 2026 review — cite as preprint.

**[WORKSHOP]** *Normalizing Audit Logs Using Large Language Models.* Knowledge
Infused Learning Workshop (KIL), ACM 2024. OpenReview `S0xv8LDbYN`
> Directly on point: generates Velocity Template Language templates mapping ISV
> events → **OCSF**, zero-shot. Two stages: hierarchical classification into
> OCSF category/class/activity, then template generation.

**Design conclusion for ULPF.** Do **not** put an LLM in the ingest path — cost,
latency and air-gap all forbid it. **Do** use one at design time to generate
mapping rules that a human reviews, after which deterministic mappings execute
at runtime. Both SchemaCoder and the KIL paper are precedent for exactly this,
which makes it a defensible architecture rather than a hedge.

---

## Part 3 — Anomaly detection: why ULPF deliberately uses a simple model

This section is the justification for the ML rewrite in
`backend/ml/anomaly_engine.py`. The point is that **simplicity here is
literature-driven, not a capability gap.**

### 3.1 The canonical deep-learning methods

**[PEER-REVIEWED]** Du, M., Li, F., Zheng, G., & Srikumar, V. (2017). *DeepLog:
Anomaly Detection and Diagnosis from System Logs through Deep Learning.* ACM CCS
2017, pp. 1285–1298.

**[PEER-REVIEWED]** Meng, W., Liu, Y., Zhu, Y., et al. (2019). *LogAnomaly.*
IJCAI 2019, pp. 4739–4745.

**[PEER-REVIEWED]** Zhang, X., Xu, Y., Lin, Q., et al. (2019). *Robust Log-Based
Anomaly Detection on Unstable Log Data.* ESEC/FSE 2019.

**[PEER-REVIEWED]** Guo, H., Yuan, S., & Wu, X. (2021). *LogBERT: Log Anomaly
Detection via BERT.* IJCNN 2021.

### 3.2 ⭐ The three critiques that justify ULPF's design

**[PEER-REVIEWED]** Le, V.-H., & Zhang, H. (2022). *Log-based Anomaly Detection
with Deep Learning: How Far Are We?* ICSE 2022. DOI: 10.1145/3510003.3510155
> **Random selection of training data causes data leakage** and invalidates the
> evaluation — temporal ordering must be respected. Verbatim: *"all the studied
> models do not always work well. The problem of log-based anomaly detection has
> not been solved yet."* Prior work routinely reported F1 > 0.9; those numbers
> do not survive realistic evaluation.

**[PEER-REVIEWED]** Landauer, M., Skopik, F., & Wurzenberger, M. (2024). *A
Critical Review of Common Log Data Sets Used for Evaluation of Sequence-Based
Anomaly Detection Techniques.* Proc. ACM Softw. Eng. 1 (FSE 2024).
DOI: 10.1145/3660768
> Verbatim: *"most anomalies are not directly related to sequential
> manifestations and … advanced detection techniques are not required to achieve
> high detection rates."* The benchmarks justifying sequence models largely do
> not contain sequential anomalies.

**[PEER-REVIEWED]** Khan, Z. A., Shin, D., Bianculli, D., & Briand, L. (2024).
*Impact of Log Parsing on Deep Learning-Based Anomaly Detection.* Empirical
Software Engineering **29**, art. 139.
> **"There is no strong correlation between log parsing accuracy and anomaly
> detection accuracy, regardless of the metric used."** What matters is
> *distinguishability*, not template correctness.
>
> **This is the most important finding in this document for how ULPF is
> pitched.** Never claim "our parser is X% accurate, therefore detection
> improves" — that inference is empirically refuted. Claim instead that ULPF
> preserves distinguishability and raw fidelity.

### 3.3 The chosen baseline

**[PEER-REVIEWED]** Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). *Isolation
Forest.* IEEE ICDM 2008, pp. 413–422. DOI: 10.1109/ICDM.2008.17
Extended: *Isolation-Based Anomaly Detection*, ACM TKDD 6(1), 2012.
DOI: 10.1145/2133360.2133363
> Isolates anomalies by random partitioning rather than profiling normality;
> anomalies need fewer splits, so average path length is shorter. **Linear time,
> low constant, low memory** — the right unsupervised baseline for an
> air-gapped, CPU-only deployment with no labels.

### 3.4 The defensible position for the viva

1. Ship Isolation Forest plus template-frequency baselines as the **primary**
   detector, and cite Landauer (FSE 2024) and Khan (EMSE 2024) as **the reason**.
2. Evaluate with **temporal splits, never random** — cite Le & Zhang (ICSE 2022).
3. **Never report F1 > 0.9 on HDFS/BGL as evidence of anything.** Judges who
   know this literature read it as a red flag.
4. If a deep model is included, present it as an **ablation**, not the product.

---

## Part 4 — Scale and systems

**[WORKSHOP]** Kreps, J., Narkhede, N., & Rao, J. (2011). *Kafka: a Distributed
Messaging System for Log Processing.* NetDB'11, Athens.
> Partitioned append-only commit log; pull-based consumers; broker statelessness
> with consumer-held offsets; OS page cache + `sendfile` zero-copy; per-partition
> ordering only. The correct citation for "billions of events/day" ingest.

**[PEER-REVIEWED]** Melnik, S., Gubarev, A., Long, J. J., et al. (2010). *Dremel:
Interactive Analysis of Web-Scale Datasets.* PVLDB 3(1–2), pp. 330–339.
DOI: 10.14778/1920841.1920886
> Origin of the repetition-level/definition-level record-shredding scheme that
> Parquet implements. This is what makes "we store nested OCSF events columnar"
> a principled claim rather than a tool preference.

### 4.1 Arithmetic that reframes "billions of events/day"

- 1 billion events/day = **11,574 events/sec** sustained.
- 10 billion/day = **115,741/sec**.
- With a 3× diurnal peak factor, 1B/day peaks at ~35,000/sec.
- At ~500 B/event, 1B events/day ≈ **500 GB/day** raw.

A single Rust log parser already exceeds 90,000 events/sec single-threaded, so
"billions/day" is a **distribution and durability** problem, not a raw parsing
speed problem. Framing it that way is more accurate and more impressive.

### 4.2 Independent collector benchmark

**[VENDOR, with disclosed bias]** VictoriaMetrics log-collectors benchmark
(2026). GCP `n2-highcpu-32`, each collector limited to **1 CPU core / 1 GiB RAM**,
default Helm settings, no tuning.

| Collector | Max logs/s | CPU cores @10k/s | RAM @10k/s |
|---|---|---|---|
| vlagent | 143,000 | 0.062 | 27.9 MiB |
| Fluent Bit v4.2.3 | 31,300 | 0.260 | 78.1 MiB |
| Vector v0.53.0 | 25,000 | 0.412 | 153.5 MiB |
| OTel Collector v0.146.1 | 20,500 | 0.491 | 106.8 MiB |
| Grafana Alloy | 15,700 | 0.578 | 66.4 MiB |
| Filebeat / Fluentd | ~5,000 | lost logs before 10k | — |

The authors built the benchmark to validate their own `vlagent`; treat that row
as vendor-favourable, the relative ordering of the rest as credible.

**⭐ The correctness findings are more valuable than the throughput ones:**
Fluent Bit and Vector both **emitted incomplete/malformed records during file
rotation** (34 malformed records in one hour at 10k logs/s), and Vector showed
**silent log loss** with default `glob_minimum_cooldown_ms`, a file-descriptor
leak under load, and pod-metadata loss. "Provably not losing events" is
therefore a real, measurable differentiator.

### 4.3 Python throughput — be honest

**[UNVERIFIED]** There is **no credible published benchmark** for "Python log
parsing events/sec". Anyone quoting one is quoting a blog. Measure your own —
which is exactly what `scripts/benchmark.py` does.

Order-of-magnitude anchor: a peer-reviewed packet-processing study measured
CPython 3.7 at 0.14 Mpps best case (arXiv:1909.06344). Pure-Python per-event hot
loops live in the **10⁴–10⁵ events/sec/core** range, not 10⁶.

**Mitigations, with numbers:**

- **msgspec vs pydantic v2** — msgspec's own benchmark reports pydantic V2 at
  **~12× slower** on decode→validate→re-encode. The author explicitly discloses
  the bias: *"I wrote msgspec, naturally whatever benchmark I published it's
  going to perform well in."* Independent corroboration suggests **2.5–5×** is
  the real-world figure. **Cite the caveat alongside the number** — showing you
  read it is worth more than the number.
- **Free-threaded Python** — PEP 779 accepted 2025-06-16; free-threaded build
  officially supported (Phase II) in **Python 3.14**, with a 5–10% single-thread
  regression against a 15% ceiling. This makes a `ThreadPoolExecutor` of parser
  workers a legitimate architecture as of 2025, where it was not in 2024.
- **PyO3 / Rust extensions** — v0.28 + maturin 1.8, free-threaded 3.14 support.
  Production users: Polars, Ruff, pydantic-core, orjson, cryptography.

**Recommended honest architecture:** Python for orchestration, config, schema
management, compliance logic and API; a small Rust or msgspec hot path for the
per-event parse loop; multiprocessing or free-threaded workers for horizontal
scale. **Present it as a conscious trade-off, not as a Python performance
claim.** Judges reward the former and punish the latter.

### 4.4 Storage comparison — read the caveats

A widely-circulated small-scale benchmark shows TimescaleDB beating ClickHouse
(17.6 ms vs 400.1 ms log ingestion). **Do not cite it naively.** The author
himself explains the ClickHouse figure **is the configured
`async_insert_busy_timeout_ms = 400`, not a performance limit**, notes "1M
records is not a large dataset", and ran everything in Docker on one machine.

At real scale ClickHouse wins decisively: Cloudflare reports ~**7 million
rows/sec on 24 servers** and **100+ PB**. **[VENDOR]** ClickHouse's own LogHouse
reports 100+ PB and ~500 trillion rows.

**Benchmark-selection bias, worth a slide:** RTABench shows TimescaleDB **1.9×
faster** than ClickHouse on a realistic application workload despite being
**6.8× slower** on ClickBench. Pick the benchmark that matches your query shape,
and say which you picked.

**DuckDB:** right for the hackathon demo (embedded, zero-ops, one file, trivially
air-gapped) and for offline forensic re-analysis. **Wrong for the production
ingest tier** — single-process, bottlenecks under concurrency. Saying both is
what separates a credible team from a hand-wavy one.

---

## Part 5 — Air-gap engineering

### 5.1 Standards to cite — and the honest state of NIST

- **NIST SP 800-92, *Guide to Computer Security Log Management*, September 2006**
  (Kent & Souppaya). DOI: 10.6028/NIST.SP.800-92. **Still current. Not
  withdrawn, not superseded.**
- **SP 800-92r1, *Cybersecurity Log Management Planning Guide*** — Initial
  Public Draft released **2023-10-11**, comments closed 2023-11-29, **still no
  final as of September 2026.**

> **⭐ A strong, entirely defensible pitch line:** the operative US federal
> log-management guidance is **twenty years old**, and its replacement has sat
> in draft for nearly three years.

- **NIST SP 800-53 Rev. 5** AU family — **AU-9** Protection of Audit
  Information, **AU-10** Non-repudiation, **AU-11** Audit Record Retention. Map
  ULPF features to these control IDs on a slide.

### 5.2 ⭐ CERT-In Direction 20(3)/2022 — the strongest India-specific angle

**Direction No. 20(3)/2022-CERT-In, MeitY, Government of India, 28 April 2022**,
issued under **Section 70B(6) of the Information Technology Act, 2000**.
Effective **27 June 2022** (60 days after issue).

Verbatim clauses relevant to ULPF:

- **Direction (i) — clock traceability:** all covered entities *"shall connect
  to the Network Time Protocol (NTP) Server of National Informatics Centre (NIC)
  or National Physical Laboratory (NPL) or with NTP servers traceable to these
  NTP servers, for synchronisation of all their ICT systems clocks."*
- **Direction (ii) — 6-hour reporting** of listed incidents to CERT-In.
- **Direction (iv) — the 180-day rule:** *"shall mandatorily enable logs of all
  their ICT systems and maintain them securely for a rolling period of 180 days
  and the same shall be maintained within the Indian jurisdiction."*
- **Direction (v):** VPS/cloud/VPN providers retain subscriber data for **5
  years** after cancellation.
- **Penalty:** punitive action under **Section 70B(7)** of the IT Act.
  **[UNVERIFIED]** — some sources cite a ₹1 crore figure; the Direction itself
  only cross-references 70B(7). Do not quote a rupee amount.

> **Why this is the best India slide available:** Directions (i) and (iv)
> together are effectively a *specification for a log pre-processing framework* —
> traceable clock, 180-day rolling retention, Indian jurisdiction. **No
> open-source pipeline implements this.** ULPF can enforce all three: NIC/NPL
> clock-offset recorded per event, a retention policy engine, and a jurisdiction
> assertion on every sink.

### 5.3 ⭐ Correction: Indian Evidence Act §65B is repealed

**The Indian Evidence Act, 1872 was repealed.** The **Bharatiya Sakshya
Adhiniyam, 2023 (BSA)** came into force **1 July 2024**, and the
electronic-records certificate provision is now **Section 63**, not 65B.

**Citing §65B in a 2026 submission would be a visible error.**

**BSA §63(4)** requires a certificate submitted **with the electronic record at
each instance** it is offered for admission, which must:
- *"(a) identify the electronic record … and describe the manner in which it was
  produced"*
- *"(b) give such particulars of any device involved in the production of that
  electronic record …"*
- *"(c) deal with any of the matters to which the conditions mentioned in
  sub-section (2) relate"*, signed by the person in charge.

**Key change from 65B — dual certification.** The certificate is now in two
parts: **Part A** by the person in charge of the device (device details,
IMEI/serial/MAC, and **hash values**), and **Part B** by an **independent
expert**. The Schedule provides fields for **SHA-1, SHA-256, MD5 or another
legally acceptable standard**.

**[PARTIALLY VERIFIED]** — §63(4) section text confirmed from a primary source;
the Schedule's dual-certificate structure and hash field list come from legal
commentary. **[UNVERIFIED]** — a claimed Supreme Court judgment upholding
§63(4) appears only in secondary blogs; **do not cite it.**

> **⭐ Strongest single feature idea in this document:** ULPF auto-generates a
> **BSA §63 Schedule Part A** artifact for any exported log set — record
> identification, production method, device particulars and SHA-256 hash. ULPF
> already computes and preserves that hash (`raw_data_hash` in the OCSF export).
> This is concretely useful, legally grounded, India-specific, and nothing on
> the market does it.

### 5.4 ⭐ GeoIP — a licensing trap that affects the current design

`PROJECT_CONTEXT.md` lists **MaxMind GeoLite2** for offline enrichment. Per the
GeoLite2 EULA:

- **You may not bundle it into a distributed ULPF image.** Disclosure to third
  parties requires notifying MaxMind and obtaining prior written consent, and
  recipients must be bound by substantially similar duties.
- **You must *"cease use of and destroy … any old versions … within thirty (30)
  days following the release of the updated GeoLite Databases."*** In a
  genuinely air-gapped enclave a 30-day sneakernet cycle cannot be guaranteed.
  **This is a compliance defect in every air-gapped deployment that bundles
  GeoLite2** — including Vector-based ones.
- Account and licence key required for download; 30 downloads/day limit.

**Recommended replacement — redistributable under CC-BY-SA 4.0, no registration:**
IP2Location LITE, DB-IP Lite, or IPLocate free databases. **This is a genuine
differentiator: nobody else solves it cleanly.**

### 5.5 Offline build mechanics

**Python wheels.** `pip download --only-binary=:all: --platform
manylinux_2_28_x86_64 --python-version 3.12 --implementation cp --abi cp312 -r
requirements.txt`, then `pip install --no-index --find-links=./wheelhouse`.

> **The #1 air-gap bug:** `--platform`, `--python-version`, `--implementation`
> and `--abi` **all default to the building machine, not to the most permissive
> value.** Downloading on Windows for a Linux target silently yields the wrong
> wheels for anything with C extensions. pip requires `--only-binary=:all:`
> whenever you specify any of them.
>
> `--require-hashes` is **all-or-nothing**: one `--hash` activates it globally,
> requiring hashes for **all** transitive dependencies and pinned versions
> throughout. Generate with `pip-compile --generate-hashes`.

**Images.** `docker save`/`load` for single-arch; for multi-arch use an **OCI
image layout** (`docker buildx build --output type=oci,dest=./image.tar`).
`skopeo sync` for registry-to-registry or registry-to-directory.

**Registry.** Harbor (CNCF graduated; offline Trivy CVE DB, cosign verification,
project RBAC) at the boundary; **zot** (single Go binary, no database,
OCI-native) on the isolated side.

**Signing.** cosign offline verification works **only if planned at signing
time** — the Rekor inclusion proof must be stored as a bundle annotation on the
manifest, after which `cosign verify --offline=true` needs no network.
`cosign save` must run on the connected side.

**SBOM.** CycloneDX **1.7** (Oct 2025, adopted as **ECMA-424 2nd Edition**,
Dec 2025); SPDX **3.0.1**. Cite the **CISA "2026 Minimum Elements for a SBOM",
published 29 July 2026** by CISA/NSA/FBI + 15 international partners — the first
full replacement of the 2021 NTIA baseline, adding component licences,
cryptographic hashes, author signatures and generating tooling. **Cite this, not
NTIA 2021.**

**Offline vulnerability scanning.** grype supports `GRYPE_DB_AUTO_UPDATE=false`,
a self-hosted `listing.json`, and `GRYPE_DB_MAX_ALLOWED_BUILT_AGE` to fail
closed on a stale database.

**Threat intel.** MISP supports local feeds (local URL/path, MISP-JSON/CSV/free
text) with feed definitions exportable as JSON. Wazuh's offline CVE path
(`<offline-url>file:///path/to/repo</offline-url>`) is the best worked example
to copy.

---

## Part 6 — Chain of custody

**[PEER-REVIEWED]** Schneier, B., & Kelsey, J. (1998). *Cryptographic Support for
Secure Logs on Untrusted Machines.* 7th USENIX Security Symposium, San Antonio.
> Evolving MAC key with hash-chained entries makes every entry written **before**
> compromise unreadable and undetectably-unmodifiable by the attacker. Ancestor
> of forward-secure sequential aggregate authentication.
>
> **Note honestly: this is 28-year-old prior art.** ULPF's contribution is
> *deployment*, not invention.

**[SPEC]** **RFC 9162**, *Certificate Transparency Version 2.0* (Dec 2021) —
**obsoletes RFC 6962**. Append-only Merkle tree, consistency proofs, split-view
detection. **Cite 9162, not 6962.** Trillian is the ready-made implementation.

**[SPEC]** **RFC 3161**, *Internet X.509 Time-Stamp Protocol*, Aug 2001,
Standards Track. Request carries only a hash imprint — the TSA never sees the
data. Provides proof-of-existence before a point in time.

> **Air-gap limitation you must state openly:** RFC 3161 needs an online TSA.
> Inside a true air gap you can only anchor to an *internal* TSA (weaker trust)
> or batch-anchor Merkle roots at each sneakernet crossing. A judge who knows
> crypto will ask.

**WORM.** S3 Object Lock — Governance mode (bypassable with
`s3:BypassGovernanceRetention`) vs **Compliance mode (not undoable within the
retention period, not even by root)**, plus indefinite Legal Hold. **MinIO**
implements this on-prem and is the air-gap-viable option.

### 6.1 ⭐ Prior art check: Splunk already tried this

**[VENDOR]** Splunk had IT data block signing, audit signing and event hashing —
**deprecated in 5.0, removed in 6.2**, explicitly because of *"challenges
associated with running in a distributed environment."* Replaced in 6.3 by
**Data Integrity Control**, still present in Splunk 10.x: hashes computed per
**128 KB slice** of newly indexed raw data into `l1Hashes`; on hot→warm roll, a
hash of that file becomes `l2Hash`. **Splunk Cloud does not use it.**

**Two conclusions.** (a) Do **not** claim tamper-evident logging is novel —
Splunk shipped it, removed it, and reshipped it. (b) The still-open gap is
precise: Splunk's integrity begins **at index time, at slice granularity,
self-hosted only**. Nothing protects the event between source and indexer — and
that is exactly the ULPF layer.

> **Frame it as: "chain of custody starting at collection, not at storage."**

---

## Part 7 — Competitive honesty

### 7.1 Claims that will be challenged — concede these

| Claim | Why it's weak |
|---|---|
| Vendor-agnostic parsing | Vector, Fluent Bit, OTel, Cribl, Graylog, Wazuh all do this. **Elastic ships 300+ integrations.** |
| Air-gap deployable | Table stakes. Vector and Fluent Bit are static binaries; Wazuh, Cribl and Harbor all document air-gap paths. |
| Containerized | Everyone ships containers. |
| High throughput in Python | You will lose to Rust/C/Go on any benchmark. Concede and show the mitigation. |
| Tamper-evident logging | Schneier–Kelsey 1998; Splunk shipped it; Trillian exists. |
| Data lineage | Apache NiFi has per-FlowFile provenance already. |

### 7.2 Defensible claims — lead with these

1. **Chain of custody at the collection layer, not the storage layer.** Splunk's
   starts at index time, 128 KB granularity, self-hosted only. Vector, Fluent
   Bit and OTel have none.
2. **An India-compliance profile that does not exist anywhere:** CERT-In
   NIC/NPL clock traceability per event, 180-day rolling retention with
   jurisdiction assertion, and auto-generated **BSA §63 Part A** certificates
   with SHA-256.
3. **Verifiable no-loss ingestion**, against incumbents with independently
   observed silent loss and rotation corruption.
4. **A genuinely redistributable offline enrichment bundle** — CC-BY-SA GeoIP
   rather than GeoLite2, which cannot legally be bundled and whose 30-day
   destroy clause is unsatisfiable in an air gap.
5. **Signed, reproducible, SBOM-bearing offline bundle** meeting the CISA 2026
   Minimum Elements with offline cosign verification — a supply-chain-sovereignty
   story that Cribl (closed source) and Redpanda Connect (relicensed mid-life
   from MIT, forked as Bento) structurally cannot tell.

### 7.3 Two sentences that will land

> The operative NIST log-management guidance is from **2006**, and its
> replacement has sat in draft since **October 2023**. Meanwhile **CERT-In
> Direction 20(3)/2022** already mandates clock traceability, 180-day retention
> and Indian jurisdiction in a way no open-source pipeline implements.
>
> ULPF is not a faster Vector — it is the **compliance and custody layer** that
> sits in front of one.

---

## Part 8 — Explicitly unverified

Do not cite these without checking first.

1. CEF current revision number (saw `v25` and SmartConnectors 8.3/8.4).
2. LEEF version and date (IBM docs reference 2.0; no dated spec confirmed).
3. Apache Parquet current format version number.
4. MITRE CAR exact analytic count ("~150+" is an estimate).
5. Sigma correlation rule types (`event_count`/`value_count`/`temporal`).
6. Drain3 current release version.
7. Sigma 2.1.0 date discrepancy (GitHub tag 2025-09-12 vs doc header 2025-08-02).
8. CSTS (arXiv:2603.23459) — appears to contain no empirical results.
9. Landauer et al. per-dataset numbers (ACM DL blocked; arXiv version used).
10. KIL 2024 OCSF paper evaluation results (OpenReview fetch blocked).
11. Claimed ₹1 crore penalty under IT Act §70B(7).
12. Claimed Supreme Court judgment on BSA §63(4).
13. Vector "100 TB/day" and "5–10× vs Fluentd" — not on any first-party page.
14. MaxMind 90-day key expiry (third-party reporting only).

---

## Part 9 — Where each citation is used in the code

| Code location | Citation |
|---|---|
| `backend/ml/anomaly_engine.py` module docstring | Landauer FSE 2024; Le & Zhang ICSE 2022; Liu ICDM 2008 |
| `backend/normalizer/taxonomy.py` | OCSF 1.9.0 class/category UIDs |
| `backend/exporter/engine.py` `to_ocsf()` | OCSF 1.9.0 base_event lossless primitives |
| `backend/normalizer/netscope.py` | RFC 5737, RFC 2544, RFC 6598, RFC 1918; Zeek `local_nets` |
| `backend/normalizer/mappings.py` | Cisco ASA Syslog Messages guide; Zeek `conn.log` docs |
| `scripts/benchmark.py` | Own measurement — the point is that no external number is claimed |
| **Not yet implemented** | Drain (ICWS 2017) — adaptive parser; RFC 9162 — Merkle anchoring; CERT-In 20(3)/2022; BSA §63 |
