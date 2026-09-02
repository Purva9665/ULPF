# ULPF — Bibliography with Links

Verified 2026-09-02. Evidence grade on every entry:
**[PEER-REVIEWED]** · **[WORKSHOP]** · **[PREPRINT]** · **[SPEC]** · **[LEGAL]** · **[VENDOR]**

> DOI links resolve through `doi.org`; arXiv links through `arxiv.org/abs/`.
> Anything I could not verify at a primary source is marked **[UNVERIFIED]** at
> the bottom — do not cite those without checking first.

---

## Tier 1 — the eight you should actually cite

If the deck has room for a handful, use these. Each one does specific work for
our argument.

| # | Citation | What it buys us |
|---|---|---|
| 1 | **Drain** — He et al., ICWS 2017 · [doi.org/10.1109/ICWS.2017.13](https://doi.org/10.1109/ICWS.2017.13) | Justifies the adaptive parser algorithm |
| 2 | **How Far Are We?** — Jiang et al., ISSTA 2024 · [arxiv.org/abs/2308.10828](https://arxiv.org/abs/2308.10828) | Evidence Drain is the best parser at scale |
| 3 | **Impact of Log Parsing on DL-Based Anomaly Detection** — Khan et al., EMSE 2024 · [doi.org/10.1007/s10664-024-10533-w](https://doi.org/10.1007/s10664-024-10533-w) | Stops us overclaiming parser→detection |
| 4 | **A Critical Review of Common Log Data Sets** — Landauer et al., FSE 2024 · [doi.org/10.1145/3660768](https://doi.org/10.1145/3660768) | Justifies *not* using a deep model |
| 5 | **How Far Are We? (anomaly detection)** — Le & Zhang, ICSE 2022 · [arxiv.org/abs/2202.04301](https://arxiv.org/abs/2202.04301) | Data-leakage argument; temporal splits |
| 6 | **Isolation Forest** — Liu, Ting & Zhou, ICDM 2008 · [doi.org/10.1109/ICDM.2008.17](https://doi.org/10.1109/ICDM.2008.17) | The model we actually ship |
| 7 | **CERT-In Direction 20(3)/2022** · [cert-in.org.in PDF](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf) | The India compliance differentiator |
| 8 | **Cryptographic Support for Secure Logs** — Schneier & Kelsey, USENIX Sec 1998 · [PDF](https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/schneier/schneier.pdf) | Chain-of-custody prior art — cite it to show we know it isn't novel |

---

## 1. Log parsing

**[PEER-REVIEWED]** He, P., Zhu, J., Zheng, Z., & Lyu, M. R. (2017).
*Drain: An Online Log Parsing Approach with Fixed Depth Tree.*
IEEE ICWS 2017, pp. 33–40.
- DOI: <https://doi.org/10.1109/ICWS.2017.13>
- Author PDF: <https://jiemingzhu.github.io/pub/pjhe_icws2017.pdf>
- Production fork (Drain3): <https://github.com/logpai/Drain3>

**[PEER-REVIEWED]** Du, M., & Li, F. (2016).
*Spell: Streaming Parsing of System Event Logs.* IEEE ICDM 2016.
Extended: *IEEE TKDE*, 2019.
- IEEE: <https://ieeexplore.ieee.org/document/7837916>

**[PEER-REVIEWED]** Zhu, J., He, S., Liu, J., He, P., Xie, Q., Zheng, Z., & Lyu, M. R. (2019).
*Tools and Benchmarks for Automated Log Parsing.* ICSE-SEIP 2019.
- arXiv: <https://arxiv.org/abs/1811.03509>
- Toolkit: <https://github.com/logpai/logparser>

**[PEER-REVIEWED]** Zhu, J., He, S., He, P., Liu, J., & Lyu, M. R. (2023).
*Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics.*
IEEE ISSRE 2023.
- arXiv: <https://arxiv.org/abs/2008.06448>
- Datasets: <https://github.com/logpai/loghub>

**[PEER-REVIEWED]** ⭐ Jiang, Z., Liu, J., Huang, J., Li, Y., Huo, Y., Gu, J., Chen, Z., Zhu, J., & Lyu, M. R. (2024).
*A Large-Scale Evaluation for Log Parsing Techniques: How Far Are We?*
ISSTA 2024, Vienna, pp. 223–234.
- arXiv: <https://arxiv.org/abs/2308.10828>
- Loghub-2.0: <https://github.com/logpai/loghub-2.0>
- **Key numbers:** 14 datasets, 15 parsers, 12-hour timeout. Drain best overall
  (+28.3% GA, +38.1% FGA, +18.6% FTA over semantic parsers). Only 6 of 15
  parsers finished all datasets. Above 5 parameters per template, every parser
  collapses (FGA < 0.03).

**[PEER-REVIEWED]** ⭐ Khan, Z. A., Shin, D., Bianculli, D., & Briand, L. (2022).
*Guidelines for Assessing the Accuracy of Log Message Template Identification Techniques.*
ICSE 2022.
- DOI: <https://doi.org/10.1145/3510003.3510101>
- **Why it matters:** source of the FTA/PTA/RTA template-level metrics. Report
  FGA and FTA, not just GA — reporting GA alone is the field's commonest overclaim.

**[PEER-REVIEWED]** Le, V.-H., & Zhang, H. (2023).
*Log Parsing with Prompt-based Few-shot Learning* (LogPPT). ICSE 2023.
- DOI: <https://doi.org/10.1109/ICSE48619.2023.00204>
- arXiv: <https://arxiv.org/abs/2302.07435>

**[PEER-REVIEWED]** Liu, Y., Zhang, X., et al. (2022).
*UniParser: A Unified Log Parser for Heterogeneous Log Data.* WWW 2022.
- DOI: <https://doi.org/10.1145/3485447.3511993>
- arXiv: <https://arxiv.org/abs/2202.06569>

**[PREPRINT]** *LILAC: Log Parsing using LLMs with Adaptive Parsing Cache.*
- arXiv: <https://arxiv.org/abs/2310.01796>

---

## 2. LLM-based parsing and schema induction (2024–2026)

**[PREPRINT]** Beck, V., Landauer, M., Wurzenberger, M., Skopik, F., & Rauber, A. (2025).
*System Log Parsing with Large Language Models: A Review.*
- arXiv: <https://arxiv.org/abs/2504.04877>
- **Quotable:** LLM parsers match Drain's runtime **only with caching**; *"45% of
  papers provide no reproducible artifacts."*

**[PREPRINT]** Ma, Z., Yang, J., & Chen, T.-H. (2026).
*LLM4Log: A Systematic Review of Large Language Model-based Log Analysis.*
- arXiv: <https://arxiv.org/abs/2604.16359>
- **Quotable:** names *privacy constraints* among the deployment barriers —
  directly citable for why an LLM cannot sit in an air-gapped ingest path.

**[PREPRINT]** ⭐ Wan, L. J., Ho, C.-T., Liang, R., Yu, C., Chen, D., & Ren, H. (2025).
*SchemaCoder: Automatic Log Schema Extraction Coder with Residual Q-Tree Boosting.*
- arXiv: <https://arxiv.org/abs/2508.18554>
- Closest published work to ULPF's core problem. Reports +21.3% over SOTA on
  LogHub-2.0. Under AAAI 2026 review — **cite as a preprint**.

**[WORKSHOP]** *Normalizing Audit Logs Using Large Language Models.*
Knowledge Infused Learning Workshop (KIL), ACM 2024.
- OpenReview: <https://openreview.net/forum?id=S0xv8LDbYN>
- PDF: <https://openreview.net/pdf?id=S0xv8LDbYN>
- Generates Velocity Template Language mappings from ISV events to **OCSF**,
  zero-shot. Precedent for using an LLM at design time, not at runtime.

---

## 3. Anomaly detection

**[PEER-REVIEWED]** ⭐ Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008).
*Isolation Forest.* IEEE ICDM 2008, pp. 413–422.
- DOI: <https://doi.org/10.1109/ICDM.2008.17>
- PDF: <https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf>
- Extended journal version (2012), *ACM TKDD* 6(1): <https://doi.org/10.1145/2133360.2133363>

**[PEER-REVIEWED]** Du, M., Li, F., Zheng, G., & Srikumar, V. (2017).
*DeepLog: Anomaly Detection and Diagnosis from System Logs through Deep Learning.*
ACM CCS 2017, pp. 1285–1298.
- DOI: <https://doi.org/10.1145/3133956.3134015>

**[PEER-REVIEWED]** Meng, W., Liu, Y., Zhu, Y., et al. (2019).
*LogAnomaly: Unsupervised Detection of Sequential and Quantitative Anomalies in Unstructured Logs.*
IJCAI 2019, pp. 4739–4745.
- DOI: <https://doi.org/10.24963/ijcai.2019/658>

**[PEER-REVIEWED]** Zhang, X., Xu, Y., Lin, Q., et al. (2019).
*Robust Log-Based Anomaly Detection on Unstable Log Data.* ESEC/FSE 2019.
- DOI: <https://doi.org/10.1145/3338906.3338931>

**[PEER-REVIEWED]** Guo, H., Yuan, S., & Wu, X. (2021).
*LogBERT: Log Anomaly Detection via BERT.* IJCNN 2021.
- arXiv: <https://arxiv.org/abs/2103.04475>

### The three critiques — these justify our design

**[PEER-REVIEWED]** ⭐ Le, V.-H., & Zhang, H. (2022).
*Log-based Anomaly Detection with Deep Learning: How Far Are We?* ICSE 2022.
- DOI: <https://doi.org/10.1145/3510003.3510155>
- arXiv: <https://arxiv.org/abs/2202.04301>
- **Quotable:** *"all the studied models do not always work well. The problem of
  log-based anomaly detection has not been solved yet."* Random train/test
  splits cause data leakage.

**[PEER-REVIEWED]** ⭐ Landauer, M., Skopik, F., & Wurzenberger, M. (2024).
*A Critical Review of Common Log Data Sets Used for Evaluation of Sequence-Based Anomaly Detection Techniques.*
Proc. ACM Softw. Eng. 1 (FSE 2024).
- DOI: <https://doi.org/10.1145/3660768>
- arXiv: <https://arxiv.org/abs/2309.02854>
- **Quotable:** *"most anomalies are not directly related to sequential
  manifestations and … advanced detection techniques are not required to achieve
  high detection rates."*

**[PEER-REVIEWED]** ⭐ Khan, Z. A., Shin, D., Bianculli, D., & Briand, L. (2024).
*Impact of Log Parsing on Deep Learning-Based Anomaly Detection.*
*Empirical Software Engineering* **29**, art. 139.
- DOI: <https://doi.org/10.1007/s10664-024-10533-w>
- **Quotable, and the single most important line for our pitch:** *"there is no
  strong correlation between log parsing accuracy and anomaly detection
  accuracy, regardless of the metric used."* Never claim better parsing ⇒ better
  detection.

**[PREPRINT]** *A Comprehensive Study of Machine Learning Techniques for Log-Based Anomaly Detection.*
- arXiv: <https://arxiv.org/abs/2307.16714>

---

## 4. Schema standards

**[SPEC]** **OCSF — Open Cybersecurity Schema Framework, v1.9.0** (2026-08-03)
- Browser: <https://schema.ocsf.io/>
- Repo + releases: <https://github.com/ocsf/ocsf-schema/releases>
- Linux Foundation announcement (2024-11-19): <https://www.linuxfoundation.org/press/linux-foundation-welcomes-the-open-cybersecurity-schema-framework>
- **Lossless base-event fields we rely on:** `raw_data`, `raw_data_hash` (added
  1.6.0), `raw_data_size`, `unmapped`, `observables`, required `metadata`.
  `record_integrity` profile added in **1.9.0**.
- ⚠️ Vendor glossary pages still say 1.4.0. Don't cite them.

**[SPEC]** **Elastic Common Schema (ECS), v9.5.0**
- Repo: <https://github.com/elastic/ecs>
- Docs: <https://www.elastic.co/guide/en/ecs/current/index.html>
- OTel donation OTEP 0199: <https://github.com/open-telemetry/oteps/blob/main/text/0199-support-elastic-common-schema-in-opentelemetry.md>
- ⚠️ ECS and OCSF are **not** merging. No formal convergence exists — don't claim it.

**[SPEC]** **OpenTelemetry Logs Data Model** (stable)
- <https://opentelemetry.io/docs/specs/otel/logs/data-model/>
- **Quotable design goal:** *"translating log data from an arbitrary log format
  to this Data Model and back should ideally result in identical data."*

**[SPEC]** **Sigma Specification v2.1.0**
- <https://github.com/SigmaHQ/sigma-specification>
- Rules: <https://github.com/SigmaHQ/sigma>

**[SPEC]** **MITRE ATT&CK** · <https://attack.mitre.org/>
**[SPEC]** **MITRE CAR** (Cyber Analytics Repository) · <https://car.mitre.org/>

**[VENDOR]** Splunk Common Information Model · <https://docs.splunk.com/Documentation/CIM>
**[VENDOR]** ArcSight CEF · <https://www.microfocus.com/documentation/arcsight/>
**[VENDOR]** IBM QRadar LEEF · <https://www.ibm.com/docs/en/dsm?topic=leef-overview>
**[VENDOR]** Amazon Security Lake (OCSF + Parquet in production) · <https://docs.aws.amazon.com/security-lake/>

**[PREPRINT]** Holeman, R., Hastings, J., & Vaidyan, V. M. (2026).
*Beyond Collection: Measuring the Detection Efficacy of Modern Security Logging Standards.*
- arXiv: <https://arxiv.org/abs/2605.05531>
- **The counter-argument to pre-empt:** CIM 63% vs OCSF 58% vs ECS 57%, but
  **identical detection scores**. The schema is not the bottleneck — capture
  completeness is.

---

## 5. Syslog RFCs — mind the status field

| RFC | Title | Status | Link |
|---|---|---|---|
| 5424 | The Syslog Protocol | Standards Track | <https://www.rfc-editor.org/rfc/rfc5424.html> |
| 5425 | TLS Transport Mapping for Syslog | Standards Track | <https://www.rfc-editor.org/rfc/rfc5425.html> |
| 5426 | Syslog over UDP | Standards Track | <https://www.rfc-editor.org/rfc/rfc5426.html> |
| **6587** | Syslog over TCP | **HISTORIC** | <https://www.rfc-editor.org/rfc/rfc6587.html> |
| **3164** | BSD syslog | **Informational** | <https://www.rfc-editor.org/rfc/rfc3164.html> |

Two precision points most submissions get wrong: **6587 is Historic, not a
standard** (it documents octet-counting vs non-transparent framing as found in
the wild — a listener must handle both), and **3164 is Informational** — it
describes, it does not standardize.

---

## 6. Integrity, custody, forensics

**[PEER-REVIEWED]** ⭐ Schneier, B., & Kelsey, J. (1998).
*Cryptographic Support for Secure Logs on Untrusted Machines.*
7th USENIX Security Symposium.
- PDF: <https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/schneier/schneier.pdf>
- Author archive: <https://www.schneier.com/academic/archives/1998/01/cryptographic_suppor.html>
- Follow-up (1999), *Secure Audit Logs to Support Computer Forensics*:
  <https://www.schneier.com/academic/archives/1999/05/secure_audit_logs_to.html>
- **Cite this to show we know tamper-evident logging is 28-year-old prior art.**
  Our claim is about *where in the pipeline it starts*, not that we invented it.

**[SPEC]** **RFC 9162** — Certificate Transparency v2.0 (Dec 2021).
**Obsoletes RFC 6962 — cite 9162.**
- <https://www.rfc-editor.org/rfc/rfc9162.html>
- Trillian (implementation): <https://github.com/google/trillian> · <https://transparency.dev/>

**[SPEC]** **RFC 3161** — X.509 Time-Stamp Protocol (TSP), Standards Track.
- <https://www.rfc-editor.org/rfc/rfc3161.html>
- ⚠️ Requires an **online** TSA. In a true air gap you can only anchor to an
  internal TSA or batch-anchor Merkle roots at each transfer. State this openly.

**[VENDOR]** AWS S3 Object Lock (Governance vs Compliance mode, Legal Hold)
- <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html>
- MinIO on-prem equivalent: <https://min.io/docs/minio/linux/administration/object-management/object-retention.html>

**[VENDOR]** Splunk Data Integrity Control — the prior art to concede
- <https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/audit-activity-in-splunk-enterprise/manage-data-integrity>
- Block signing was **deprecated in 5.0, removed in 6.2**; replaced in 6.3 by
  slice-level hashing (`l1Hashes` / `l2Hash`). Not in Splunk Cloud. **Starts at
  index time** — which is exactly the gap ULPF fills.

---

## 7. Indian legal and regulatory

**[LEGAL]** ⭐ **CERT-In Direction No. 20(3)/2022**, MeitY, 28 April 2022,
under IT Act §70B(6). Effective 27 June 2022.
- Official PDF: <https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf>
- CERT-In home: <https://www.cert-in.org.in/>
- **Direction (i)** — clocks synced to **NIC or NPL** NTP servers.
- **Direction (ii)** — incident reporting within **6 hours**.
- **Direction (iv)** — logs retained **180 days, rolling, within Indian jurisdiction**.
- **Direction (v)** — VPS/cloud/VPN subscriber data retained **5 years**.

**[LEGAL]** ⚠️ **Bharatiya Sakshya Adhiniyam, 2023 — in force 1 July 2024.**
The Indian Evidence Act 1872 is **repealed**; the electronic-records certificate
is now **Section 63**, not §65B.
- Act text: <https://www.indiacode.nic.in/handle/123456789/20063>
- Section 63: <https://indiankanoon.org/doc/125020475/>
- Commentary on the dual Part A / Part B certificate and its **SHA-256** field:
  <https://www.livelaw.in/articles/electronic-evidence-admissibility-section-63-bhartiya-saksha-adhiniyam-2023-261511>
- **Citing §65B in 2026 is a visible error.**

**[SPEC]** NIC NTP service · <https://samay.nic.in/> — CSIR-NPL · <https://www.nplindia.org/>

**[LEGAL]** Information Technology Act, 2000 §70B · <https://www.indiacode.nic.in/handle/123456789/1999>

**[LEGAL]** NCIIPC (critical information infrastructure) · <https://nciipc.gov.in/>

---

## 8. Standards and compliance (international)

**[SPEC]** **NIST SP 800-92**, *Guide to Computer Security Log Management*,
September 2006 — **still current, not superseded**.
- <https://csrc.nist.gov/pubs/sp/800/92/final>
- DOI: <https://doi.org/10.6028/NIST.SP.800-92>

**[SPEC]** **NIST SP 800-92r1** — Initial Public Draft, 11 Oct 2023.
**Still a draft as of Sept 2026.**
- <https://csrc.nist.gov/pubs/sp/800/92/r1/ipd>
- Draft PDF: <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-92r1.ipd.pdf>
- **The pitch line this supports:** the operative US federal log-management
  guidance is **twenty years old** and its replacement has sat in draft for three.

**[SPEC]** **NIST SP 800-53 Rev. 5** — AU family: **AU-9** (Protection of Audit
Information), **AU-10** (Non-repudiation), **AU-11** (Audit Record Retention).
- <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>
- Browsable: <https://csf.tools/reference/nist-sp-800-53/r5/au/>

**[SPEC]** **CISA — 2026 Minimum Elements for a Software Bill of Materials**,
published 29 July 2026 (CISA + NSA + FBI + 15 international partners). Replaces
the NTIA 2021 baseline. **Cite this one.**
- <https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom>
- PDF: <https://www.cisa.gov/sites/default/files/2026-07/2026_cisa_sbom_minimum_elements_508c.pdf>

**[SPEC]** CycloneDX 1.7 (ECMA-424) · <https://cyclonedx.org/> — SPDX 3.0.1 · <https://spdx.dev/>
**[SPEC]** SLSA supply-chain levels · <https://slsa.dev/>
**[SPEC]** Sigstore / cosign · <https://docs.sigstore.dev/> · <https://github.com/sigstore/cosign>

---

## 9. Scale and systems

**[WORKSHOP]** Kreps, J., Narkhede, N., & Rao, J. (2011).
*Kafka: a Distributed Messaging System for Log Processing.* NetDB'11, Athens.
- PDF: <https://notes.stephenholiday.com/Kafka.pdf>
- Kafka design docs: <https://kafka.apache.org/documentation/#design>
- Cite **as a workshop paper**, not a conference paper.

**[PEER-REVIEWED]** Melnik, S., Gubarev, A., Long, J. J., et al. (2010).
*Dremel: Interactive Analysis of Web-Scale Datasets.* PVLDB 3(1–2), pp. 330–339.
- DOI: <https://doi.org/10.14778/1920841.1920886>
- PDF: <https://research.google/pubs/pub36632/>
- CACM version (2011): <https://doi.org/10.1145/1953122.1953148>
- Origin of the record-shredding scheme Parquet implements — this is what makes
  "columnar nested OCSF events" a principled claim, not a tool preference.

**[SPEC]** Apache Parquet format · <https://parquet.apache.org/docs/file-format/>

**[PREPRINT]** *Performance of Python for packet processing* (order-of-magnitude
anchor for pure-Python hot loops) · <https://arxiv.org/abs/1909.06344>

**[SPEC]** **PEP 779** — free-threaded Python officially supported in 3.14.
- <https://peps.python.org/pep-0779/>

**[VENDOR]** PyO3 (Rust extensions) · <https://pyo3.rs/>
**[VENDOR]** msgspec benchmarks (vs pydantic v2) · <https://msgspec.dev/benchmarks>
— author discloses his own bias; independent reports suggest 2.5–5×, not 12×.

---

## 10. Competitive landscape (all **[VENDOR]** unless noted)

| Tool | Link |
|---|---|
| Vector (Datadog) | <https://vector.dev/> · releases <https://vector.dev/releases/> |
| Fluent Bit | <https://fluentbit.io/> · docs <https://docs.fluentbit.io/> |
| Logstash | <https://www.elastic.co/logstash> |
| Cribl Stream | <https://cribl.io/stream/> · air-gap <https://docs.cribl.io/billing-licensing/on-prem-licensing/> |
| OpenTelemetry Collector | <https://opentelemetry.io/docs/collector/> |
| Redpanda Connect (ex-Benthos) | <https://github.com/redpanda-data/connect> · fork Bento <https://github.com/warpstreamlabs/bento> |
| Wazuh | <https://documentation.wazuh.com/> · offline CVE <https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/offline-update.html> |
| Graylog Illuminate (Enterprise only) | <https://graylog.org/feature/content/> |
| Apache NiFi (provenance prior art) | <https://nifi.apache.org/nifi-docs/nifi-in-depth.html> |
| Elastic integrations (300+) | <https://www.elastic.co/integrations/data-integrations> |

**Independent collector benchmark (2026)** — the best public methodology I found,
though authored by a vendor whose own agent is in the table:
- <https://victoriametrics.com/blog/log-collectors-benchmark-2026/>
- Configs: <https://github.com/VictoriaMetrics/log-collectors-benchmark>
- **The correctness findings matter more than the throughput ones:** Fluent Bit
  and Vector both emitted malformed records during file rotation; Vector showed
  silent log loss with default settings.

---

## 11. Air-gap operations

**MaxMind GeoLite2 — the licensing trap**
- EULA: <https://www.maxmind.com/en/geolite/eula>
- Docs: <https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/>
- **Forbids redistribution**, and requires destroying old versions within **30
  days** of a release — unsatisfiable inside an air gap.

**Redistributable alternatives (CC-BY-SA 4.0, no registration)**
- IP2Location LITE: <https://lite.ip2location.com/>
- DB-IP Lite: <https://db-ip.com/db/>
- IPLocate: <https://www.iplocate.io/>

**Offline tooling**
- pip secure installs / `--require-hashes`: <https://pip.pypa.io/en/stable/topics/secure-installs/>
- `pip download`: <https://pip.pypa.io/en/stable/cli/pip_download/>
- manylinux: <https://github.com/pypa/manylinux>
- Harbor registry: <https://goharbor.io/> — zot: <https://zotregistry.dev/>
- skopeo: <https://github.com/containers/skopeo>
- grype offline DB: <https://oss.anchore.com/docs/architecture/grype-db/>
- MISP offline feeds: <https://www.misp-project.org/feeds/>
- Verdaccio (offline npm): <https://verdaccio.org/>

**Data diodes (unidirectional gateways)**
- Owl Cyber Defense: <https://owlcyberdefense.com/>
- Waterfall Security: <https://waterfall-security.com/>
- Advenica: <https://advenica.com/>

---

## 12. Unverified — check before citing

1. CEF current revision number (saw `v25` and SmartConnectors 8.3/8.4).
2. LEEF version and date — IBM docs reference 2.0; no dated spec confirmed.
3. Apache Parquet current format version number.
4. MITRE CAR exact analytic count ("~150+" is an estimate).
5. Sigma correlation rule types (`event_count`/`value_count`/`temporal`).
6. Drain3 current release version.
7. Sigma 2.1.0 date discrepancy (GitHub tag 2025-09-12 vs doc header 2025-08-02).
8. CSTS (<https://arxiv.org/abs/2603.23459>) — appears to be a position paper with
   no empirical results.
9. Landauer et al. per-dataset numbers — ACM DL blocked automated fetch; the
   arXiv version was used.
10. KIL 2024 OCSF paper evaluation results — OpenReview blocked automated fetch;
    retrieve the PDF manually.
11. Any ₹ penalty figure under IT Act §70B(7). The Direction only cross-references
    the section.
12. A claimed Supreme Court judgment upholding BSA §63(4) — appears only in
    secondary blogs. **Do not cite.**
13. Vector's "100 TB/day" and "5–10× vs Fluentd" — not on any first-party page.
14. MaxMind 90-day licence-key expiry — third-party reporting only.

---

## How to cite in the deck

Slides don't take full citations. Use author-year inline and put the full list
on a final references slide:

> "Drain (He et al., 2017) is the best-performing parser at scale
> (Jiang et al., ISSTA 2024)."

> "We use Isolation Forest (Liu et al., 2008) rather than a sequence model,
> because Landauer et al. (FSE 2024) show the benchmarks justifying those models
> largely don't contain sequential anomalies."

> "Logs are retained 180 days in Indian jurisdiction per CERT-In Direction
> 20(3)/2022, and exported with a Bharatiya Sakshya Adhiniyam §63 certificate."
