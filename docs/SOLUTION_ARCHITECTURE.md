# ULPF — Solution Architecture & Positioning

**For presentation preparation. Enterprise / Government SOC deployment.**
Date: 2026-09-02

This document answers four questions in order:

1. If the system is air-gapped, how do logs get in? (the question a judge *will* ask)
2. How does containerisation actually work here, including storage?
3. What is our solution, in one sentence?
4. What already exists, and what is genuinely ours?

---

# PART 1 — The air-gap question

## 1.1 First, a correction to the premise

> *"The devices are not inside our environment, so how are we going to import
> the logs? If we connect it just for getting the logs, that's a threat, and
> then we are not air-gapped anymore."*

This contains one wrong assumption that, once fixed, dissolves most of the
problem: **the perimeter devices ARE inside the environment.**

A firewall is not "outside". A firewall has **two planes**:

| Plane | Faces | Carries |
|---|---|---|
| **Data plane** | The internet / untrusted networks | Customer traffic being filtered |
| **Management plane** | The internal management VLAN only | Config, SNMP, **and syslog** |

Logs come off the **management plane**, which never touches the internet. This
is standard practice and has a name: **out-of-band (OOB) management**. The
firewall's external interface is exposed; its management interface is on an
isolated VLAN reachable only from the NOC/SOC segment.

So ULPF receiving syslog from a firewall is **an internal LAN connection, not an
internet connection.** The air gap is intact.

## 1.2 What "air-gapped" actually means

The word is used loosely. There are three real topologies, and they have
different answers:

| Topology | Definition | How logs move | Where it's used |
|---|---|---|---|
| **Isolated enclave** | No route to the internet; internal connectivity exists | Syslog/TLS over the internal management VLAN | Most govt/enterprise SOCs. **This is the common case.** |
| **Cross-domain** | Two zones at different trust levels | **Data diode** — hardware-enforced one-way | Defence, ISRO, nuclear, power grid |
| **True air gap** | No network path at all | Removable media, hand-carried | Crypto key material, the most classified systems |

**ULPF must support all three.** That's the honest architectural requirement, and
supporting all three is itself a differentiator — most tools only assume #1.

## 1.3 Topology A — Isolated enclave (the default)

```
   INTERNET
      │
      │  (data plane — filtered traffic)
      ▼
┌───────────────┐
│   FIREWALL    │─────────┐
│   IDS / IPS   │         │  management plane
│   PROXY       │         │  syslog over TLS (RFC 5425)
└───────────────┘         │  ONE WAY: device ──▶ ULPF
      │                   ▼
      │            ┌──────────────┐
   INTERNAL        │     ULPF     │   ◀── no internet route
   NETWORK         │  (listener)  │   ◀── never initiates outbound
                   └──────┬───────┘
                          ▼
                   SIEM  +  Data Lake
```

**Key property: ULPF is listen-only.** It accepts connections; it never opens
one. Nothing inside ULPF phones home, checks for updates, downloads threat
feeds, or resolves external DNS. That is what makes it air-gap-safe, and it is
an architectural commitment we can state and demonstrate.

## 1.4 Topology B — Data diode (the real answer for defence/ISRO)

When logs must cross a trust boundary, the enterprise answer is a
**unidirectional security gateway**, commonly called a data diode.

**How it physically works:** a fibre-optic link with the transmit side present
and the **receive side physically absent**. Not a firewall rule — not software —
*there is no return path in the hardware.* Data can only travel one way. No
configuration error, no compromise, no exploit can make it flow backwards,
because the electronics to do so do not exist.

```
  HIGH-TRUST ZONE                      LOW-TRUST / SOC ZONE
  (log sources)                        (ULPF + SIEM)

  ┌──────────┐    ┌─────────┐         ┌──────────┐
  │ Devices  │───▶│  DIODE  │────────▶│   ULPF   │
  └──────────┘    │ TX │ RX │         └──────────┘
                  │ ▲  │ ✗  │
                  └─┼──┴────┘
        transmit ───┘   receive hardware absent
```

**The engineering consequence — and this is worth a slide:** a diode gives you
**no TCP**. TCP needs ACKs, and ACKs travel backwards. So across a diode you get
**UDP only, with no delivery guarantee and no retransmission.** That forces
specific design decisions:

- **Forward error correction** and sequence numbers in the protocol, because you
  cannot ask for a resend.
- **Sequence-gap detection at the receiver** — ULPF must be able to say "events
  4471–4480 never arrived", because nothing else can.
- **Hash chaining**, so a missing event is *provable*, not merely suspected.

This is exactly where ULPF's integrity design earns its place. A tool that only
reshapes logs cannot tell you what it never received. Commercial diode vendors:
Owl Cyber Defense, Waterfall Security, Fox-IT, Advenica. India: this is the
model used in critical-infrastructure NCIIPC-protected environments.

## 1.5 Topology C — Sneakernet / batch transfer

For the most sensitive enclaves, logs are exported to removable media and
carried across. ULPF supports this by making the transfer unit a **signed,
sealed batch**:

- Events batched into a file (Parquet or newline-delimited OCSF JSON)
- A **Merkle root** over the batch, so any single event can be proven a member
  without shipping the whole batch
- Manifest with batch ID, event count, time range, source enclave, SHA-256
- Detached signature

On import ULPF verifies the root before accepting a single event. This also
handles the `ObservedTimestamp` vs `Timestamp` divergence that OpenTelemetry's
Logs Data Model already models — source time and ingest time can legitimately
differ by days in a sneakernet enclave, and the schema has a place for both.

## 1.6 "Doesn't a listener increase attack surface?" — Yes. Address it directly.

This is the strongest part of your question and you should raise it *before* the
judge does. A syslog listener parsing untrusted input is genuinely the most
dangerous component in the system.

**The precedent everyone in the room will know: Log4Shell (CVE-2021-44228).** A
*logging library* was compromised because it **interpreted log content as
instructions** — a lookup syntax in a log message caused a remote class load.
The lesson is precise: log processors are attack surface *because attackers
control their input*, and every field in a log is attacker-influenced.

ULPF's defensive posture, stated as design commitments:

| Risk | Control |
|---|---|
| Code execution from log content | **The parser never evaluates, interpolates, or resolves anything in a log.** No template lookups, no dynamic imports, no `eval`. Content is data, only ever data. |
| Memory exhaustion via crafted input | Bounded template space, bounded field counts, bounded line length. Already implemented: the adaptive parser refuses to grow past a cap and reports saturation. |
| Regex catastrophic backtracking (ReDoS) | Anchored patterns, bounded quantifiers, timeouts per parse |
| Compromised ULPF pivoting deeper | **Egress-zero: no outbound connections at all.** Even if the parser is compromised, there is nowhere to call out to. |
| Malformed input silently corrupting data | Arity validation — implemented; misaligned records are flagged and confidence-degraded, not silently accepted |
| Supply chain | Offline bundle, pinned hashes, SBOM, signed images, reproducible build |

**Net argument:** the attack surface is one inbound port, running a parser that
by construction cannot execute anything, in a process with no outbound network,
in a container with a read-only root filesystem and dropped capabilities. That is
a defensible posture, and it is *more* defensible than the alternative — which is
that nobody collects the logs at all.

---

# PART 2 — Containers: how this actually works

## 2.1 The rule: containers hold compute, volumes hold state

The common confusion is "how do we store data in a container?" — you don't.
Containers are **ephemeral and replaceable**. State lives in volumes and
dedicated data services.

| Component | Container? | State | Scaling |
|---|---|---|---|
| ULPF processor (parse/normalize/classify) | Yes | **Stateless** | Horizontal — run N replicas |
| Ingest listener (syslog/TLS) | Yes | Stateless | Horizontal behind a load balancer |
| PostgreSQL + TimescaleDB (SIEM store) | Yes | **Persistent volume** | Vertical + read replicas |
| MinIO (Data Lake, S3-compatible) | Yes | **Persistent volume**, WORM/Object Lock | Horizontal, erasure coded |
| Redis (correlation window) | Yes | Ephemeral by design | Horizontal |
| Kafka (buffer) | Yes | Persistent volume | Horizontal by partition |

**Why the processor being stateless matters:** it is what lets you meet the
throughput target. Our measured single-process figure is ~895 events/sec. The
route to 10,000 EPS is not making Python faster — it is running more replicas,
which is only possible because the processor holds no state.

## 2.2 The offline bundle — how it actually gets in

This is the concrete answer to "deployable in an air-gapped network" (req j) and
"packaged in a container" (req k). It is a **build-side / air-side** split:

```
  CONNECTED BUILD ENVIRONMENT          │   AIR-GAPPED ENCLAVE
                                       │
  docker buildx build                  │
    --output type=oci                  │
  pip download --platform ...          │   docker load < ulpf-bundle.tar
  npm ci (vendored)                    │   cosign verify --offline=true
  syft → SBOM (CycloneDX)              │   docker compose up
  cosign sign (bundle annotation)      │
        ↓                              │
   ulpf-bundle.tar  ──── physical ─────▶
   + SBOM + manifest    media / diode
```

**Details that matter and that most teams get wrong:**

- **Multi-arch:** `docker save` is the wrong primitive. Use an **OCI image
  layout** (`docker buildx build --output type=oci`), which is what mirrors and
  signing tools actually consume.
- **Python wheels:** `pip download --only-binary=:all: --platform
  manylinux_2_28_x86_64 --python-version 3.12 --implementation cp --abi cp312`.
  The trap: **these flags default to the building machine, not the target.**
  Downloading on Windows for a Linux target silently gives you the wrong wheels
  for anything with C extensions.
- **Hash pinning:** `--require-hashes` is all-or-nothing — one hash activates it
  globally and every transitive dependency must be pinned and hashed. Generate
  with `pip-compile --generate-hashes`.
- **Signature verification offline:** cosign can verify with no network **only if
  the Rekor inclusion proof was stored as a bundle annotation at signing time.**
  That decision must be made on the connected side; you cannot retrofit it.
- **Registry inside the enclave:** Harbor at the boundary (CVE DB offline,
  cosign verification at pull, RBAC), or **zot** on the isolated side — a single
  Go binary, no database, OCI-native.
- **SBOM:** CycloneDX 1.7 (now ECMA-424). Cite **CISA's 2026 Minimum Elements
  for an SBOM** (published 29 July 2026), not the older NTIA 2021 baseline — it
  adds component licences, cryptographic hashes and author signatures.

## 2.3 Container hardening posture

```yaml
# The security posture, as configuration
read_only: true                    # immutable root filesystem
cap_drop: [ALL]                    # no Linux capabilities
security_opt:
  - no-new-privileges:true
  - seccomp:./ulpf-seccomp.json    # syscall allowlist
user: "10001:10001"                # non-root
networks:
  ingest:    { internal: true }    # no egress route exists
tmpfs:
  - /tmp:noexec,nosuid
```

The `internal: true` network is the enforcement of egress-zero at the
infrastructure layer, not just by convention.

---

# PART 3 — What our solution actually is

## 3.1 The one-sentence positioning

> **ULPF is not a faster log shipper. It is the evidence layer — it makes every
> event provably unmodified, explainably classified, and legally certifiable,
> starting at the moment of collection.**

## 3.2 Why that framing, and not "universal parser"

Be honest with yourselves about this, because a judge will be:

**Universal log parsing is a solved commercial problem.** Vector, Fluent Bit,
Cribl Stream, Logstash, OpenTelemetry Collector, Graylog, Wazuh and NiFi all do
it. Elastic alone ships **300+ prebuilt integrations**. If your pitch is "we
parse many log formats", the honest response is "so does everything else, and
theirs is in Rust."

What none of them do is answer the question a SOC analyst, an auditor, or a
court actually asks:

> *"Can you prove this log line is exactly what the device emitted, that nothing
> was lost between there and here, and can you show me why your system decided
> it was an attack?"*

That is the gap. Everything below is built to fill it.

## 3.3 The four pillars

### Pillar 1 — Custody begins at collection, not at storage

Splunk has integrity control, but it starts **at index time**, at **128 KB slice
granularity**, and is **not available in Splunk Cloud**. Vector, Fluent Bit and
the OTel Collector have **no integrity layer at all**. Nothing protects the event
between the device and the indexer — and that is precisely where ULPF sits.

ULPF hashes each event **at ingest** (SHA-256, already implemented), carries that
hash through every transformation, and emits it in the OCSF `raw_data_hash`
field so a downstream consumer can verify it independently. The raw payload is
preserved byte-identical alongside the normalized form.

**Say this carefully:** tamper-evident logging is *not* novel — Schneier & Kelsey
published it in 1998, and Splunk shipped it, removed it, and reshipped it. Our
claim is about **where in the pipeline it starts**, which is genuinely open.

### Pillar 2 — Explainable classification, with an evidence trail

Every ULPF classification carries the evidence that produced it:

```json
"classification": {
  "ocsf_class_name": "SMB Activity",
  "threat_class": "reconnaissance",
  "confidence": 0.75,
  "mitre_techniques": ["T1046"],
  "evidence": [
    { "signal": "action + destination.port",
      "observed": "DENY to port 445",
      "contributes": "reconnaissance (blocked remote-administration port)",
      "weight": 0.75 },
    { "signal": "destination.port", "observed": 445,
      "contributes": "OCSF SMB Activity (well-known SMB port)", "weight": 0.55 }
  ]
}
```

Cribl and Vector give you a field mapping with no provenance — you cannot ask
them *why*. For a SOC that must justify an escalation, and for an auditor
reviewing a detection, that "why" is the product.

**Paired with it: the system refuses to guess.** Below a confidence threshold it
returns `unclassified` with confidence 0.0 rather than a confident-sounding
label. A blocked SSH probe is reported as reconnaissance, **not** as "brute
force", because a single event cannot evidence a brute-force campaign — that
needs correlation across a time window. Restraint is a feature, and it is
unusual.

### Pillar 3 — An India-compliance profile that does not exist anywhere else

This is the strongest differentiator available and it is entirely concrete.

**CERT-In Direction No. 20(3)/2022** (28 April 2022, under IT Act §70B(6),
effective 27 June 2022) mandates:

- **Direction (i):** clocks synchronised to **NIC or NPL NTP servers**, or to
  servers traceable to them.
- **Direction (iv):** logs *"maintained securely for a rolling period of 180
  days and the same shall be maintained within the Indian jurisdiction."*
- **Direction (ii):** incident reporting to CERT-In **within 6 hours**.

Read those together: they are effectively a **specification for a log
pre-processing framework**. No open-source pipeline implements them. ULPF can:

- Record **NIC/NPL clock offset per event** as a provenance field
- Enforce **180-day rolling retention** as a policy engine, with proof of compliance
- Assert **jurisdiction** on every storage sink
- Pre-build the 6-hour incident report from routed SIEM events

**And the legal artifact — the sharpest single idea in this document:**

> **⚠️ Correction you must internalise:** the Indian Evidence Act §65B is
> **repealed**. The **Bharatiya Sakshya Adhiniyam, 2023** came into force
> **1 July 2024**; the electronic-records certificate is now **Section 63**.
> Citing 65B in a 2026 presentation is a visible error that a knowledgeable
> judge will catch.

BSA §63 requires a certificate accompanying electronic records **each time** they
are submitted, now in **two parts** — Part A by the device custodian (including
**hash values**), Part B by an independent expert. The Schedule provides fields
for **SHA-256**.

**ULPF already computes and preserves exactly that hash.** Auto-generating a
**BSA §63 Schedule Part A** artifact for any exported log set is therefore a
small feature on top of what exists — and nothing on the market does it. That
turns "our logs are hashed" into "our logs are court-admissible in India".

### Pillar 4 — Provable no-loss, and honest about it

An independent 2026 benchmark of log collectors found that **Fluent Bit and
Vector both emit malformed records during file rotation** (34 malformed records
in one hour at 10k logs/s), and that Vector showed **silent log loss** with
default settings plus a file-descriptor leak under load.

"Provably not losing events" is therefore a real, measurable claim — and across
a data diode, where there is no retransmission, it stops being a nice-to-have
and becomes the only way to know what happened.

---

# PART 4 — Competitive landscape

## 4.1 What already exists (be honest — the judge knows)

| Tool | What it does well | What it does not do |
|---|---|---|
| **Vector** (Datadog, Rust, MPL-2.0) | Fastest mainstream shipper; VRL is a safe non-Turing-complete transform language; huge sink coverage | No integrity layer, no custody, no compliance profile; documented silent-loss and rotation-corruption defects |
| **Fluent Bit** (CNCF, C) | Tiny footprint (~78 MiB), ubiquitous, graduated | Same — no integrity, weak stateful correlation; rotation corruption observed |
| **Logstash** (Elastic, JRuby) | Mature, huge plugin ecosystem | JVM; ~4 GB RAM recommended; heavy |
| **Cribl Stream** | Best-in-class routing/reduction; free to 1 TB/day; air-gap documented | **Closed source, commercial.** For a government air-gapped deployment the blocker is licensing and source availability, not capability |
| **OTel Collector** | Vendor-neutral, OTTL transforms, CNCF | General-purpose telemetry, not security-specific; no custody |
| **Redpanda Connect** (ex-Benthos) | Excellent stream processing | **Relicensed mid-life** from MIT — forked as Bento. A licensing-risk cautionary tale for a 10-year government deployment |
| **Wazuh** | Full open-source SIEM/XDR, air-gap documented | Decoders are XML/regex bound to its own rule engine — not reusable as a standalone pipeline |
| **Graylog Illuminate** | Prebuilt parsers + Sigma per source | **Not in Graylog Open** — Enterprise/Security only |
| **Apache NiFi** | **Has per-FlowFile data provenance** — closest prior art | JVM-heavy; provenance repo grows very large; provenance is operational, not cryptographic or legal |
| **Elastic integrations** | **300+ turn-key integrations** — the coverage bar you'll be measured against | Ecosystem lock-in; no custody layer |

## 4.2 Claims to concede immediately

Conceding these *gains* you credibility. Trying to defend them loses the room.

| Don't claim | Why |
|---|---|
| "Vendor-agnostic parsing is novel" | Everyone does it. Elastic ships 300+ integrations |
| "Air-gap deployable is unique" | Table stakes. Vector and Fluent Bit are static binaries; Wazuh, Cribl and Harbor all document air-gap paths |
| "Containerised" | Everyone ships containers |
| "High throughput" | We measured 895 EPS in Python. Rust parsers do 90,000–700,000 EPS single-threaded. **This argument is unwinnable — concede it and show the mitigation path** |
| "Tamper-evident logging is new" | Schneier & Kelsey, 1998. Splunk shipped it in 2005 |
| "Data lineage" | NiFi has had it for a decade |

## 4.3 The USP, in the order you should present it

1. **Custody starts at collection.** Splunk starts at index, 128 KB granularity,
   self-hosted only. Vector/Fluent Bit/OTel: nothing. The device-to-indexer gap
   is unowned, and that is where we sit.
2. **India-native compliance.** CERT-In clock traceability + 180-day
   jurisdictional retention + **auto-generated BSA §63 Part A certificates**.
   Nothing on the market does this.
3. **Explainable classification.** Every decision carries its evidence and its
   MITRE mapping; the system refuses to guess when it lacks signal.
4. **Diode-native ingestion.** Designed for one-way transfer with sequence-gap
   detection and hash chaining — because across a diode, nobody else can tell
   you what went missing.
5. **Sovereign supply chain.** Permissively licensed, reproducible build, signed
   images, offline SBOM, and **redistributable** offline GeoIP.

## 4.4 One more concrete differentiator worth a slide

**The GeoIP licensing trap.** Almost every pipeline uses MaxMind GeoLite2 for
offline enrichment. Its EULA:

- **Forbids redistribution** — you cannot legally bundle it into a distributed
  ULPF image without MaxMind's written consent.
- Requires you to *"cease use of and destroy … any old versions … within thirty
  (30) days"* of a new release.

**In a genuinely air-gapped enclave, a 30-day update cycle cannot be
guaranteed.** That makes GeoLite2 a *compliance defect* in every air-gapped
deployment that bundles it — including Vector-based ones.

ULPF ships **CC-BY-SA 4.0** databases instead (IP2Location LITE, DB-IP Lite) —
redistributable with attribution, no registration, no destroy clause. Small
detail; demonstrates that we actually thought about air-gap operations rather
than just saying the words.

---

# PART 5 — Requirement coverage (a–k)

| Req | Requirement | How ULPF meets it | Status |
|---|---|---|---|
| **a** | Preserve complete raw event, no loss | Byte-identical payload + SHA-256 at ingest; emitted as OCSF `raw_data` / `raw_data_hash` / `raw_data_size` so a consumer can **verify**, not just trust | Implemented, verified in tests |
| **b** | Extract source-specific attributes | 9 vendor parsers + arity validation that flags column misalignment instead of silently corrupting fields | Implemented |
| **c** | Normalize into common taxonomy | Two aligned axes: **OCSF 1.9.0 class** (what it is) + **ULPF threat class** (what it means), with MITRE ATT&CK mapping | Implemented |
| **d** | Traceability normalized ↔ original | `event_id` links every stage; `raw_data_hash` in the export makes the link independently checkable | Implemented |
| **e** | Plug-and-play onboarding | Declarative rule tables (no code changes) + **Drain-based adaptive parser** that learns structure from unseen sources with zero configuration | Implemented |
| **f** | Unified visibility | Single canonical schema across all sources; real-time dashboard | Partial — UI needs updating to surface classification |
| **g** | Efficient SIEM + Data Lake integration | Explainable router: **11.5% of realistic traffic to SIEM, 100% to Data Lake** — an ~88% reduction in SIEM ingest cost | Implemented, measured |
| **h** | AI/ML-ready analytics | Isolation Forest on observed traffic + separate deterministic rule risk; honest cold-start reporting | Implemented |
| **i** | Reduced parser development effort | Adaptive parser removes the need to write a tokenizer per source; mapping becomes a rule, not a module | Implemented |
| **j** | Air-gapped deployment | Egress-zero design; offline bundle; three supported topologies incl. data diode | Design complete; bundle needs building |
| **k** | Container packaging | Docker + Compose; stateless processors, volume-backed state; hardened runtime | Implemented |

---

# PART 6 — Slide plan (5 slides)

| # | Slide | Core message |
|---|---|---|
| 1 | **Problem & framing** | Universal parsing is solved. What isn't: proving a log is what the device emitted. Open with the NIST point — the operative US log-management guidance (SP 800-92) is from **2006** and its replacement has been in draft since Oct 2023 |
| 2 | **Architecture** | 7-stage pipeline + the three air-gap topologies, with the diode diagram. This slide answers the deployment question before it's asked |
| 3 | **What makes it different** | The four pillars. Lead with custody-at-collection; land on the **BSA §63 certificate** — that is the moment the room understands this is India-specific |
| 4 | **Evidence it works** | Live numbers only: 12/12 formats parsed, byte-identical preservation verified, 895 EPS measured (with range and methodology), 11.5% SIEM routing, 58 tests |
| 5 | **Honest roadmap** | What's built vs what's next. Explicitly: single-process is 895 EPS against a 1,000–10,000 target; multi-worker closes it and is not yet measured |

**Slide 5 is not a weakness — it is the strongest slide you have.** Every other
team will claim they hit their targets. Showing a measured number, its variance,
and precisely what closes the gap is what separates an engineering team from a
demo.

## The two sentences to rehearse

> The operative NIST log-management guidance is from **2006**, and its
> replacement has sat in draft since October 2023. Meanwhile **CERT-In Direction
> 20(3)/2022** already mandates clock traceability, 180-day retention and Indian
> jurisdiction — and no open-source pipeline implements any of it.

> ULPF is not a faster Vector. It is the **custody and compliance layer** that
> sits in front of one.

---

# PART 7 — Questions to expect, and the honest answer

| Question | Answer |
|---|---|
| *"Why not just use Vector/Cribl?"* | For transport, you should. They're faster and battle-tested. Neither can prove an event is unmodified, neither generates a BSA §63 certificate, and Cribl is closed-source — which is a procurement blocker for a classified deployment, not a technical one |
| *"How do logs reach an air-gapped system?"* | Devices are inside the enclave; logs come off the **management plane**, not the internet-facing data plane. For cross-domain, a **data diode** — one-way in hardware. For maximum isolation, signed batch transfer |
| *"Isn't your listener an attack surface?"* | Yes, and it's the most dangerous component. Log4Shell is the precedent. Our parser never interprets content as instructions, has bounded memory, and the process has **no outbound network path at all** |
| *"Only 895 EPS? That's slow."* | Correct, and we measured it rather than claiming it. Python costs us roughly 100× against Rust. The processor is stateless, so throughput scales with replicas; the hot loop is the identified candidate for a Rust extension |
| *"Is your ML real?"* | It's an Isolation Forest trained on observed traffic, reported separately from deterministic rule risk, with cold-start honestly declared. We deliberately did **not** use a deep sequence model — recent literature (FSE 2024, ICSE 2022) shows those benchmarks don't contain the anomalies those models claim to find |
| *"What's actually novel?"* | The combination: custody from collection + explainable classification + Indian legal/regulatory artifacts. Individually, prior art exists for each, and we'll say so |

---

## Sources

Detailed citations, version numbers and evidence grading in
[`RESEARCH_AND_REFERENCES.md`](RESEARCH_AND_REFERENCES.md). Implementation
evidence and measured figures in
[`SESSION6_CHANGES.md`](SESSION6_CHANGES.md).
