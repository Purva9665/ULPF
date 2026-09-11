# ULPF — Universal Log Pre-processing Framework

**Smart India Hackathon 2026 · Problem Statement SIH26156 · NTRO**

Ingests logs from any perimeter device, parses and normalizes them into a
lossless universal schema, and turns them into **detections an analyst can
work** — not a stream of scored events.

---

## Quick start

Two ways to run it.

> **Both paths have been run end-to-end and verified.** The Docker image was
> built and started, the trained model loads inside the container, and its
> predictions were checked to be bit-identical to the local install (see
> [Container verification](#container-verification) below).

### Option A — Docker (recommended)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) only.
No Python, no Node.

```bash
git clone https://github.com/Purva9665/ULPF.git
```

```bash
cd ULPF && docker compose up --build
```

Then open **http://localhost:8000**

First build takes 3–5 minutes (it compiles the frontend and installs Python
packages). Later starts take seconds.

To stop it:

```bash
docker compose down
```

### Option B — Run locally without Docker

Needs **Python 3.11+** and **Node 20+**.

```bash
git clone https://github.com/Purva9665/ULPF.git && cd ULPF
```

**1. Backend** — create a virtual environment and install dependencies.

Create it:

```bash
python -m venv .venv
```

Activate it — **pick the line for your shell**:

| Shell | Command |
|---|---|
| Windows PowerShell | `.venv\Scripts\Activate.ps1` |
| Windows CMD | `.venv\Scripts\activate.bat` |
| Git Bash / macOS / Linux | `source .venv/bin/activate` (Git Bash on Windows: `source .venv/Scripts/activate`) |

If PowerShell blocks the script, run this once and try again:

```bash
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then install:

```bash
pip install -r backend/requirements.txt
```

Skipping the virtual environment entirely also works — `pip install -r backend/requirements.txt` straight into your system Python is fine for a prototype.

**2. Frontend** (in the same folder)

```bash
cd frontend && npm install && npm run build && cd ..
```

**3. Start it**

```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open **http://localhost:8000**.

> Building the frontend once (step 2) means the Python server serves the UI
> too, so you only run one process. For frontend development with hot reload,
> run `npm run dev --prefix frontend` in a second terminal and use port 5173.

### Container verification

Verified on Docker 29.7.2 / Compose v5.5.1:

| Check | Result |
|---|---|
| `docker compose build` | succeeds, ~90s cold |
| Image size | 650 MB |
| Container healthcheck | `healthy` in ~9s |
| Trained model loads inside container | yes — `mode: trained`, no error |
| 12 sample logs through the container | 12 processed, 0 failed, 2 detections |
| Build context | 1.7 MB (a `.dockerignore` keeps the corpus out) |

**One expected warning.** The container resolves scikit-learn 1.9.1 while the
shipped model was trained on 1.9.0, so scikit-learn prints
`InconsistentVersionWarning` at startup. This was checked rather than assumed:
running 200 identical feature vectors through the model in both environments
gives **bit-identical probabilities** (sum delta 0.0), across different
scikit-learn patch versions, different Python versions (3.14 vs 3.11) and
different operating systems. The warning is cosmetic here. If you would rather
not see it at all, pin `scikit-learn==1.9.0` in `backend/requirements.txt`.

---

## Using the prototype

The app opens on **Detections**.

1. Click **Run sample logs** — pushes 12 bundled sample events (Cisco ASA,
   Palo Alto, Suricata, AWS VPC Flow, Zeek, CEF, FortiGate, Windows, nginx,
   iptables) through the full pipeline.
2. The **detection queue** fills. Each row is one finding, not one event.
3. Click a detection to see **why it was flagged** — the weighted evidence
   behind the verdict, including evidence *against*, its MITRE ATT&CK mapping,
   and the contributing raw events with their SHA-256 hashes.
4. Mark it **Investigating / Confirmed / False positive**.

The badge at the top right says **TRAINED MODEL** when the shipped model
loaded, or **HEURISTIC** if it did not — the app never hides which one is
running.

Other tabs (Pipeline, Demo, Log Explorer, Event Journey) show the underlying
stage-by-stage processing.

---

## What's inside

### Pipeline

```
raw log → INGEST → PARSE → NORMALIZE → VALIDATE → STORE → DETECT → EXPORT
          (SHA-256) (10 parsers) (OCSF 1.9)  (DQI)  (SQLite)  (ensemble)
```

### Detection model

| Layer | What it does | Why this choice |
|---|---|---|
| **Rules** | Taxonomy + MITRE + known indicators | Works on event one, no warm-up |
| **Behaviour** | Compares an event to that entity's own baseline | Scans and brute force look normal per-event; only the *shape* gives them away |
| **Temporal** | Burst, failure runs, **beaconing** | Beaconing catches C2 by its regularity — inter-arrival coefficient of variation |
| **Novelty** | **ECOD** + Isolation Forest | ECOD is parameter-free, deterministic, and gives per-feature attribution for free |
| **Fusion** | HistGradientBoosting + isotonic calibration | Output is a real probability an analyst can threshold, not an arbitrary score |

ECOD is implemented in-tree (`backend/ml/detectors/novelty.py`) rather than
pulled from PyOD — it's ~40 lines of NumPy and an offline air-gapped bundle
shouldn't carry a dependency for that.

### Technology used

| Area | Technology |
|---|---|
| Backend | Python 3.11+, FastAPI, Uvicorn, Pydantic v2, WebSockets |
| ML | scikit-learn (HistGradientBoosting, isotonic calibration, IsolationForest), NumPy |
| Frontend | React 19, TypeScript, Vite 8, lucide-react |
| Storage | SQLite (WAL mode) — three logical stores: primary, SIEM, data lake |
| Packaging | Docker multi-stage build, docker compose |
| Schema | OCSF 1.9.0, MITRE ATT&CK |
| Training data | CIC-IDS2017 (ICISSP 2018) |

No runtime network calls, no CDN fonts, no external APIs — the whole thing runs
air-gapped.

---

## Tests

```bash
python -m pytest tests/ -q
```

164 tests. They do not need the training corpus — corpus-dependent tests skip
automatically when it is absent.

---

## Retraining the model (optional)

Not needed to run the prototype. A trained model ships in `models/`.

**1. Fetch the corpus** (~271 MB, downloaded once, git-ignored)

```bash
python scripts/fetch_corpus.py
```

This verifies the download against the published flow count (2,830,743) so a
tampered or truncated mirror is caught.

**2. Train and evaluate**

```bash
python scripts/train_and_evaluate.py --per-day 120000
```

Takes roughly 40 minutes. Writes `models/ulpf_fusion.pkl` and
`docs/model_evaluation.json`.

**3. Other experiments**

```bash
python scripts/usp1_experiment.py
```

```bash
python scripts/measure_detections.py
```

---

## Measured results

Trained on 600,000 flows from CIC-IDS2017, evaluated under two protocols fixed
*before* results were seen (see `docs/IMPLEMENTATION_PLAN.md`).

**Protocol A — chronological within day.** Earliest 70% of each capture day
trains, latest 30% tests. No shuffle leakage.

| Metric | Value |
|---|---|
| PR-AUC | **0.9868** |
| Precision | 0.9593 |
| Recall | 0.9851 |
| F1 | 0.972 |
| False positives per 10k benign | 59.5 |

**Protocol B — cross-day, zero-shot.** Trains Mon–Wed, tests Thu–Fri, where
every test attack family is one the model has never seen.

| Metric | Value |
|---|---|
| PR-AUC | **0.4158** |
| Recall | 0.9336 |
| Precision | 0.4206 |
| False positives per 10k benign | 3375.9 |

**Ablation (Protocol A)** — what each layer contributes alone:

| Configuration | PR-AUC | F1 | FP/10k |
|---|---|---|---|
| rules only | 0.1735 | 0.2394 | 922.0 |
| behaviour only | 0.1408 | 0.2595 | 8096.3 |
| temporal only | 0.8352 | 0.9023 | 159.3 |
| novelty only | 0.1083 | 0.2645 | 7187.8 |
| **fused ensemble** | **0.9868** | **0.972** | **59.5** |

---

## Honest limitations

These are stated here rather than discovered later.

- **Protocol B is poor.** On attack families it has never seen, precision drops
  to 0.42 and false positives rise sharply. Recall stays high (0.93), so the
  ensemble still *fires* on unseen attacks — it just fires on a lot else too.
- **The confidence-feature mechanism did not work**, and the first attempt to
  measure it was itself flawed. Each condition chose its own threshold by
  maximising F1 on its own training split, so the false-positive counts were
  read at *different operating points* (0.8294, 0.8698, 0.8968, 0.8676) and are
  not a valid comparison. That flaw produced two reports that contradict each
  other: `docs/model_evaluation.json` shows 59.5 vs 122.2 FP/10k (mechanism
  helps), `docs/usp1_experiment.json` shows 154.2 vs 105.7 (mechanism hurts).
  The threshold-independent metric is the one to trust, and it says the
  mechanism does nothing on clean data (PR-AUC 0.9863 both ways) and is
  actively worse under degradation (0.7066 with vs 0.7682 without). So the
  conclusion stands - the mechanism is not supported - but the FP figures
  previously quoted here were not evidence for it. `scripts/usp1_matched_recall.py`
  re-runs the comparison at matched recall, which is the correct test.
- **Sampling artifact.** Training sampled 120,000 flows per capture day, which
  thins the event stream and therefore understates true event rates. The
  temporal detector measures events per 60 seconds of real time, so its
  contribution is likely *understated* here.
- **CIC-IDS2017 is a 2017 single-network capture** with documented label
  defects (Engelen et al., 2021). Classes with fewer than 100 samples
  (Heartbleed n=11, SQL Injection n=21, Infiltration n=36) are reported as
  *insufficient data*, never as a percentage.
- **Throughput is ~1,200 EPS single-process.** The "billions of events per day"
  target needs horizontal scale-out; that is designed for but not measured.
- **Storage is SQLite.** ClickHouse is the intended production store and is not
  implemented yet.

---

## Repository layout

```
backend/
  core/          models, parser registry
  ingestion/     SHA-256 chain of custody
  parsers/       10 parsers + Drain adaptive tier
  normalizer/    OCSF mapping, taxonomy, field provenance
  validator/     data quality scoring
  storage/       SQLite WAL engine
  ml/
    profiles.py    entity behaviour baselines
    features.py    44 features in 3 families
    detectors/     rules, behaviour, temporal, novelty (ECOD)
    fusion.py      calibrated ensemble
    engine.py      orchestration
    eval/          corpus loader, replay, harness, degradation
  detections/    Detection object, correlator, service
  main.py        FastAPI app
frontend/src/
  views/DetectionsView.tsx   the product home screen
scripts/         fetch_corpus, train_and_evaluate, experiments
tests/           164 tests
docs/            plan, evaluation results, architecture
models/          trained fusion model
```

---

## Troubleshooting

**Port 8000 already in use** — run on another port and tell the frontend:

```bash
python -m uvicorn backend.main:app --port 8080
```

**`docker compose` not recognised** — older Docker uses a hyphen:

```bash
docker-compose up --build
```

**Frontend shows no data** — the backend isn't running, or is on a different
port. Check http://localhost:8000/api/health returns JSON.

**Badge says HEURISTIC instead of TRAINED MODEL** — `models/ulpf_fusion.pkl` is
missing. It ships in the repo; if you deleted it, retrain or restore it. The app
still works, just less accurately.
