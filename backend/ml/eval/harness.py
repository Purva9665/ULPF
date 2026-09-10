"""
Evaluation harness - turns replayed log lines into labelled feature matrices.

The parse path here is the real one: `auto_detect_and_parse` on the shipped
registry, then the shipped `NormalizationEngine`. What it skips is storage and
export, which write to SQLite and produce no features. Skipping them is a
throughput decision, not a shortcut past the product: every parser, every
mapping rule, every taxonomy classification and every provenance record is
exercised exactly as in production.

Ordering
--------
Events are processed in **timestamp order within each capture day**, because
entity profiles and the temporal detector are stateful. Feeding them shuffled
traffic would build baselines out of a future that had not happened yet, which
inflates every behavioural feature and is the subtle version of the leakage the
evaluation protocol exists to prevent.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

from backend.core.registry import default_registry
from backend.ingestion.engine import IngestionEngine
from backend.ml.detectors import Signal
from backend.ml.engine import DetectionEngine
from backend.ml.eval.corpus import FlowRecord, iter_flows
from backend.ml.eval.replay import ReplayEvent, replay
from backend.normalizer.engine import NormalizationEngine

_normalizer = NormalizationEngine()
_ingestor = IngestionEngine()


@dataclass
class HarnessResult:
    """Feature matrix plus everything needed to evaluate and explain it."""

    X: np.ndarray                                  # fusion inputs
    y: np.ndarray                                  # 1 = attack
    labels: List[str] = field(default_factory=list)
    days: List[str] = field(default_factory=list)
    vendors: List[str] = field(default_factory=list)
    input_names: List[str] = field(default_factory=list)
    detector_scores: Dict[str, List[float]] = field(default_factory=dict)
    parse_failures: int = 0
    elapsed_s: float = 0.0

    def __len__(self) -> int:
        return len(self.y)

    def summary(self) -> Dict[str, Any]:
        from collections import Counter
        return {
            "events": len(self.y),
            "attacks": int(self.y.sum()),
            "attack_ratio": round(float(self.y.mean()), 4) if len(self.y) else 0.0,
            "n_inputs": self.X.shape[1] if len(self.X) else 0,
            "parse_failures": self.parse_failures,
            "labels": dict(Counter(self.labels).most_common()),
            "days": dict(Counter(self.days)),
            "vendors": dict(Counter(self.vendors)),
            "elapsed_s": round(self.elapsed_s, 1),
            "events_per_second": round(len(self.y) / self.elapsed_s, 1)
            if self.elapsed_s > 0 else 0.0,
        }


def normalize_line(raw_log: str):
    """Raw log line -> normalized event, through the real ingest + parse path.

    Uses the shipped IngestionEngine rather than constructing a RawPayload by
    hand, so the SHA-256 chain of custody is computed exactly as it is in
    production and the harness cannot drift from the real ingest behaviour.
    """
    raw_event = _ingestor.ingest(raw_text=raw_log)
    parsed, _parser, _confidence = default_registry.auto_detect_and_parse(raw_event)
    return _normalizer.normalize(parsed)


def sorted_flows(
    days: Optional[Sequence[str]] = None,
    limit: Optional[int] = None,
    per_day_limit: Optional[int] = None,
) -> List[FlowRecord]:
    """Load flows and order them chronologically within each day.

    The corpus files are not globally sorted, and the temporal detector's
    windows are meaningless over out-of-order input.
    """
    flows = list(iter_flows(days=days, limit=limit))
    flows.sort(key=lambda f: (f.day, f.timestamp))
    if per_day_limit:
        kept: List[FlowRecord] = []
        seen: Dict[str, int] = {}
        for flow in flows:
            count = seen.get(flow.day, 0)
            if count < per_day_limit:
                kept.append(flow)
                seen[flow.day] = count + 1
        flows = kept
    return flows


def build(
    flows: Iterable[FlowRecord],
    *,
    engine: Optional[DetectionEngine] = None,
    use_confidence_features: bool = True,
    warm_novelty_after: Optional[int] = 20_000,
    progress_every: int = 100_000,
    verbose: bool = True,
    degrader: Optional[Any] = None,
) -> Tuple[HarnessResult, DetectionEngine]:
    """Replay flows through the real pipeline and assemble the fusion matrix.

    `warm_novelty_after` fits the unsupervised layer once that many events have
    been observed, then continues. This mirrors deployment: the novelty model
    is cold at first and warms on real traffic, and the resulting features
    honestly reflect that a live system's early events are scored by a model
    that had not yet learned the network.
    """
    eng = engine or DetectionEngine(use_confidence_features=use_confidence_features)
    y: List[int] = []
    labels: List[str] = []
    days: List[str] = []
    vendors: List[str] = []
    det_scores: Dict[str, List[float]] = {d: [] for d in eng.fusion.detector_order}
    failures = 0
    warmed = False
    t0 = time.perf_counter()

    # Phase 1 - sequential. Feature extraction and the rules/behaviour/temporal
    # detectors are order-dependent (they read and update entity profiles and
    # sliding windows), so they must run one event at a time, in order.
    #
    # Rows are written straight into a preallocated float32 matrix rather than
    # accumulated as Python lists: at corpus scale a list-of-lists of Python
    # floats costs several gigabytes in object overhead alone, while the same
    # data as float32 is a few hundred megabytes.
    flows = list(flows)
    n_features = len(eng.features.feature_names)
    n_inputs = len(eng.fusion.input_names)
    X = np.zeros((len(flows), n_inputs), dtype=np.float32)
    written = 0

    for i, event in enumerate(replay(iter(flows))):
        try:
            raw_log = degrader.apply(event.raw_log) if degrader else event.raw_log
            norm = normalize_line(raw_log)
        except Exception:
            failures += 1
            continue

        vector, named = eng.features.extract(norm)
        context = {"epoch": event.flow.timestamp.timestamp()}
        signals: Dict[str, Signal] = {
            "rules": eng.rules.analyse(named, norm, context),
            "behaviour": eng.behaviour.analyse(named, norm, context),
            "temporal": eng.temporal.analyse(named, norm, context),
        }
        # Novelty is filled in during phase 2; its slots stay zero for now.
        signals["novelty"] = Signal(detector="novelty", score=0.0, confidence=0.0)
        X[written, :] = eng.fusion.assemble(named, signals)
        written += 1

        y.append(1 if event.is_attack else 0)
        labels.append(event.label)
        days.append(event.day)
        vendors.append(event.vendor)
        for name in ("rules", "behaviour", "temporal"):
            det_scores[name].append(signals[name].score)

        if verbose and progress_every and (i + 1) % progress_every == 0:
            rate = (i + 1) / (time.perf_counter() - t0)
            print(f"    {i + 1:,} events  ({rate:,.0f}/s)")

    X = X[:written]

    # Phase 2 - batched. The novelty layer is stateless once fitted, so scoring
    # the whole matrix in one call is numerically identical to scoring event by
    # event (asserted by test_novelty_batch_matches_per_event) while avoiding
    # scikit-learn's per-call overhead, which dominates single-row inference.
    novelty_idx = eng.fusion.input_names.index("det:novelty:score")
    conf_idx = eng.fusion.input_names.index("det:novelty:confidence")
    if written:
        warm = min(warm_novelty_after or written, written)
        eng.fit_novelty(X[:warm, :n_features])
        if verbose and eng.novelty.fitted:
            print(f"    novelty model fitted on {warm:,} events")
        if eng.novelty.fitted:
            scores = eng.novelty.score_batch(X[:, :n_features])
            X[:, novelty_idx] = scores
            X[:, conf_idx] = 0.70
            det_scores["novelty"] = [float(v) for v in scores]
        else:
            det_scores["novelty"] = [0.0] * written

    elapsed = time.perf_counter() - t0
    result = HarnessResult(
        X=X,
        y=np.asarray(y, dtype=int),
        labels=labels, days=days, vendors=vendors,
        input_names=eng.fusion.input_names,
        detector_scores=det_scores,
        parse_failures=failures,
        elapsed_s=elapsed,
    )
    return result, eng


def chronological_split(
    result: HarnessResult, train_fraction: float = 0.7
) -> Tuple[np.ndarray, np.ndarray]:
    """Protocol A: within each day, the earliest `train_fraction` trains.

    Returns boolean masks. Splitting per day rather than globally keeps every
    attack family represented on both sides - each family appears on exactly
    one capture day, so a global chronological cut would put whole classes
    entirely in one half.
    """
    train = np.zeros(len(result), dtype=bool)
    by_day: Dict[str, List[int]] = {}
    for idx, day in enumerate(result.days):
        by_day.setdefault(day, []).append(idx)
    for indices in by_day.values():
        cut = int(len(indices) * train_fraction)
        train[np.array(indices[:cut], dtype=int)] = True
    return train, ~train


def cross_day_split(
    result: HarnessResult,
    train_days: Sequence[str] = ("Monday", "Tuesday", "Wednesday"),
) -> Tuple[np.ndarray, np.ndarray]:
    """Protocol B: train on early days, test on later ones (zero-shot classes)."""
    train = np.array([d in set(train_days) for d in result.days], dtype=bool)
    return train, ~train


def stratified_sample(
    per_day: int = 200_000,
    days: Optional[Sequence[str]] = None,
    verbose: bool = True,
) -> List[FlowRecord]:
    """Sample each capture day evenly across its whole timespan.

    Taking the first N flows of a day would bias the sample toward morning
    traffic and could miss an attack entirely - the Friday PortScan and DDoS
    both run in the afternoon. Systematic sampling (every k-th flow after
    sorting by time) spans the full day and preserves the natural attack base
    rate, which matters because the fusion layer's calibration is only
    meaningful if the class balance it saw resembles the one it will meet.

    Memory is bounded to one day at a time rather than the whole corpus.
    """
    wanted = list(days) if days else ["Monday", "Tuesday", "Wednesday",
                                      "Thursday", "Friday"]
    out: List[FlowRecord] = []
    for day in wanted:
        day_flows = list(iter_flows(days=[day]))
        if not day_flows:
            continue
        day_flows.sort(key=lambda f: f.timestamp)
        if len(day_flows) > per_day:
            stride = len(day_flows) / per_day
            sampled = [day_flows[int(i * stride)] for i in range(per_day)]
        else:
            sampled = day_flows
        attacks = sum(1 for f in sampled if f.is_attack)
        if verbose:
            print(f"    {day:<10} {len(day_flows):>9,} -> {len(sampled):>8,} "
                  f"sampled  ({attacks:,} attacks, {attacks/max(len(sampled),1):.1%})")
        out.extend(sampled)
        del day_flows
    return out
