"""
Measure the events-to-detections reduction, and per-class recall after grouping.

    python scripts/measure_detections.py [--per-day 60000]

Two questions:

1. **How many alerts does an analyst actually get?** Scored events are not
   alerts. This replays traffic through the full stack, correlates, and reports
   the ratio.

2. **Did grouping hide anything?** Per-class recall is recomputed *after*
   correlation - an attack class counts as detected only if some detection
   covering it exists. Measuring recall before grouping would let a correlator
   that swallowed a whole attack family still look good.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.detections import Correlator  # noqa: E402
from backend.ml.engine import DetectionEngine  # noqa: E402
from backend.ml.eval.harness import normalize_line, stratified_sample  # noqa: E402
from backend.ml.eval.replay import replay  # noqa: E402
from backend.ml.fusion import FusionModel  # noqa: E402

MODEL_PATH = os.path.join("models", "ulpf_fusion.pkl")
REPORT_PATH = os.path.join("docs", "detection_metrics.json")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-day", type=int, default=60_000)
    args = parser.parse_args()

    print("=" * 78)
    print("Detection volume and post-correlation recall")
    print("=" * 78)

    fusion = None
    if os.path.exists(MODEL_PATH):
        fusion = FusionModel.load(MODEL_PATH)
        print(f"\nLoaded trained model (threshold {fusion.threshold:.4f})")
    else:
        print("\nNo trained model found - running in heuristic mode. "
              "Numbers will be worse and are labelled as such.")

    print("\n[1/3] Sampling corpus")
    flows = stratified_sample(per_day=args.per_day, verbose=False)
    print(f"    {len(flows):,} flows")

    engine = DetectionEngine(fusion=fusion)
    correlator = Correlator()

    print("\n[2/3] Replaying and correlating")
    label_events: Counter = Counter()
    label_detected: Counter = Counter()
    detections_by_label: Dict[str, set] = defaultdict(set)
    warm_at = min(20_000, len(flows) // 4)
    seen = 0

    for event in replay(iter(flows)):
        try:
            norm = normalize_line(event.raw_log)
        except Exception:
            continue
        verdict = engine.analyse(norm)
        epoch = event.flow.timestamp.timestamp()
        detection = correlator.observe(norm, verdict, epoch=epoch)

        label_events[event.label] += 1
        if detection is not None:
            label_detected[event.label] += 1
            detections_by_label[event.label].add(detection.detection_id)

        seen += 1
        if seen == warm_at and not engine.novelty.fitted:
            engine.fit_novelty()
            print(f"    novelty fitted at {seen:,} events")
        if seen % 100_000 == 0:
            print(f"    {seen:,} events, {len(correlator.detections()):,} detections")

    print("\n[3/3] Result")
    summary = correlator.summary()
    print(f"\n    events seen              {summary['events_seen']:>10,}")
    print(f"    events flagged anomalous {summary['events_anomalous']:>10,}")
    print(f"    detections produced      {summary['detections_total']:>10,}")
    print(f"    events per detection     {summary['events_per_detection']:>10,}")
    print(f"    alert volume reduction   {summary['alert_volume_reduction_pct']:>9}%")
    print(f"    entities implicated      {summary['entities_implicated']:>10,}")
    print(f"    degraded-evidence detections {summary['degraded_evidence_detections']:>6,}")

    print("\n    Post-correlation coverage by class")
    per_class: Dict[str, Any] = {}
    for label, total in label_events.most_common():
        if label == "BENIGN":
            continue
        covered = label_detected.get(label, 0)
        entry = {
            "events": total,
            "events_in_a_detection": covered,
            "distinct_detections": len(detections_by_label.get(label, ())),
        }
        if total < 100:
            entry["coverage"] = None
            entry["note"] = f"insufficient data (n={total})"
            shown = "insufficient data"
        else:
            entry["coverage"] = round(covered / total, 4)
            shown = f"{covered / total:.1%}"
        per_class[label] = entry
        print(f"      {label:<30} n={total:<8,} covered {shown:<18} "
              f"({entry['distinct_detections']} detections)")

    benign_total = label_events.get("BENIGN", 0)
    benign_flagged = label_detected.get("BENIGN", 0)
    benign_detections = len(detections_by_label.get("BENIGN", ()))
    print(f"\n      {'BENIGN (false positives)':<30} n={benign_total:<8,} "
          f"flagged {benign_flagged:,} ({benign_detections} detections)")

    report = {
        "mode": "trained" if fusion and fusion.trained else "heuristic",
        "correlation": summary,
        "per_class_post_correlation": per_class,
        "benign": {
            "events": benign_total,
            "events_flagged": benign_flagged,
            "detections": benign_detections,
            "fp_detections_per_10k_benign": round(
                benign_detections / benign_total * 10_000, 2) if benign_total else 0.0,
        },
    }
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=str)
    print(f"\n    wrote {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
