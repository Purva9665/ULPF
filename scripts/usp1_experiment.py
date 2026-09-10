"""
USP-1 experiment: does parse-confidence awareness reduce false positives?

    python scripts/usp1_experiment.py [--per-day 60000] [--rate 0.15]

The claim under test
--------------------
ULPF keeps per-field parse confidence and feeds it to the detection layer.
Every other pipeline discards it at the wire-format boundary. The claim is that
knowing which fields are unreliable lets the model avoid raising confident
alarms on badly-parsed events.

Four conditions, one corpus
---------------------------
    clean    + confidence features       baseline
    clean    - confidence features       does the mechanism cost anything?
    degraded + confidence features       the case the mechanism is for
    degraded - confidence features       what every other pipeline sees

The comparison that matters is the second pair. The first pair is the control:
if confidence features hurt on clean data, that is a cost the mechanism carries
and it belongs in the result.

What would falsify the claim
----------------------------
If degraded/with is not better than degraded/without on false positives, the
mechanism does not work and the report says so. That outcome was written here
before the experiment was run.

A known weakness, stated up front
---------------------------------
Downranking detections built on low-confidence fields creates an evasion path:
an attacker who can make their traffic log badly gains suppression. This is a
real limitation of the design, not a hypothetical. It is why the reliability
factor in the engine is floored rather than allowed to reach zero - a degraded
event is discounted, never silenced.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ml.eval.degrade import Degrader, DegradationProfile  # noqa: E402
from backend.ml.eval.harness import build, chronological_split, stratified_sample  # noqa: E402
from backend.ml.fusion import FusionModel  # noqa: E402
from scripts.train_and_evaluate import best_threshold, metrics_at  # noqa: E402

REPORT_PATH = os.path.join("docs", "usp1_experiment.json")


def run_condition(name: str, flows, *, use_confidence: bool,
                  degrader) -> Dict[str, Any]:
    print(f"\n  {name}")
    result, engine = build(
        flows,
        use_confidence_features=use_confidence,
        warm_novelty_after=min(20_000, len(flows) // 4),
        progress_every=0,
        verbose=False,
        degrader=degrader,
    )
    n_features = len(engine.features.feature_names)
    train_mask, test_mask = chronological_split(result, train_fraction=0.7)

    model = FusionModel(feature_names=result.input_names[:n_features])
    model.fit(result.X[train_mask], result.y[train_mask])
    train_scores = model.predict_proba(result.X[train_mask])
    test_scores = model.predict_proba(result.X[test_mask])
    threshold = best_threshold(result.y[train_mask], train_scores)
    m = metrics_at(result.y[test_mask], test_scores, threshold)

    print(f"    parse failures {result.parse_failures:,}   "
          f"PR-AUC {m['pr_auc']}   precision {m['precision']}   "
          f"recall {m['recall']}   FP/10k {m['fp_per_10k_benign']}")
    return {
        "condition": name,
        "confidence_features": use_confidence,
        "degraded": degrader is not None,
        "n_features": n_features,
        "parse_failures": result.parse_failures,
        "events": len(result),
        **m,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-day", type=int, default=60_000)
    parser.add_argument("--rate", type=float, default=0.15,
                        help="share of log lines degraded")
    args = parser.parse_args()

    print("=" * 78)
    print("USP-1: does parse-confidence awareness reduce false positives?")
    print("=" * 78)

    print("\n[1/3] Sampling corpus")
    flows = stratified_sample(per_day=args.per_day, verbose=False)
    print(f"    {len(flows):,} flows")

    profile = DegradationProfile(rate=args.rate)
    print(f"\n[2/3] Running four conditions (degradation rate {args.rate:.0%})")

    conditions = []
    conditions.append(run_condition(
        "clean / with confidence features", flows,
        use_confidence=True, degrader=None))
    conditions.append(run_condition(
        "clean / without confidence features", flows,
        use_confidence=False, degrader=None))

    deg_with = Degrader(profile)
    conditions.append(run_condition(
        "degraded / with confidence features", flows,
        use_confidence=True, degrader=deg_with))
    deg_without = Degrader(profile)
    conditions.append(run_condition(
        "degraded / without confidence features", flows,
        use_confidence=False, degrader=deg_without))

    print("\n[3/3] Result")
    clean_with, clean_without, deg_w, deg_wo = conditions

    clean_delta = clean_without["fp_per_10k_benign"] - clean_with["fp_per_10k_benign"]
    deg_delta = deg_wo["fp_per_10k_benign"] - deg_w["fp_per_10k_benign"]

    verdict = (
        "supported" if deg_delta > 0 and deg_delta > abs(clean_delta)
        else "not supported"
    )

    print(f"\n    clean    : with {clean_with['fp_per_10k_benign']} FP/10k, "
          f"without {clean_without['fp_per_10k_benign']} FP/10k  "
          f"(confidence features change: {clean_delta:+.1f})")
    print(f"    degraded : with {deg_w['fp_per_10k_benign']} FP/10k, "
          f"without {deg_wo['fp_per_10k_benign']} FP/10k  "
          f"(confidence features change: {deg_delta:+.1f})")
    print(f"\n    VERDICT: USP-1 claim is {verdict.upper()}")
    if verdict == "not supported":
        print("    Reporting this as a null result. The mechanism did not "
              "reduce false positives under test.")

    report = {
        "question": "Does feeding per-field parse confidence to the detection "
                    "layer reduce false positives?",
        "degradation_profile": profile.as_dict(),
        "degradation_applied": deg_with.stats(),
        "conditions": conditions,
        "clean_fp_delta_per_10k": round(clean_delta, 1),
        "degraded_fp_delta_per_10k": round(deg_delta, 1),
        "verdict": verdict,
        "known_limitation": (
            "Downranking low-confidence detections creates an evasion path: an "
            "attacker able to make their traffic log badly gains suppression. "
            "The engine floors the reliability factor so a degraded event is "
            "discounted rather than silenced."
        ),
    }
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=str)
    print(f"\n    wrote {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
