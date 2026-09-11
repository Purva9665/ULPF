"""
USP-1, decided at matched recall.

Why this script exists
----------------------
Two existing reports disagree about whether parse-confidence features help:

* `docs/model_evaluation.json` -> "delta_fp_per_10k": 62.7  (a large improvement)
* `docs/usp1_experiment.json`  -> "verdict": "not supported"

Both compared false-positive counts between a model WITH the confidence
features and one WITHOUT. But each condition picked its own threshold by
maximising F1 on its own training split, so the two models were measured at
*different operating points* - 0.8294 against 0.8698 in the first report. A
false-positive count read at two different points on two different
precision-recall curves does not compare the models; it compares where
F1-maximisation happened to land each one.

There are only two valid ways to compare:

1. **Threshold-independent** - PR-AUC over the whole curve.
2. **Matched recall** - hold recall equal, then compare false positives.
   This is the one an operator cares about: "if I want to catch the same
   share of attacks, how much more noise do I have to wade through?"

This script reports both, for clean and for degraded input. A detection layer
that knows which fields were guessed should help most exactly when fields ARE
being guessed, so the degraded condition is the one that matters.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ml.eval.degrade import Degrader, DegradationProfile  # noqa: E402
from backend.ml.eval.harness import build, chronological_split, stratified_sample  # noqa: E402
from backend.ml.fusion import FusionModel  # noqa: E402

REPORT_PATH = os.path.join("docs", "usp1_matched_recall.json")

#: Recall levels to compare at. Spanning a range guards against a conclusion
#: that only holds at one convenient point on the curve.
TARGET_RECALLS = (0.90, 0.95, 0.98, 0.99)


def fp_at_recall(y_true: np.ndarray, scores: np.ndarray,
                 target_recall: float) -> Optional[Dict[str, Any]]:
    """False positives per 10k benign at the loosest threshold still reaching
    `target_recall`. Returns None if the model cannot reach that recall at all.
    """
    pos = y_true == 1
    neg = ~pos
    n_pos, n_neg = int(pos.sum()), int(neg.sum())
    if n_pos == 0 or n_neg == 0:
        return None

    # The threshold that achieves exactly this recall is the (1-r) quantile of
    # the positive scores: take it directly rather than sweeping a grid.
    k = int(np.ceil(target_recall * n_pos))
    if k < 1 or k > n_pos:
        return None
    pos_sorted = np.sort(scores[pos])[::-1]
    threshold = float(pos_sorted[k - 1])

    tp = int((scores[pos] >= threshold).sum())
    fp = int((scores[neg] >= threshold).sum())
    return {
        "target_recall": target_recall,
        "threshold": round(threshold, 6),
        "achieved_recall": round(tp / n_pos, 4),
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
        "fp": fp,
        "fp_per_10k_benign": round(fp / n_neg * 10_000, 1),
    }


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
    test_scores = model.predict_proba(result.X[test_mask])
    y_test = result.y[test_mask]

    from sklearn.metrics import average_precision_score, roc_auc_score

    curve = [fp_at_recall(y_test, test_scores, r) for r in TARGET_RECALLS]
    curve = [c for c in curve if c is not None]

    out = {
        "condition": name,
        "confidence_features": use_confidence,
        "degraded": degrader is not None,
        "n_features": n_features,
        "events": len(result),
        "test_events": int(test_mask.sum()),
        "test_attacks": int(y_test.sum()),
        "parse_failures": result.parse_failures,
        "pr_auc": round(float(average_precision_score(y_test, test_scores)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, test_scores)), 4),
        "matched_recall": curve,
    }
    print(f"    PR-AUC {out['pr_auc']}   " + "   ".join(
        f"FP/10k@r{c['target_recall']}={c['fp_per_10k_benign']}" for c in curve))
    return out


def compare(with_c: Dict[str, Any], without_c: Dict[str, Any]) -> Dict[str, Any]:
    """Positive delta means the confidence features HELPED (fewer FPs)."""
    by_recall = []
    wo = {c["target_recall"]: c for c in without_c["matched_recall"]}
    for c in with_c["matched_recall"]:
        r = c["target_recall"]
        if r not in wo:
            continue
        delta = wo[r]["fp_per_10k_benign"] - c["fp_per_10k_benign"]
        by_recall.append({
            "target_recall": r,
            "fp_per_10k_with": c["fp_per_10k_benign"],
            "fp_per_10k_without": wo[r]["fp_per_10k_benign"],
            "delta_fp_per_10k": round(delta, 1),
            "relative_change_pct": round(
                -100.0 * delta / wo[r]["fp_per_10k_benign"], 1
            ) if wo[r]["fp_per_10k_benign"] else 0.0,
        })
    deltas = [b["delta_fp_per_10k"] for b in by_recall]
    return {
        "delta_pr_auc": round(with_c["pr_auc"] - without_c["pr_auc"], 4),
        "by_recall": by_recall,
        "mean_delta_fp_per_10k": round(float(np.mean(deltas)), 1) if deltas else 0.0,
        "helps_at_every_recall": all(d > 0 for d in deltas) if deltas else False,
    }


def verdict(clean: Dict[str, Any], degraded: Dict[str, Any]) -> Dict[str, str]:
    """State the conclusion in the terms the claim was made in."""
    helped = clean["helps_at_every_recall"] or degraded["helps_at_every_recall"]
    pr_gain = max(clean["delta_pr_auc"], degraded["delta_pr_auc"])
    if helped and pr_gain >= 0:
        text = ("SUPPORTED. Confidence features reduce false positives at "
                "matched recall without costing discrimination.")
        short = "supported"
    elif pr_gain < -0.005:
        text = ("NOT SUPPORTED, and harmful. PR-AUC is materially lower with "
                "the confidence features, so the loss is in the model's "
                "ranking, not in where the threshold sits.")
        short = "not_supported_harmful"
    else:
        text = ("NOT SUPPORTED. At matched recall the confidence features do "
                "not reduce false positives, and PR-AUC is unchanged - the "
                "apparent gain in earlier reports came from comparing two "
                "models at different thresholds.")
        short = "not_supported"
    return {"verdict": short, "statement": text}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-day", type=int, default=40_000)
    parser.add_argument("--rate", type=float, default=0.15)
    args = parser.parse_args()

    print("=" * 78)
    print("USP-1 at matched recall: do parse-confidence features reduce FPs?")
    print("=" * 78)

    print("\n[1/3] Sampling corpus")
    flows = stratified_sample(per_day=args.per_day, verbose=False)
    print(f"    {len(flows):,} flows")

    profile = DegradationProfile(rate=args.rate)

    print(f"\n[2/3] Clean input")
    clean_with = run_condition("clean / with confidence", flows,
                               use_confidence=True, degrader=None)
    clean_without = run_condition("clean / without confidence", flows,
                                  use_confidence=False, degrader=None)

    print(f"\n[3/3] Degraded input (rate {args.rate:.0%}) "
          f"- the case the USP is meant for")
    deg_with = run_condition("degraded / with confidence", flows,
                             use_confidence=True, degrader=Degrader(profile))
    deg_without = run_condition("degraded / without confidence", flows,
                                use_confidence=False, degrader=Degrader(profile))

    clean_cmp = compare(clean_with, clean_without)
    deg_cmp = compare(deg_with, deg_without)
    v = verdict(clean_cmp, deg_cmp)

    report = {
        "question": ("Does feeding per-field parse confidence to the detection "
                     "layer reduce false positives, compared at MATCHED RECALL?"),
        "why_matched_recall": (
            "Earlier reports compared FP counts at thresholds each model chose "
            "for itself by maximising F1, so they sat at different operating "
            "points. Matched recall and PR-AUC are the only valid comparisons."),
        "config": {"per_day": args.per_day, "degradation_rate": args.rate,
                   "target_recalls": list(TARGET_RECALLS)},
        "conditions": [clean_with, clean_without, deg_with, deg_without],
        "clean_comparison": clean_cmp,
        "degraded_comparison": deg_cmp,
        **v,
    }

    os.makedirs("docs", exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print("\n" + "=" * 78)
    print("RESULT")
    print("=" * 78)
    for label, cmp_ in (("CLEAN", clean_cmp), ("DEGRADED", deg_cmp)):
        print(f"\n{label}   delta PR-AUC {cmp_['delta_pr_auc']:+.4f}")
        print(f"  {'recall':>8} {'FP/10k with':>13} {'FP/10k without':>15} {'delta':>9}")
        for b in cmp_["by_recall"]:
            print(f"  {b['target_recall']:>8.2f} {b['fp_per_10k_with']:>13.1f} "
                  f"{b['fp_per_10k_without']:>15.1f} {b['delta_fp_per_10k']:>+9.1f}")
    print(f"\nVERDICT: {v['statement']}")
    print(f"\nWritten to {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
