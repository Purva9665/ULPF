"""
Train the ULPF fusion model and evaluate it under both protocols.

    python scripts/train_and_evaluate.py [--per-day 120000] [--quick]

Everything about the protocol was fixed in docs/IMPLEMENTATION_PLAN.md before
any result was seen. This script implements that plan and writes what it finds,
including where the model does badly.

Protocol A - chronological within day. Per capture day the earliest 70% of
flows train and the latest 30% test. No shuffle leakage, every attack family
present on both sides. This is the headline number.

Protocol B - cross-day, zero-shot. Train Monday-Wednesday, test
Thursday-Friday, where every test attack family is one the supervised layer has
never seen. This measures whether the ensemble catches tomorrow's attack.

Metrics are PR-AUC rather than ROC-AUC: with a ~20% positive rate and some
classes at 0.001%, ROC-AUC flatters everything. False positives are reported
per 10,000 benign flows because that is the quantity a SOC actually feels.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ml.eval.harness import (  # noqa: E402
    build,
    chronological_split,
    cross_day_split,
    stratified_sample,
)
from backend.ml.fusion import FusionModel  # noqa: E402

MODEL_PATH = os.path.join("models", "ulpf_fusion.pkl")
REPORT_PATH = os.path.join("docs", "model_evaluation.json")

#: Classes below this count cannot support a per-class accuracy figure. They
#: are reported as insufficient data rather than as a percentage of eleven.
MIN_CLASS_SUPPORT = 100


# -- metrics ---------------------------------------------------------------


def metrics_at(y_true: np.ndarray, scores: np.ndarray,
               threshold: float) -> Dict[str, Any]:
    from sklearn.metrics import average_precision_score, roc_auc_score

    predicted = (scores >= threshold).astype(int)
    tp = int(((predicted == 1) & (y_true == 1)).sum())
    fp = int(((predicted == 1) & (y_true == 0)).sum())
    fn = int(((predicted == 0) & (y_true == 1)).sum())
    tn = int(((predicted == 0) & (y_true == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    benign = tn + fp
    return {
        "threshold": round(float(threshold), 4),
        "pr_auc": round(float(average_precision_score(y_true, scores)), 4)
        if len(np.unique(y_true)) > 1 else None,
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 4)
        if len(np.unique(y_true)) > 1 else None,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fp_per_10k_benign": round(fp / benign * 10_000, 1) if benign else 0.0,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def best_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    """Threshold maximising F1 **on the training split only**.

    Choosing it on test would be tuning on the data used to report, which is
    the most common way an evaluation quietly stops meaning anything.
    """
    from sklearn.metrics import precision_recall_curve

    if len(np.unique(y_true)) < 2:
        return 0.5
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    denom = precision + recall
    f1 = np.where(denom > 0, 2 * precision * recall / np.maximum(denom, 1e-12), 0.0)
    idx = int(np.argmax(f1[:-1])) if len(f1) > 1 else 0
    return float(thresholds[idx]) if len(thresholds) else 0.5


def per_class_recall(labels: Sequence[str], y_true: np.ndarray,
                     scores: np.ndarray, threshold: float) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    labels_arr = np.asarray(labels)
    for label in sorted(set(labels)):
        if label == "BENIGN":
            continue
        mask = labels_arr == label
        n = int(mask.sum())
        if n == 0:
            continue
        detected = int((scores[mask] >= threshold).sum())
        entry: Dict[str, Any] = {"n": n, "detected": detected}
        if n < MIN_CLASS_SUPPORT:
            entry["recall"] = None
            entry["note"] = f"insufficient data (n={n}); no rate reported"
        else:
            entry["recall"] = round(detected / n, 4)
        out[label] = entry
    return out


# -- evaluation ------------------------------------------------------------


def evaluate_split(
    name: str,
    result,
    train_mask: np.ndarray,
    test_mask: np.ndarray,
    n_features: int,
) -> Dict[str, Any]:
    X, y = result.X, result.y
    X_tr, y_tr = X[train_mask], y[train_mask]
    X_te, y_te = X[test_mask], y[test_mask]

    print(f"\n  {name}")
    print(f"    train {len(y_tr):,} ({int(y_tr.sum()):,} attacks)   "
          f"test {len(y_te):,} ({int(y_te.sum()):,} attacks)")

    if len(np.unique(y_tr)) < 2 or len(np.unique(y_te)) < 2:
        return {"error": "a split contains only one class"}

    model = FusionModel(feature_names=result.input_names[:n_features])
    model.fit(X_tr, y_tr)

    train_scores = model.predict_proba(X_tr)
    test_scores = model.predict_proba(X_te)
    threshold = best_threshold(y_tr, train_scores)

    test_labels = [l for l, m in zip(result.labels, test_mask) if m]
    report = {
        "train_size": int(len(y_tr)),
        "test_size": int(len(y_te)),
        "train_attacks": int(y_tr.sum()),
        "test_attacks": int(y_te.sum()),
        "threshold_chosen_on": "train split",
        "test": metrics_at(y_te, test_scores, threshold),
        "per_class_recall": per_class_recall(test_labels, y_te, test_scores, threshold),
    }
    t = report["test"]
    print(f"    PR-AUC {t['pr_auc']}   precision {t['precision']}   "
          f"recall {t['recall']}   F1 {t['f1']}")
    print(f"    false positives per 10k benign: {t['fp_per_10k_benign']}")
    return report


def ablation(result, n_features: int, train_mask: np.ndarray,
             test_mask: np.ndarray) -> List[Dict[str, Any]]:
    """Each detector alone, then the trained fusion, on the same split.

    The unsupervised rows need no training - their score is read straight from
    the detector column - so they are evaluated as-is. That is the honest
    comparison: it is what that detector would deliver on its own.
    """
    names = result.input_names
    y = result.y
    rows: List[Dict[str, Any]] = []

    for detector in ("rules", "behaviour", "temporal", "novelty"):
        column = names.index(f"det:{detector}:score")
        scores_tr = result.X[train_mask, column]
        scores_te = result.X[test_mask, column]
        threshold = best_threshold(y[train_mask], scores_tr)
        m = metrics_at(y[test_mask], scores_te, threshold)
        rows.append({"configuration": f"{detector} only", "trained": False, **m})

    model = FusionModel(feature_names=names[:n_features])
    model.fit(result.X[train_mask], y[train_mask])
    tr = model.predict_proba(result.X[train_mask])
    te = model.predict_proba(result.X[test_mask])
    threshold = best_threshold(y[train_mask], tr)
    rows.append({"configuration": "fused ensemble (trained)", "trained": True,
                 **metrics_at(y[test_mask], te, threshold)})
    return rows


# -- main ------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-day", type=int, default=120_000,
                        help="flows sampled per capture day")
    parser.add_argument("--quick", action="store_true",
                        help="small run for a smoke test")
    parser.add_argument("--full", action="store_true",
                        help="use every flow, no sampling")
    args = parser.parse_args()
    per_day = 8_000 if args.quick else args.per_day

    print("=" * 78)
    print("ULPF fusion model - training and evaluation")
    print("=" * 78)

    print("\n[1/5] Sampling corpus")
    flows = stratified_sample(per_day=per_day)
    print(f"    total sampled: {len(flows):,}")

    print("\n[2/5] Replaying through the real pipeline (confidence features ON)")
    full, engine = build(flows, use_confidence_features=True,
                         warm_novelty_after=min(20_000, len(flows) // 4),
                         progress_every=100_000)
    n_features_full = len(engine.features.feature_names)
    s = full.summary()
    print(f"    {s['events']:,} events, {s['attacks']:,} attacks "
          f"({s['attack_ratio']:.1%}), {s['parse_failures']} parse failures, "
          f"{s['events_per_second']:,.0f} EPS")

    print("\n[3/5] Replaying again (confidence features OFF - USP-1 ablation)")
    ablated, engine_ab = build(flows, use_confidence_features=False,
                               warm_novelty_after=min(20_000, len(flows) // 4),
                               progress_every=100_000, verbose=False)
    n_features_ab = len(engine_ab.features.feature_names)
    print(f"    {len(ablated):,} events, {n_features_ab} features "
          f"(vs {n_features_full} with confidence)")

    print("\n[4/5] Evaluating")
    report: Dict[str, Any] = {
        "corpus": {
            "name": "CIC-IDS2017 (GeneratedLabelledFlows)",
            "citation": "Sharafaldin, Lashkari & Ghorbani, ICISSP 2018",
            "sampled_per_day": per_day,
            **s,
        },
        "model": {
            "unsupervised": "ECOD (Li et al., TKDE 2022) + IsolationForest",
            "fusion": "HistGradientBoostingClassifier + isotonic calibration",
            "n_features": n_features_full,
            "n_fusion_inputs": full.X.shape[1],
        },
    }

    tr_a, te_a = chronological_split(full, train_fraction=0.7)
    report["protocol_a_chronological"] = evaluate_split(
        "Protocol A - chronological within day (headline)",
        full, tr_a, te_a, n_features_full)

    tr_b, te_b = cross_day_split(full)
    report["protocol_b_cross_day"] = evaluate_split(
        "Protocol B - cross-day, zero-shot attack families",
        full, tr_b, te_b, n_features_full)

    print("\n  Ablation (Protocol A split)")
    report["ablation"] = ablation(full, n_features_full, tr_a, te_a)
    for row in report["ablation"]:
        print(f"    {row['configuration']:<28} PR-AUC {row['pr_auc']}  "
              f"F1 {row['f1']}  FP/10k {row['fp_per_10k_benign']}")

    # USP-1: same protocol, same split, confidence features removed.
    tr_ab, te_ab = chronological_split(ablated, train_fraction=0.7)
    with_conf = report["protocol_a_chronological"]["test"]
    without = evaluate_split(
        "USP-1 ablation - confidence features removed",
        ablated, tr_ab, te_ab, n_features_ab)
    report["usp1_confidence_ablation"] = {
        "with_confidence_features": with_conf,
        "without_confidence_features": without.get("test"),
        "delta_fp_per_10k": round(
            (without.get("test", {}).get("fp_per_10k_benign", 0.0)
             - with_conf["fp_per_10k_benign"]), 1),
        "delta_pr_auc": round(
            (with_conf.get("pr_auc") or 0.0)
            - (without.get("test", {}).get("pr_auc") or 0.0), 4),
    }

    print("\n[5/5] Training final model on Protocol A train split and saving")
    final = FusionModel(feature_names=full.input_names[:n_features_full])
    final.fit(full.X[tr_a], full.y[tr_a])
    final.threshold = best_threshold(full.y[tr_a], final.predict_proba(full.X[tr_a]))
    final.save(MODEL_PATH)
    report["model"]["saved_to"] = MODEL_PATH
    report["model"]["threshold"] = round(final.threshold, 4)
    report["model"]["details"] = final.describe()
    print(f"    saved {MODEL_PATH} (threshold {final.threshold:.4f})")

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=str)
    print(f"    wrote {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
