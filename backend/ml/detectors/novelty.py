"""
Unsupervised novelty detection - ECOD, with Isolation Forest as a second view.

ECOD
----
Li, Zhao, Hu, Botta, Ionescu & Chen, "ECOD: Unsupervised Outlier Detection
Using Empirical Cumulative Distribution Functions", IEEE TKDE 35(12), 2022.
DOI: 10.1109/TKDE.2022.3159580

Chosen over the more common Isolation Forest as the *primary* estimator for
three reasons that matter here specifically:

1. **Parameter-free.** No contamination rate, no tree count, no subsample size.
   Nothing to tune means nothing arbitrary to defend, and no risk that a
   number chosen on 2017 data quietly mis-serves a different network.
2. **Per-dimension attribution is native.** The score *is* a sum of
   per-feature tail probabilities, so "which feature made this anomalous" comes
   out of the algorithm rather than out of a post-hoc explainer that
   approximates it.
3. **Deterministic.** The same input yields the same score, always. Isolation
   Forest depends on a random seed, which is awkward when a detection has to be
   reproducible for an auditor.

Implemented directly rather than pulled from PyOD. ECOD is about forty lines of
NumPy, and adding a dependency to an offline air-gapped bundle for forty lines
is a poor trade. Implementing it also means the per-dimension contributions are
available in the shape this codebase needs.

How it works
------------
For each feature independently, estimate the empirical CDF from the training
sample. For a new point, the left-tail probability is P(X <= x) and the
right-tail is P(X >= x). A value far into either tail is improbable, and
-log(probability) turns that into an additive score. Summing across dimensions
assumes feature independence - which is wrong, and which the paper is explicit
about; it is what buys the linear time complexity. The aggregate is the maximum
of the left-tail, right-tail, and skewness-directed sums.

The independence assumption is why ECOD is a *component* here and not the whole
model. Correlated structure is what the gradient-boosted fusion layer is for.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from backend.ml.detectors.base import Evidence, Signal

#: Observations required before an unsupervised model is fitted at all. Below
#: this the sample cannot describe a distribution and any score derived from it
#: would be noise presented as a measurement.
MIN_FIT_SAMPLES = 500


class ECOD:
    """Empirical-CDF outlier detection. Parameter-free and deterministic."""

    def __init__(self) -> None:
        self._sorted: Optional[np.ndarray] = None   # (n, d), each column sorted
        self._skew: Optional[np.ndarray] = None     # (d,)
        self._n = 0

    @property
    def fitted(self) -> bool:
        return self._sorted is not None

    def fit(self, X: np.ndarray) -> "ECOD":
        data = np.asarray(X, dtype=float)
        if data.ndim != 2 or data.shape[0] < 2:
            raise ValueError("ECOD.fit needs a 2-D sample with at least 2 rows")
        data = np.nan_to_num(data, nan=0.0, posinf=0.0, neginf=0.0)
        self._n = data.shape[0]
        self._sorted = np.sort(data, axis=0)
        self._skew = _column_skew(data)
        return self

    def tail_probabilities(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Left and right tail probabilities, per point per dimension."""
        if self._sorted is None:
            raise RuntimeError("ECOD is not fitted")
        data = np.nan_to_num(np.asarray(X, dtype=float),
                             nan=0.0, posinf=0.0, neginf=0.0)
        n = self._n
        left = np.empty(data.shape, dtype=float)
        right = np.empty(data.shape, dtype=float)
        for j in range(data.shape[1]):
            column = self._sorted[:, j]
            # P(X <= x) and P(X >= x) from the sorted training column.
            le = np.searchsorted(column, data[:, j], side="right")
            lt = np.searchsorted(column, data[:, j], side="left")
            left[:, j] = le / n
            right[:, j] = (n - lt) / n
        # Floor at 1/n: an event rarer than the sample can resolve is capped at
        # the sample's resolution rather than assigned infinite surprise.
        floor = 1.0 / n
        return np.maximum(left, floor), np.maximum(right, floor)

    def decision_scores(self, X: np.ndarray) -> np.ndarray:
        """Raw outlier scores. Higher is more anomalous."""
        per_dim = self.per_dimension_scores(X)
        return per_dim.sum(axis=1)

    def per_dimension_scores(self, X: np.ndarray) -> np.ndarray:
        """Per-feature contribution to the outlier score, shape (n, d).

        This is the attribution that comes free with the method: the score is
        literally the sum of these, so a contribution is exact rather than an
        approximation of the model's reasoning.
        """
        left, right = self.tail_probabilities(X)
        o_left = -np.log(left)
        o_right = -np.log(right)
        # Skewness decides which tail is the interesting one per feature.
        skew = self._skew if self._skew is not None else np.zeros(left.shape[1])
        o_auto = np.where(skew < 0.0, o_left, o_right)
        # Choose, per point, whichever aggregate is largest - then report the
        # per-dimension terms of that same aggregate so attribution and score
        # always agree.
        sums = np.stack([o_left.sum(axis=1), o_right.sum(axis=1),
                         o_auto.sum(axis=1)], axis=1)
        choice = np.argmax(sums, axis=1)
        stacked = np.stack([o_left, o_right, o_auto], axis=0)
        return stacked[choice, np.arange(len(choice)), :]


def _column_skew(X: np.ndarray) -> np.ndarray:
    """Fisher-Pearson skewness per column, without a SciPy dependency."""
    mean = X.mean(axis=0)
    centred = X - mean
    m2 = (centred ** 2).mean(axis=0)
    m3 = (centred ** 3).mean(axis=0)
    sigma = np.sqrt(np.maximum(m2, 1e-12))
    return m3 / np.maximum(sigma ** 3, 1e-12)


class NoveltyDetector:
    """ECOD primary, Isolation Forest secondary, both fitted on observed traffic.

    Two estimators rather than one because they fail differently: ECOD assumes
    feature independence and sees only per-axis tails, while Isolation Forest
    partitions jointly and can catch a combination that is unremarkable on
    every individual axis. Reporting both, and taking the stronger, means one
    estimator's blind spot is not the system's blind spot.
    """

    name = "novelty"

    def __init__(self, feature_names: Optional[Sequence[str]] = None,
                 min_fit_samples: int = MIN_FIT_SAMPLES):
        self.feature_names: List[str] = list(feature_names or [])
        self.min_fit_samples = min_fit_samples
        self.ecod = ECOD()
        self._iforest = None
        self._ecod_lo = 0.0
        self._ecod_hi = 1.0
        self._if_lo = -0.5
        self._if_hi = -0.4
        self._fitted = False

    @property
    def fitted(self) -> bool:
        return self._fitted

    def fit(self, X: np.ndarray) -> "NoveltyDetector":
        """Fit both estimators and calibrate their score ranges.

        Calibration uses the 1st and 99th percentiles of the *training* scores,
        so a reported 0-1 score means "relative to this network's own traffic"
        rather than relative to constants chosen during development.
        """
        data = np.asarray(X, dtype=float)
        if data.shape[0] < self.min_fit_samples:
            return self
        data = np.nan_to_num(data, nan=0.0, posinf=0.0, neginf=0.0)

        self.ecod.fit(data)
        raw = self.ecod.decision_scores(data)
        self._ecod_lo = float(np.percentile(raw, 1))
        self._ecod_hi = float(np.percentile(raw, 99))

        try:
            from sklearn.ensemble import IsolationForest
            self._iforest = IsolationForest(
                n_estimators=100, contamination="auto",
                random_state=42, n_jobs=1,
            ).fit(data)
            if_raw = self._iforest.score_samples(data)
            self._if_lo = float(np.percentile(if_raw, 1))
            self._if_hi = float(np.percentile(if_raw, 99))
        except Exception:
            self._iforest = None

        self._fitted = True
        return self

    def score_batch(self, X: np.ndarray) -> np.ndarray:
        """Combined novelty score per row, in [0, 1]."""
        if not self._fitted:
            return np.zeros(len(X), dtype=float)
        data = np.nan_to_num(np.asarray(X, dtype=float),
                             nan=0.0, posinf=0.0, neginf=0.0)
        ecod_s = _rescale(self.ecod.decision_scores(data),
                          self._ecod_lo, self._ecod_hi)
        if self._iforest is None:
            return ecod_s
        # Isolation Forest: lower score_samples means more anomalous.
        if_s = _rescale(-self._iforest.score_samples(data),
                        -self._if_hi, -self._if_lo)
        return np.maximum(ecod_s, if_s)

    def analyse(
        self,
        features: Dict[str, float],
        norm: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Signal:
        if not self._fitted:
            return Signal(
                detector=self.name, score=0.0, confidence=0.15,
                evidence=[Evidence(
                    signal="model_cold_start",
                    observed=self.min_fit_samples,
                    argues=f"Fewer than {self.min_fit_samples} events observed; "
                           "the novelty model is not fitted and contributes nothing",
                    weight=0.0,
                )],
                state={"model_state": "cold_start"},
            )

        vector = np.array([[features.get(n, 0.0) for n in self.feature_names]],
                          dtype=float)
        score = float(self.score_batch(vector)[0])

        per_dim = self.ecod.per_dimension_scores(vector)[0]
        order = np.argsort(per_dim)[::-1][:5]
        evidence = []
        total = float(per_dim.sum()) or 1.0
        for idx in order:
            if per_dim[idx] <= 0.0:
                continue
            name = (self.feature_names[idx] if idx < len(self.feature_names)
                    else f"feature_{idx}")
            evidence.append(Evidence(
                signal=f"novelty:{name}",
                observed=round(float(features.get(name, 0.0)), 4),
                argues=f"'{name}' sits in the tail of what this deployment "
                       f"normally observes",
                weight=round(float(per_dim[idx]) / total, 4),
            ))

        return Signal(
            detector=self.name,
            score=score,
            confidence=0.70,
            evidence=evidence,
            state={"model_state": "fitted",
                   "estimators": "ecod+iforest" if self._iforest else "ecod"},
        )


def _rescale(raw: np.ndarray, lo: float, hi: float) -> np.ndarray:
    span = hi - lo
    if span <= 1e-12:
        return np.zeros_like(raw, dtype=float)
    return np.clip((raw - lo) / span, 0.0, 1.0)
