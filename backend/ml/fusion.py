"""
Score fusion - turning several detector opinions into one calibrated probability.

Why not just take the maximum
-----------------------------
The previous engine combined its two axes with `max(rule_risk, anomaly_score)`.
That is a defensible fallback and a poor model. It cannot express agreement
(two detectors at 0.6 is stronger evidence than one at 0.6), it cannot express
disagreement (a confident benign classification cannot pull a score down), and
its output is not a probability - 0.7 does not mean "70% of events scoring this
are attacks", so no threshold chosen from it has a meaning an analyst can use.

What this does instead
----------------------
A gradient-boosted classifier over the full feature vector *plus* each
detector's score and confidence, wrapped in isotonic calibration. The detectors
stay independently interpretable - their signals and evidence are unchanged and
still reported - but the final number is a calibrated probability.

Calibration is not cosmetic. An analyst triaging a queue needs "73% of events
like this one are attacks" to allocate attention. An uncalibrated score cannot
support that sentence, and a score that cannot support it gets ignored, which
is how SIEM risk columns end up as decoration.

Day-one behaviour
-----------------
`FusionModel` works untrained. Before a model is fitted - or in a deployment
that declines to use shipped weights - it falls back to an explicit
confidence-weighted combination of detector scores. That is worse than the
trained model and is reported as such via `mode`, never disguised as one.
"""

from __future__ import annotations

import json
import os
import pickle
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

#: Detectors whose score and confidence become fusion inputs, in fixed order.
DETECTOR_ORDER: Tuple[str, ...] = ("rules", "behaviour", "temporal", "novelty")

#: Default operating threshold. Overridden by whatever the evaluation picks.
DEFAULT_THRESHOLD = 0.5


@dataclass
class FusionVerdict:
    """The fused result for one event."""

    probability: float
    is_anomalous: bool
    mode: str                                   # "trained" | "heuristic"
    threshold: float
    contributions: List[Tuple[str, float]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "probability": round(self.probability, 4),
            "is_anomalous": self.is_anomalous,
            "mode": self.mode,
            "threshold": self.threshold,
            "contributions": [(n, round(v, 4)) for n, v in self.contributions],
        }


class FusionModel:
    """Calibrated supervised fusion over detector signals and raw features."""

    def __init__(
        self,
        feature_names: Sequence[str],
        detector_order: Sequence[str] = DETECTOR_ORDER,
        threshold: float = DEFAULT_THRESHOLD,
    ):
        self.feature_names = list(feature_names)
        self.detector_order = list(detector_order)
        self.threshold = threshold
        self._model = None
        self._calibrated = None
        self._trained_on: Dict[str, Any] = {}

    # -- input assembly -----------------------------------------------------

    @property
    def input_names(self) -> List[str]:
        """Fusion input names: raw features, then per-detector score/confidence."""
        names = list(self.feature_names)
        for d in self.detector_order:
            names.append(f"det:{d}:score")
            names.append(f"det:{d}:confidence")
        return names

    def assemble(
        self,
        features: Dict[str, float],
        signals: Dict[str, Any],
    ) -> List[float]:
        """Build one fusion input row from features and detector signals."""
        row = [float(features.get(n, 0.0)) for n in self.feature_names]
        for d in self.detector_order:
            sig = signals.get(d)
            row.append(float(getattr(sig, "score", 0.0)) if sig else 0.0)
            row.append(float(getattr(sig, "confidence", 0.0)) if sig else 0.0)
        return row

    # -- training -----------------------------------------------------------

    @property
    def trained(self) -> bool:
        return self._calibrated is not None

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        *,
        calibration_fraction: float = 0.25,
        random_state: int = 42,
    ) -> "FusionModel":
        """Fit the classifier, then calibrate it on data it was not fitted on.

        Calibrating on the training data would produce optimistically sharp
        probabilities: the classifier already fits that data well, so its
        apparent reliability there overstates what it achieves on new events.
        A held-out calibration slice is what makes the output an honest
        probability rather than a confident-looking one.

        The split is chronological, not random - the calibration slice is the
        *latest* portion. Calibrating on a random sample would leak future
        traffic into the mapping, which is the same leakage the evaluation
        protocol exists to avoid.
        """
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.ensemble import HistGradientBoostingClassifier

        X = np.nan_to_num(np.asarray(X, dtype=float), nan=0.0,
                          posinf=0.0, neginf=0.0)
        y = np.asarray(y).astype(int)
        if len(np.unique(y)) < 2:
            raise ValueError("fusion training needs both classes present")

        cut = int(len(X) * (1.0 - calibration_fraction))
        X_fit, y_fit = X[:cut], y[:cut]
        X_cal, y_cal = X[cut:], y[cut:]
        if len(np.unique(y_fit)) < 2 or len(np.unique(y_cal)) < 2:
            # A chronological split can land all positives on one side. Fall
            # back to fitting on everything and calibrating with cross-
            # validation, and record that this happened.
            self._model = HistGradientBoostingClassifier(
                max_iter=300, learning_rate=0.1, max_leaf_nodes=31,
                l2_regularization=1.0, random_state=random_state,
            )
            self._calibrated = CalibratedClassifierCV(
                self._model, method="isotonic", cv=3,
            ).fit(X, y)
            self._trained_on = {"n": int(len(X)), "calibration": "cv3-fallback",
                                "positives": int(y.sum())}
            return self

        self._model = HistGradientBoostingClassifier(
            max_iter=300, learning_rate=0.1, max_leaf_nodes=31,
            l2_regularization=1.0, random_state=random_state,
        ).fit(X_fit, y_fit)
        self._calibrated = CalibratedClassifierCV(
            _freeze(self._model), method="isotonic",
        ).fit(X_cal, y_cal)
        self._trained_on = {
            "n_fit": int(len(X_fit)), "n_calibration": int(len(X_cal)),
            "calibration": "isotonic-holdout",
            "positives": int(y.sum()),
        }
        return self

    # -- inference ----------------------------------------------------------

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self.trained:
            raise RuntimeError("FusionModel is not trained")
        X = np.nan_to_num(np.asarray(X, dtype=float), nan=0.0,
                          posinf=0.0, neginf=0.0)
        return self._calibrated.predict_proba(X)[:, 1]

    def fuse(
        self,
        features: Dict[str, float],
        signals: Dict[str, Any],
    ) -> FusionVerdict:
        row = self.assemble(features, signals)
        if self.trained:
            probability = float(self.predict_proba(np.array([row]))[0])
            mode = "trained"
        else:
            probability = _heuristic_fuse(signals, self.detector_order)
            mode = "heuristic"
        return FusionVerdict(
            probability=probability,
            is_anomalous=probability >= self.threshold,
            mode=mode,
            threshold=self.threshold,
            contributions=_detector_contributions(signals, self.detector_order),
        )

    # -- persistence --------------------------------------------------------

    def save(self, path: str) -> None:
        """Persist the fitted model plus everything needed to interpret it.

        The training environment is recorded because scikit-learn pickles are
        version-sensitive: this model is calibrated with `FrozenEstimator`,
        which did not exist before scikit-learn 1.6, so loading it on an older
        install fails. Recording the version turns that from a mystery into a
        message that names the actual problem.
        """
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as handle:
            pickle.dump({
                "feature_names": self.feature_names,
                "detector_order": self.detector_order,
                "threshold": self.threshold,
                "calibrated": self._calibrated,
                "trained_on": self._trained_on,
                "environment": _training_environment(),
            }, handle, protocol=pickle.HIGHEST_PROTOCOL)
        # A sidecar the user can read without unpickling, because a binary
        # blob nobody can inspect is a poor thing to ship into a secure network.
        with open(path + ".json", "w", encoding="utf-8") as handle:
            json.dump({
                "feature_names": self.feature_names,
                "detector_order": self.detector_order,
                "threshold": self.threshold,
                "trained_on": self._trained_on,
                "n_inputs": len(self.input_names),
                "environment": _training_environment(),
            }, handle, indent=2)

    @classmethod
    def load(cls, path: str) -> "FusionModel":
        with open(path, "rb") as handle:
            blob = pickle.load(handle)
        model = cls(
            feature_names=blob["feature_names"],
            detector_order=blob["detector_order"],
            threshold=blob.get("threshold", DEFAULT_THRESHOLD),
        )
        model._calibrated = blob["calibrated"]
        model._trained_on = blob.get("trained_on", {})
        model.environment = blob.get("environment", {})
        return model

    def describe(self) -> Dict[str, Any]:
        return {
            "trained": self.trained,
            "environment": getattr(self, "environment", {}),
            "n_features": len(self.feature_names),
            "n_inputs": len(self.input_names),
            "detectors": self.detector_order,
            "threshold": self.threshold,
            "trained_on": self._trained_on,
        }


def _freeze(estimator):
    """Wrap an already-fitted estimator so calibration will not refit it.

    scikit-learn 1.6 replaced `CalibratedClassifierCV(cv="prefit")` with an
    explicit `FrozenEstimator`, and 1.9 removed the old spelling entirely.
    Supporting both keeps this working across the versions a deployment might
    actually have, which matters more than usual for an offline bundle where
    upgrading scikit-learn is not a quick `pip install`.
    """
    try:
        from sklearn.frozen import FrozenEstimator
        return FrozenEstimator(estimator)
    except ImportError:          # scikit-learn < 1.6
        return estimator


def _training_environment() -> Dict[str, Any]:
    """Versions the model was produced with, for reproducibility and diagnosis."""
    import platform
    import sys
    try:
        import sklearn
        sklearn_version = sklearn.__version__
    except Exception:                                # pragma: no cover
        sklearn_version = "unknown"
    try:
        import numpy
        numpy_version = numpy.__version__
    except Exception:                                # pragma: no cover
        numpy_version = "unknown"
    return {
        "sklearn": sklearn_version,
        "numpy": numpy_version,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
    }


def check_environment(recorded: Dict[str, Any]) -> Optional[str]:
    """Compare the current environment against the one a model was trained in.

    Returns a human-readable warning, or None when nothing looks wrong. The
    scikit-learn version is the one that actually breaks things - a pickle
    written by a newer version can reference classes an older one does not
    have, and `FrozenEstimator` (used by this model's calibration) is exactly
    such a class, introduced in 1.6.
    """
    if not recorded:
        return None
    try:
        import sklearn
        current = sklearn.__version__
    except Exception:                                # pragma: no cover
        return None
    trained_with = recorded.get("sklearn")
    if not trained_with or trained_with == current:
        return None

    def major_minor(v: str):
        parts = v.split(".")
        try:
            return int(parts[0]), int(parts[1])
        except (IndexError, ValueError):
            return None

    a, b = major_minor(current), major_minor(trained_with)
    if a is None or b is None or a == b:
        return None
    return (f"model was trained with scikit-learn {trained_with}, this "
            f"environment has {current}; predictions may differ or the model "
            f"may fail to load. Pin scikit-learn to match, or retrain.")


def _heuristic_fuse(signals: Dict[str, Any], order: Sequence[str]) -> float:
    """Untrained fallback: confidence-weighted combination of detector scores.

    Explicitly worse than the trained model, and reported as `mode="heuristic"`
    so it is never mistaken for one. It exists because the product must do
    something sensible on its first event in a network with no shipped weights.
    """
    numerator = 0.0
    denominator = 0.0
    peak = 0.0
    for name in order:
        sig = signals.get(name)
        if sig is None:
            continue
        score = float(getattr(sig, "score", 0.0))
        conf = float(getattr(sig, "confidence", 0.0))
        numerator += score * conf
        denominator += conf
        peak = max(peak, score * conf)
    if denominator <= 0.0:
        return 0.0
    weighted_mean = numerator / denominator
    # Halfway between the weighted mean and the strongest confident signal: a
    # single high-confidence detector should not be averaged into silence by
    # three quiet ones.
    return float(min(1.0, 0.5 * weighted_mean + 0.5 * peak))


def _detector_contributions(
    signals: Dict[str, Any], order: Sequence[str]
) -> List[Tuple[str, float]]:
    out = []
    for name in order:
        sig = signals.get(name)
        if sig is None:
            continue
        out.append((name, float(getattr(sig, "score", 0.0))
                    * float(getattr(sig, "confidence", 0.0))))
    return sorted(out, key=lambda kv: kv[1], reverse=True)
