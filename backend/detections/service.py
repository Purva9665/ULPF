"""
Detection service - the single object the API talks to.

Holds the detection engine, the correlator, and the loaded fusion model, and
turns a raw log line into a stored, correlated detection. Keeping this out of
`main.py` means the HTTP layer stays a thin adapter and the same service can be
driven by a replay script, a test, or a future syslog listener without change.

Model loading
-------------
A trained model is used when one is present on disk. When it is absent the
engine still runs, in `heuristic` mode, and every response says so. A product
that silently degrades from a trained model to a rule-of-thumb without telling
anyone is worse than one that has no model at all.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Dict, List, Optional

from backend.detections.correlator import Correlator
from backend.detections.models import Detection, TriageState
from backend.ml.engine import DetectionEngine
from backend.ml.fusion import FusionModel, check_environment

DEFAULT_MODEL_PATH = os.environ.get(
    "ULPF_MODEL_PATH", os.path.join("models", "ulpf_fusion.pkl")
)


class DetectionService:
    """Scores normalized events, correlates them, and serves the results."""

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH):
        self.model_path = model_path
        self.model_error: Optional[str] = None
        self.environment_warning: Optional[str] = None
        fusion = self._load_model(model_path)
        self.engine = DetectionEngine(fusion=fusion)
        self.correlator = Correlator()
        # The API is served by an async event loop but the engine is stateful
        # (profiles, sliding windows). A lock keeps concurrent requests from
        # interleaving updates into those structures.
        self._lock = threading.Lock()

    def _load_model(self, path: str) -> Optional[FusionModel]:
        if not os.path.exists(path):
            self.model_error = f"no trained model at {path}; running heuristic mode"
            return None
        try:
            model = FusionModel.load(path)
        except Exception as exc:
            # Loudly, with the most likely cause named. The commonest failure
            # is a scikit-learn older than 1.6, which cannot unpickle the
            # FrozenEstimator this model's calibration uses.
            self.model_error = (
                f"failed to load {path}: {exc}. If this mentions "
                f"'FrozenEstimator' or 'sklearn.frozen', the installed "
                f"scikit-learn is older than 1.6 - run "
                f"'pip install -r backend/requirements.txt' to get a "
                f"compatible version."
            )
            return None
        self.environment_warning = check_environment(getattr(model, "environment", {}))
        return model

    # -- ingestion ----------------------------------------------------------

    def analyse(self, norm: Any, epoch: float = 0.0) -> Dict[str, Any]:
        """Score one normalized event and fold it into a detection."""
        with self._lock:
            verdict = self.engine.analyse(norm)
            detection = self.correlator.observe(norm, verdict, epoch=epoch)
        return {
            "verdict": verdict.as_dict(),
            "detection_id": detection.detection_id if detection else None,
        }

    # -- queries ------------------------------------------------------------

    def detections(self, limit: int = 50, offset: int = 0,
                   state: Optional[str] = None,
                   severity: Optional[str] = None) -> Dict[str, Any]:
        items = self.correlator.detections()
        if state:
            items = [d for d in items if d.state.value == state]
        if severity:
            items = [d for d in items if d.severity.value == severity]
        window = items[offset:offset + limit]
        return {
            "total": len(items),
            "limit": limit,
            "offset": offset,
            "detections": [d.as_dict() for d in window],
        }

    def detection(self, detection_id: str) -> Optional[Dict[str, Any]]:
        for d in self.correlator.detections():
            if d.detection_id == detection_id:
                return {
                    **d.as_dict(),
                    "evidence": d.evidence,
                    "peer_ips": d.peer_ips[:50],
                    "ports_touched": sorted(d.ports_touched)[:100],
                    "events": [e.as_dict() for e in d.events],
                }
        return None

    def evidence_bundle(self, detection_id: str) -> Optional[Dict[str, Any]]:
        for d in self.correlator.detections():
            if d.detection_id == detection_id:
                return d.evidence_bundle()
        return None

    def set_state(self, detection_id: str, state: str,
                  note: str = "") -> Optional[Dict[str, Any]]:
        try:
            target = TriageState(state)
        except ValueError:
            return None
        for d in self.correlator.detections():
            if d.detection_id == detection_id:
                return d.set_state(target, note).as_dict()
        return None

    def entities(self, limit: int = 25) -> List[Dict[str, Any]]:
        return [r.as_dict() for r in self.correlator.entity_risks()[:limit]]

    def summary(self) -> Dict[str, Any]:
        stats = self.engine.stats()
        return {
            "mode": "trained" if (self.engine.fusion and self.engine.fusion.trained)
                    else "heuristic",
            "model_path": self.model_path,
            "model_error": self.model_error,
            "environment_warning": self.environment_warning,
            "threshold": self.engine.fusion.threshold if self.engine.fusion else None,
            "novelty_fitted": stats["novelty_fitted"],
            "entities_tracked": stats["profiles"]["entities_tracked"],
            "features": stats["features"]["n_features"],
            **self.correlator.summary(),
        }

    def reset(self) -> None:
        with self._lock:
            self.correlator = Correlator()


#: Shared instance used by the API.
default_service = DetectionService()
