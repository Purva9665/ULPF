"""
Temporal detector - rate, burst, and periodicity.

Three shapes that only exist in time, and are therefore invisible to any
per-event model no matter how many features it has:

* **Burst** - an entity's event rate jumping far above its own baseline rate.
  This is the flood and scan signature.
* **Beaconing** - contact intervals that are too *regular*. Command-and-control
  implants call home on a timer; humans and applications do not. The
  coefficient of variation of inter-arrival gaps separates them without needing
  to know the beacon period in advance, which is what makes it work against an
  implant nobody has seen before.
* **Failure runs** - consecutive refusals against one destination, which is
  what credential attacks and closed-port sweeps look like from the outside.

Beaconing is the one worth dwelling on: it is a detector that finds an attacker
by their *discipline* rather than their volume, and it is one of the few
techniques that gets stronger the more careful the attacker is.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Deque, Dict, Optional, Tuple

from backend.ml.detectors.base import Evidence, Signal

#: Window over which short-term event rate is measured, in seconds.
RATE_WINDOW_S = 60.0

#: Events in the window above which burst scoring engages at all. Below this,
#: rate ratios are dominated by sampling noise.
MIN_BURST_EVENTS = 20

#: Consecutive refusals against one destination before it reads as a run.
FAILURE_RUN_THRESHOLD = 5

#: Coefficient of variation below which contact intervals look machine-timed.
#: 0.15 is deliberately tight - ordinary application polling sits around
#: 0.3-0.6, and loosening this is the fastest way to flood a SOC with false
#: beacon alerts from monitoring agents.
BEACON_CV_THRESHOLD = 0.15

#: Minimum contacts before periodicity is claimed. Three evenly spaced
#: connections are a coincidence, not a pattern.
MIN_BEACON_OBSERVATIONS = 8


class TemporalDetector:
    """Rate, burst and periodicity signals over a sliding window."""

    name = "temporal"

    def __init__(self, window_s: float = RATE_WINDOW_S, max_entities: int = 20_000):
        self.window_s = window_s
        self.max_entities = max_entities
        self._recent: Dict[str, Deque[float]] = defaultdict(deque)
        self._failure_runs: Dict[Tuple[str, str], int] = {}

    def analyse(
        self,
        features: Dict[str, float],
        norm: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Signal:
        src = getattr(getattr(norm, "source", None), "ip", None) or ""
        dst = getattr(getattr(norm, "destination", None), "ip", None) or ""
        now = float((context or {}).get("epoch", 0.0))
        denied = features.get("action_is_denied", 0.0) >= 1.0

        evidence = []
        scores = []

        # --- burst ----------------------------------------------------------
        rate = self._observe_rate(src, now) if src else 0
        if rate >= MIN_BURST_EVENTS:
            # Normalised against 200 events/minute from one source, which is
            # already far beyond interactive human behaviour.
            burst = min(1.0, rate / 200.0)
            scores.append(0.6 * burst)
            evidence.append(Evidence(
                signal="event_burst",
                observed=rate,
                argues=f"{rate} events from this source in the last "
                       f"{int(self.window_s)}s",
                weight=0.6 * burst,
            ))

        # --- failure runs ---------------------------------------------------
        run = self._observe_failure(src, dst, denied) if src and dst else 0
        if run >= FAILURE_RUN_THRESHOLD:
            run_score = min(1.0, run / 25.0)
            scores.append(0.55 * run_score)
            evidence.append(Evidence(
                signal="failure_run",
                observed=run,
                argues=f"{run} consecutive refused connections to this destination",
                weight=0.55 * run_score,
            ))

        # --- beaconing ------------------------------------------------------
        beacon = features.get("src_beacon_score", 0.0)
        if beacon > 0.0:
            scores.append(0.7 * beacon)
            evidence.append(Evidence(
                signal="periodic_contact",
                observed=round(beacon, 3),
                argues="Contact intervals with this destination are unusually "
                       "regular, which is characteristic of automated "
                       "call-home behaviour rather than human or application traffic",
                weight=0.7 * beacon,
            ))

        if not scores:
            evidence.append(Evidence(
                signal="no_temporal_anomaly",
                observed=rate,
                argues="Event timing shows no burst, periodicity or failure run",
                weight=-0.10,
            ))

        score = max(scores) if scores else 0.0
        # Timing evidence is only as good as the timestamps. If the source did
        # not carry one, everything above was computed against ingest time.
        has_time = now > 0.0
        confidence = 0.65 if has_time else 0.25
        if not has_time:
            evidence.append(Evidence(
                signal="no_event_timestamp",
                observed=None,
                argues="The source carried no usable event timestamp, so timing "
                       "signals are measured against ingest time and are unreliable",
                weight=0.0,
            ))

        return Signal(
            detector=self.name,
            score=score,
            confidence=confidence,
            evidence=evidence,
            state={"window_events": rate, "tracked_entities": len(self._recent)},
        )

    # -- windowed state ------------------------------------------------------

    def _observe_rate(self, entity: str, now: float) -> int:
        window = self._recent[entity]
        window.append(now)
        cutoff = now - self.window_s
        while window and window[0] < cutoff:
            window.popleft()
        if len(self._recent) > self.max_entities:
            self._evict()
        return len(window)

    def _observe_failure(self, src: str, dst: str, denied: bool) -> int:
        key = (src, dst)
        if denied:
            self._failure_runs[key] = self._failure_runs.get(key, 0) + 1
        else:
            # A success resets the run. A credential attack that succeeds is
            # still worth detecting, but that is the correlator's job - here it
            # genuinely ends the run of failures.
            self._failure_runs.pop(key, None)
        if len(self._failure_runs) > self.max_entities:
            self._failure_runs.clear()
        return self._failure_runs.get(key, 0)

    def _evict(self) -> None:
        """Drop the entities with the least recent activity."""
        for entity in sorted(self._recent, key=lambda e: self._recent[e][-1]
                             if self._recent[e] else 0.0)[: self.max_entities // 4]:
            self._recent.pop(entity, None)

    def reset(self) -> None:
        self._recent.clear()
        self._failure_runs.clear()
