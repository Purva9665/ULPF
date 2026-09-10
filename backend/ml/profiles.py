"""
ULPF Entity Behaviour Profiles - the memory the detection model reasons against.

Why this module exists
----------------------
The previous engine scored every event in isolation from six per-event
features. That cannot express the statements a SOC analyst actually makes:

    "This host has never talked to port 3389 before."
    "This account normally logs in at 09:00, not 03:00."
    "This server's outbound volume is 12x its own baseline."

Every one of those is a comparison against a *baseline for that entity*, and
none of them are computable from a single log line. This module maintains those
baselines incrementally, in bounded memory, with no training phase and no
network access - which is what an air-gapped deployment requires.

Design constraints
------------------
* O(1) update per event. The pipeline runs at ~900 EPS single-process; a
  profile update costing more than a few microseconds is not viable.
* Bounded memory. An enterprise sees millions of distinct IPs. Profiles live in
  an LRU map with a hard cap, and per-profile counters are themselves capped,
  so worst-case memory is a function of configuration, not of traffic.
* Streaming statistics only. Welford's algorithm for mean/variance (Welford
  1962, Technometrics 4(3):419-420) so no sample buffer is retained.
* Recency weighting. Counts decay exponentially so a baseline tracks current
  behaviour rather than everything ever seen. Without decay a profile grows
  steadily less sensitive as it ages, which is the classic failure mode of
  naive UEBA baselines.

Rarity scoring
--------------
For a categorical attribute we estimate P(value | entity) with additive
(Laplace) smoothing and report surprisal, -log2(P), normalised to [0, 1].
Smoothing matters: without it the first observation of any value has
probability zero and infinite surprisal, so every new entity would light up
every detector on its first event.
"""

from __future__ import annotations

import math
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

#: Additive smoothing constant for categorical rarity. 0.5 is the Jeffreys
#: prior, the usual choice when the alphabet size is not known in advance.
ALPHA = 0.5

#: Half-life for exponential count decay, measured in events observed by that
#: entity. After this many of its own events, an old observation carries half
#: the weight of a fresh one.
DECAY_HALF_LIFE = 2000.0

#: Maximum distinct values retained per categorical attribute. Beyond this the
#: least-weighted value is evicted, which bounds memory per profile.
MAX_CATEGORY_CARDINALITY = 256

#: Events an entity must be seen for before its baseline is considered usable.
MIN_EVENTS_FOR_BASELINE = 30


class DecayingCounter:
    """Categorical counter with exponential decay and bounded cardinality.

    Decaying every stored value on each update would be O(n) per event. Instead
    we scale the *increment* upward over time and divide by the running scale
    when a probability is requested. This is the standard trick for
    exponentially weighted counts and keeps updates O(1).
    """

    __slots__ = ("_counts", "_scale", "_total", "_lambda", "_max_card")

    def __init__(
        self,
        half_life: float = DECAY_HALF_LIFE,
        max_cardinality: int = MAX_CATEGORY_CARDINALITY,
    ):
        self._counts: Dict[str, float] = {}
        self._scale = 1.0
        self._total = 0.0
        self._lambda = math.log(2.0) / max(half_life, 1.0)
        self._max_card = max_cardinality

    def observe(self, value: str) -> None:
        self._scale *= math.exp(self._lambda)
        # Renormalise before the scale overflows a float64.
        if self._scale > 1e250:
            self._renormalise()
        self._counts[value] = self._counts.get(value, 0.0) + self._scale
        self._total += self._scale
        if len(self._counts) > self._max_card:
            self._evict()

    def weight_of(self, value: str) -> float:
        return self._counts.get(value, 0.0) / self._scale

    def total(self) -> float:
        return self._total / self._scale

    def cardinality(self) -> int:
        return len(self._counts)

    def probability(self, value: str) -> float:
        """Smoothed P(value | this entity)."""
        n = self.total()
        k = max(len(self._counts), 1)
        return (self.weight_of(value) + ALPHA) / (n + ALPHA * (k + 1))

    def surprisal(self, value: str) -> float:
        """-log2 P(value), normalised to [0, 1].

        Normalised against 12 bits, i.e. a probability around 1/4096. Anything
        rarer than that is already maximally surprising for our purposes, and
        the extra resolution only produces noise.
        """
        p = self.probability(value)
        bits = -math.log2(max(p, 1e-12))
        return min(1.0, bits / 12.0)

    def is_new(self, value: str) -> bool:
        return value not in self._counts

    def top(self, n: int = 5) -> List[Tuple[str, float]]:
        items = sorted(self._counts.items(), key=lambda kv: kv[1], reverse=True)
        return [(k, round(v / self._scale, 2)) for k, v in items[:n]]

    def _renormalise(self) -> None:
        s = self._scale
        self._counts = {k: v / s for k, v in self._counts.items()}
        self._total /= s
        self._scale = 1.0

    def _evict(self) -> None:
        victim = min(self._counts, key=self._counts.get)
        self._total -= self._counts.pop(victim)


class RunningStats:
    """Welford streaming mean/variance. No sample buffer retained."""

    __slots__ = ("n", "mean", "m2", "minimum", "maximum")

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.minimum = float("inf")
        self.maximum = float("-inf")

    def observe(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)
        if x < self.minimum:
            self.minimum = x
        if x > self.maximum:
            self.maximum = x

    @property
    def variance(self) -> float:
        return self.m2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

    def zscore(self, x: float) -> float:
        """Deviation from this entity's own baseline, in standard deviations.

        Returns 0.0 until there is enough history to have a baseline at all.

        A floor is applied to sigma because an entity with a near-constant
        value would otherwise produce an unbounded z-score on the first small
        deviation - the single most common source of false positives in
        volume-based detection.
        """
        if self.n < MIN_EVENTS_FOR_BASELINE:
            return 0.0
        sigma = max(self.stddev, abs(self.mean) * 0.05, 1.0)
        return (x - self.mean) / sigma


@dataclass
class EntityProfile:
    """Behavioural baseline for one entity (an IP, user, or host)."""

    entity_id: str
    entity_type: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    event_count: int = 0

    dst_ports: DecayingCounter = field(default_factory=DecayingCounter)
    peers: DecayingCounter = field(default_factory=DecayingCounter)
    protocols: DecayingCounter = field(default_factory=DecayingCounter)
    actions: DecayingCounter = field(default_factory=DecayingCounter)
    threat_classes: DecayingCounter = field(default_factory=DecayingCounter)
    hours: DecayingCounter = field(default_factory=DecayingCounter)

    bytes_out: RunningStats = field(default_factory=RunningStats)
    bytes_in: RunningStats = field(default_factory=RunningStats)

    #: Inter-arrival gaps per peer, for periodicity (beaconing) detection.
    last_seen_per_peer: Dict[str, float] = field(default_factory=dict)
    intervals: Dict[str, RunningStats] = field(default_factory=dict)

    def is_cold(self, min_events: int = MIN_EVENTS_FOR_BASELINE) -> bool:
        """True while there is too little history to judge against.

        Reported rather than hidden: a detector firing on an entity with four
        observations is guessing, and the output should say so.
        """
        return self.event_count < min_events

    def observe(
        self,
        *,
        dst_port: Optional[int] = None,
        peer: Optional[str] = None,
        protocol: Optional[str] = None,
        action: Optional[str] = None,
        threat_class: Optional[str] = None,
        hour: Optional[int] = None,
        bytes_out: Optional[int] = None,
        bytes_in: Optional[int] = None,
        timestamp: Optional[float] = None,
    ) -> None:
        ts = time.time() if timestamp is None else timestamp
        self.event_count += 1
        self.last_seen = ts

        if dst_port is not None:
            self.dst_ports.observe(str(dst_port))
        if peer:
            self._observe_peer(peer, ts)
        if protocol:
            self.protocols.observe(protocol)
        if action:
            self.actions.observe(action)
        if threat_class:
            self.threat_classes.observe(threat_class)
        if hour is not None:
            self.hours.observe(str(hour))
        if bytes_out:
            self.bytes_out.observe(float(bytes_out))
        if bytes_in:
            self.bytes_in.observe(float(bytes_in))

    def _observe_peer(self, peer: str, ts: float) -> None:
        self.peers.observe(peer)
        prev = self.last_seen_per_peer.get(peer)
        if prev is not None:
            gap = ts - prev
            # Sub-second gaps are scan or flood behaviour, not beaconing, and
            # they distort the interval statistics the beacon detector depends
            # on. The burst detector owns that signal instead.
            if 1.0 <= gap <= 86400.0:
                self.intervals.setdefault(peer, RunningStats()).observe(gap)
        self.last_seen_per_peer[peer] = ts
        if len(self.last_seen_per_peer) > MAX_CATEGORY_CARDINALITY:
            oldest = min(self.last_seen_per_peer, key=self.last_seen_per_peer.get)
            self.last_seen_per_peer.pop(oldest, None)
            self.intervals.pop(oldest, None)

    def summary(self) -> Dict[str, object]:
        """Human-readable baseline, for the detection evidence panel."""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "event_count": self.event_count,
            "is_cold": self.is_cold(),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "distinct_ports": self.dst_ports.cardinality(),
            "distinct_peers": self.peers.cardinality(),
            "top_ports": self.dst_ports.top(5),
            "top_peers": self.peers.top(5),
            "mean_bytes_out": round(self.bytes_out.mean, 1),
            "mean_bytes_in": round(self.bytes_in.mean, 1),
        }


class ProfileStore:
    """Bounded LRU collection of entity profiles.

    An enterprise sees far more distinct entities than can be held in memory.
    Eviction is least-recently-used, which keeps the working set - the entities
    currently generating traffic - resident, and that is exactly the set the
    detectors need.
    """

    def __init__(self, max_entities: int = 50_000):
        self._profiles: "OrderedDict[Tuple[str, str], EntityProfile]" = OrderedDict()
        self.max_entities = max_entities
        self.evictions = 0

    def get(self, entity_type: str, entity_id: str) -> EntityProfile:
        key = (entity_type, entity_id)
        profile = self._profiles.get(key)
        if profile is None:
            profile = EntityProfile(entity_id=entity_id, entity_type=entity_type)
            self._profiles[key] = profile
            if len(self._profiles) > self.max_entities:
                self._profiles.popitem(last=False)
                self.evictions += 1
        else:
            self._profiles.move_to_end(key)
        return profile

    def peek(self, entity_type: str, entity_id: str) -> Optional[EntityProfile]:
        """Read a profile without creating or promoting it."""
        return self._profiles.get((entity_type, entity_id))

    def __len__(self) -> int:
        return len(self._profiles)

    def __contains__(self, key: Tuple[str, str]) -> bool:
        return key in self._profiles

    def top_by_events(self, n: int = 20) -> List[EntityProfile]:
        return sorted(
            self._profiles.values(), key=lambda p: p.event_count, reverse=True
        )[:n]

    def all_of_type(self, entity_type: str) -> Iterable[EntityProfile]:
        return (p for (t, _), p in self._profiles.items() if t == entity_type)

    def stats(self) -> Dict[str, object]:
        return {
            "entities_tracked": len(self._profiles),
            "max_entities": self.max_entities,
            "evictions": self.evictions,
        }
