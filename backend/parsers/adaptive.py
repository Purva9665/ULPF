"""
ULPF Adaptive Template Parser - zero-configuration onboarding of unknown sources.

Requirements (e) "plug-and-play onboarding of new log sources" and (i) "reduced
parser development effort" cannot be met by shipping hand-written parsers,
because writing a parser per source is precisely the cost the problem statement
identifies. A source ULPF has never seen must still yield structure.

Algorithm: Drain
----------------
He, P., Zhu, J., Zheng, Z., & Lyu, M. R. (2017). "Drain: An Online Log Parsing
Approach with Fixed Depth Tree." IEEE ICWS 2017, pp. 33-40.
DOI: 10.1109/ICWS.2017.13

Chosen on published evidence rather than preference. In the largest public log
parsing evaluation to date - Jiang et al., "A Large-Scale Evaluation for Log
Parsing Techniques: How Far Are We?", ISSTA 2024, arXiv:2308.10828 - Drain was
the highest-performing parser overall (+28.3% grouping accuracy, +38.1% FGA,
+18.6% FTA over semantic-based parsers), and was one of only 6 of 15 parsers
that completed all 14 datasets within a 12-hour budget. It requires no training,
no labels and no network access, which is what an air-gapped deployment needs.

How it works
------------
1. Preprocess: mask obvious variables (IPs, numbers, hex, UUIDs, paths) so they
   do not fragment the template space.
2. Search a fixed-depth tree: first layer keyed by token count, subsequent
   layers by leading tokens. Depth is bounded, so lookup is O(depth), not O(n).
3. At the leaf, compare against existing clusters by token-position similarity.
4. If the best similarity clears the threshold, merge - positions that differ
   become wildcards. Otherwise start a new cluster.

The result is a stable template plus the variable parts, which ULPF exposes as
positional parameters for the normalizer to map.

Honest limitations, stated because they matter
----------------------------------------------
* Drain infers *structure*, not *meaning*. It yields param_0, param_1 ... not
  src_ip. Semantic naming still needs a mapping rule; what Drain removes is the
  need to write a tokenizer for every new source.
* Jiang et al. Finding 7: on messages with more than 5 variable parameters every
  evaluated parser degrades badly (FGA below 0.03; LogPPT reaches only 0.16).
  Parameter-dense network logs are the hard case, and this parser will not be
  accurate on them. It is a fallback for unknown sources, not a replacement for
  the vendor parsers.
* This parser deliberately reports low confidence so the registry always prefers
  a purpose-built parser when one matches.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from backend.core.base_parser import BaseParser
from backend.core.models import ULPFParsedEvent, ULPFRawEvent

#: Wildcard used in templates for a position that varies between messages.
WILDCARD = "<*>"

#: Ordered masking rules applied before tokenization. Order matters: the more
#: specific pattern must win, or an IPv4 address becomes three separate numbers.
MASKING_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"), "<MAC>"),
    # Timestamps must be masked before IPv6. A loose "colon-separated hex
    # groups" pattern also matches the 01:00:00 inside 2026-09-01T01:00:00Z,
    # which shatters every timestamped log line into the wrong template.
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
                r"(?:Z|[+-]\d{2}:?\d{2})?"), "<TIMESTAMP>"),
    (re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b"), "<TIME>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"), "<IP>"),
    # IPv6 only in unambiguous forms: the full eight-group address, or one
    # containing the "::" compression marker. Anything looser collides with
    # clock times and port ranges.
    (re.compile(r"\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}"), "<IPV6>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"(?<![\w.])[/\\](?:[\w.\-]+[/\\])+[\w.\-]*"), "<PATH>"),
    (re.compile(r"\b\d+\.\d+\b"), "<FLOAT>"),
    (re.compile(r"\b\d+\b"), "<NUM>"),
]

#: Token separators. Kept conservative - splitting on punctuation would shatter
#: key=value pairs that carry real structure.
_SPLIT = re.compile(r"[\s,;|]+")


class LogCluster:
    """One inferred template and the messages that matched it."""

    __slots__ = ("template_tokens", "cluster_id", "match_count", "first_seen", "last_seen")

    def __init__(self, tokens: List[str], cluster_id: int):
        self.template_tokens: List[str] = list(tokens)
        self.cluster_id = cluster_id
        self.match_count = 1
        self.first_seen = time.time()
        self.last_seen = self.first_seen

    @property
    def template(self) -> str:
        return " ".join(self.template_tokens)

    def similarity(self, tokens: List[str]) -> float:
        """Fraction of positions that agree.

        A wildcard position counts as agreeing with anything, but does not add
        to the score - otherwise a heavily-wildcarded template would absorb
        every message and the template space would collapse to one entry.
        """
        if len(tokens) != len(self.template_tokens):
            return 0.0
        if not tokens:
            return 1.0
        matched = sum(
            1 for a, b in zip(self.template_tokens, tokens)
            if a == b and a != WILDCARD
        )
        return matched / len(tokens)

    def merge(self, tokens: List[str]) -> int:
        """Widen the template to accommodate a new message.

        Returns the number of positions newly turned into wildcards, which the
        caller uses to report template stability.
        """
        widened = 0
        for i, (existing, incoming) in enumerate(zip(self.template_tokens, tokens)):
            if existing != incoming and existing != WILDCARD:
                self.template_tokens[i] = WILDCARD
                widened += 1
        self.match_count += 1
        self.last_seen = time.time()
        return widened

    def parameters(self, tokens: List[str]) -> List[str]:
        """The variable parts of this message, in template order."""
        return [
            tok for tmpl, tok in zip(self.template_tokens, tokens)
            if tmpl == WILDCARD
        ]


class DrainTree:
    """Fixed-depth prefix tree over token count then leading tokens."""

    def __init__(self, depth: int = 4, max_children: int = 100,
                 similarity_threshold: float = 0.5, max_clusters: int = 10_000):
        # Depth counts the two structural layers (length, then tokens), so the
        # usable prefix length is depth - 2, matching the original paper.
        self.max_depth = max(3, depth)
        self.max_children = max_children
        self.threshold = similarity_threshold
        self.max_clusters = max_clusters
        self._root: Dict[Any, Any] = {}
        self._clusters: Dict[int, LogCluster] = {}
        self._next_id = 0

    # -- public ------------------------------------------------------------

    @property
    def clusters(self) -> List[LogCluster]:
        return list(self._clusters.values())

    def add(self, tokens: List[str]) -> Tuple[LogCluster, bool, int]:
        """Match or create a cluster.

        Returns (cluster, is_new, positions_widened).
        """
        leaf = self._leaf_for(tokens, create=True)
        best, best_sim = None, -1.0
        for cluster in leaf:
            sim = cluster.similarity(tokens)
            if sim > best_sim:
                best, best_sim = cluster, sim

        if best is not None and best_sim >= self.threshold:
            widened = best.merge(tokens)
            return best, False, widened

        if len(self._clusters) >= self.max_clusters:
            # Refuse to grow without bound. An unbounded template space on
            # adversarial or highly variable input is a memory-exhaustion risk,
            # and a saturated tree is a signal worth surfacing, not hiding.
            if best is not None:
                widened = best.merge(tokens)
                return best, False, widened

        cluster = LogCluster(tokens, self._next_id)
        self._next_id += 1
        self._clusters[cluster.cluster_id] = cluster
        leaf.append(cluster)
        return cluster, True, 0

    def stats(self) -> Dict[str, Any]:
        return {
            "templates": len(self._clusters),
            "max_templates": self.max_clusters,
            "depth": self.max_depth,
            "similarity_threshold": self.threshold,
            "saturated": len(self._clusters) >= self.max_clusters,
        }

    # -- internal ----------------------------------------------------------

    @staticmethod
    def _key(token: str) -> str:
        """Tokens containing digits are unstable and must not become tree keys,
        or every distinct value spawns a branch."""
        return WILDCARD if any(ch.isdigit() for ch in token) else token

    def _leaf_for(self, tokens: List[str], create: bool) -> List[LogCluster]:
        node = self._root.setdefault(len(tokens), {}) if create else self._root.get(len(tokens), {})

        prefix_len = min(self.max_depth - 2, len(tokens))
        for i in range(prefix_len):
            key = self._key(tokens[i])
            child = node.get(key)
            if child is None:
                if not create:
                    return []
                if len([k for k in node if k != WILDCARD]) >= self.max_children:
                    key = WILDCARD
                    child = node.setdefault(key, {})
                else:
                    child = node.setdefault(key, {})
            node = child

        if "__leaf__" not in node:
            node["__leaf__"] = []
        return node["__leaf__"]


def preprocess(line: str) -> Tuple[str, List[str]]:
    """Mask variables, then tokenize. Returns (masked_line, tokens)."""
    masked = line.strip()
    for pattern, placeholder in MASKING_RULES:
        masked = pattern.sub(placeholder, masked)
    tokens = [t for t in _SPLIT.split(masked) if t]
    return masked, tokens


class AdaptiveTemplateParser(BaseParser):
    """Last-resort parser that learns the structure of an unseen log source.

    Confidence is intentionally capped below every purpose-built parser so the
    registry only selects this when nothing else matches. It is a safety net
    that guarantees an unknown source still produces structure, not a competitor
    to the vendor parsers.
    """

    name = "adaptive_template"
    vendor = "ULPF"
    product = "Adaptive Template Miner (Drain)"
    supported_formats = ["unknown", "text", "any"]
    description = (
        "Zero-configuration structure inference for unseen log sources using the "
        "Drain fixed-depth-tree algorithm (He et al., ICWS 2017)"
    )

    #: Deliberately low - every hand-written parser must outrank this.
    BASE_CONFIDENCE = 0.35

    def __init__(self, depth: int = 4, similarity_threshold: float = 0.5,
                 max_clusters: int = 10_000):
        self.tree = DrainTree(
            depth=depth,
            similarity_threshold=similarity_threshold,
            max_clusters=max_clusters,
        )

    def can_parse(self, raw_event: ULPFRawEvent) -> Tuple[bool, float]:
        """Accepts any non-empty text. The registry resolves by confidence, so
        claiming universal applicability at low confidence is exactly right for
        a fallback: always available, never preferred."""
        payload = raw_event.raw.payload
        if not payload or not payload.strip():
            return False, 0.0
        return True, self.BASE_CONFIDENCE

    def parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        line = raw_event.raw.payload
        masked, tokens = preprocess(line)
        cluster, is_new, widened = self.tree.add(tokens)
        params = cluster.parameters(tokens)

        extracted: Dict[str, Any] = {
            "_template": cluster.template,
            "_template_id": cluster.cluster_id,
            "_template_is_new": is_new,
            "_template_match_count": cluster.match_count,
            "_template_widened_positions": widened,
            "_masked_line": masked,
            "_token_count": len(tokens),
            "vendor": self.vendor,
            "product": self.product,
        }

        # Positional parameters. Named semantically only where masking already
        # told us what the value is - inventing a name we cannot justify would
        # be worse than leaving it positional.
        for i, value in enumerate(params):
            extracted[f"param_{i}"] = value

        for key, value in self._recover_semantics(line).items():
            extracted.setdefault(key, value)

        # A template seen only once is not yet evidence of structure. Report
        # lower confidence until it has recurred.
        confidence = self.BASE_CONFIDENCE
        if cluster.match_count >= 5 and widened == 0:
            confidence = 0.55
        elif is_new:
            confidence = 0.25

        tokens_out = [
            {"key": k, "value": v, "type": type(v).__name__}
            for k, v in extracted.items()
        ]

        return ULPFParsedEvent(
            event_id=raw_event.event_id,
            raw=raw_event.raw,
            parser_name=self.name,
            parser_vendor=self.vendor,
            parser_product=self.product,
            confidence_score=confidence,
            extracted_fields=extracted,
            tokens=tokens_out,
        )

    # -- semantic recovery --------------------------------------------------

    _KV = re.compile(r"(\w[\w.\-]*)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s,;|]+)")
    _IPV4 = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?\b")

    def _recover_semantics(self, line: str) -> Dict[str, Any]:
        """Extract the few things that are unambiguous from raw text alone.

        This is intentionally minimal. Drain gives structure; guessing which IP
        is the source and which the destination from position alone is exactly
        the kind of confident-but-wrong output this project is avoiding, so
        addresses are reported as an ordered list and left for a mapping rule.
        """
        found: Dict[str, Any] = {}

        for key, value in self._KV.findall(line):
            found.setdefault(key.lower(), value.strip("\"'"))

        addresses = self._IPV4.findall(line)
        if addresses:
            found["_observed_ips"] = [ip for ip, _ in addresses]
            ports = [int(p) for _, p in addresses if p]
            if ports:
                found["_observed_ports"] = ports

        return found

    def stats(self) -> Dict[str, Any]:
        tree_stats = self.tree.stats()
        tree_stats["top_templates"] = [
            {
                "id": c.cluster_id,
                "template": c.template,
                "matches": c.match_count,
            }
            for c in sorted(self.tree.clusters, key=lambda c: -c.match_count)[:10]
        ]
        return tree_stats
