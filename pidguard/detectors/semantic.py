"""Stage 2c -- Semantic nearest-neighbour detection.

The learned classifier gives a probability but no evidence. This detector
answers a different, more auditable question: *which known attack is this
closest to, and how close?* That neighbour is what gets shown to a security
reviewer in the audit log, and it is what lets a new attack be defended by
adding one example rather than by retraining.

The representation is a hashed character-4-gram + word-bigram vector with
cosine similarity -- deliberately not a neural embedding, so the middleware
adds no GPU dependency and no network hop to the request path. The
`ExemplarIndex` interface is the swap point: replacing `_vectorize` with a
sentence-transformer call is a one-function change.
"""

from __future__ import annotations

import json
import math
import os
import re
from typing import Dict, List, Sequence, Tuple

from .. import config as _config
from ..types import Detection, NormalizationReport, Severity
from .base import Detector
from .statistical import hash_str

N_BUCKETS = 1 << 14
DEFAULT_EXEMPLARS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "models", "exemplars.json")

_WORD_RE = re.compile(r"[a-z0-9']+")


def _vectorize(text: str) -> Dict[int, float]:
    """Sparse L2-normalised hashed vector. Swap point for real embeddings."""
    vec: Dict[int, float] = {}
    low = re.sub(r"\s+", " ", text.lower()).strip()
    words = _WORD_RE.findall(low)
    for w in words:
        i = hash_str("w:" + w) % N_BUCKETS
        vec[i] = vec.get(i, 0.0) + 1.0
    for a, b in zip(words, words[1:]):
        i = hash_str("b:" + a + "_" + b) % N_BUCKETS
        vec[i] = vec.get(i, 0.0) + 1.5
    for k in range(len(low) - 3):
        i = hash_str("c:" + low[k:k + 4]) % N_BUCKETS
        vec[i] = vec.get(i, 0.0) + 0.5
    norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
    return {k: v / norm for k, v in vec.items()}


def cosine(a: Dict[int, float], b: Dict[int, float]) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(v * b.get(k, 0.0) for k, v in a.items())


class ExemplarIndex:
    """Vector store of known-malicious spans, with their attack family."""

    def __init__(self) -> None:
        self.vectors: List[Dict[int, float]] = []
        self.texts: List[str] = []
        self.families: List[str] = []

    def add(self, text: str, family: str = "unknown") -> None:
        self.vectors.append(_vectorize(text))
        self.texts.append(text)
        self.families.append(family)

    def add_many(self, items: Sequence[Tuple[str, str]]) -> None:
        for text, family in items:
            self.add(text, family)

    def nearest(self, text: str) -> Tuple[float, str, str]:
        """Return (similarity, exemplar_text, family) of the closest attack."""
        if not self.vectors:
            return 0.0, "", ""
        q = _vectorize(text)
        best, best_i = -1.0, 0
        for i, v in enumerate(self.vectors):
            s = cosine(q, v)
            if s > best:
                best, best_i = s, i
        return best, self.texts[best_i], self.families[best_i]

    # -- persistence: exemplar *text* is stored, vectors are rebuilt on load,
    #    so the index stays readable and reviewable by a human.
    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump([{"text": t, "family": f}
                       for t, f in zip(self.texts, self.families)], fh,
                      ensure_ascii=False, indent=1)

    @classmethod
    def load(cls, path: str) -> "ExemplarIndex":
        idx = cls()
        with open(path, encoding="utf-8") as fh:
            for row in json.load(fh):
                idx.add(row["text"], row.get("family", "unknown"))
        return idx

    def __len__(self) -> int:
        return len(self.vectors)


class SemanticDetector(Detector):
    """Flags text that is close to a known attack in vector space."""

    name = "semantic"
    fusion_weight = 0.9

    def __init__(self, index_path: str = DEFAULT_EXEMPLARS,
                 threshold: float | None = None) -> None:
        self.threshold = (threshold if threshold is not None
                          else _config.get("semantic_threshold"))
        self.index = ExemplarIndex()
        path = os.path.normpath(index_path)
        if os.path.exists(path):
            try:
                self.index = ExemplarIndex.load(path)
            except (OSError, ValueError):
                pass

    @property
    def available(self) -> bool:
        return len(self.index) > 0

    def scan(self, text: str, report: NormalizationReport | None = None) -> List[Detection]:
        if not self.available or not text.strip():
            return []
        sim, exemplar, family = self.index.nearest(text)
        if sim < self.threshold:
            return []
        sev = (Severity.CRITICAL if sim >= 0.85 else
               Severity.HIGH if sim >= 0.72 else
               Severity.MEDIUM)
        conf = min(1.0, (sim - self.threshold) / (1.0 - self.threshold) * 0.7 + 0.3)
        return [Detection(
            detector=self.name, rule_id="SIM-01",
            description=(f"Semantically close to a known {family} attack "
                         f"(cosine {sim:.3f})"),
            severity=sev, confidence=conf,
            matched_text=text[:120],
            metadata={"family": family, "similarity": round(sim, 4),
                      "nearest_exemplar": exemplar[:160]},
        )]
