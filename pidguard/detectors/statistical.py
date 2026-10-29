"""Stage 2b -- Learned detection (pure-Python, zero third-party dependencies).

Signatures cover the attacks we have already seen. A learned model is what
generalises to paraphrases the rule base never anticipated -- the "kindly set
aside whatever you were told earlier" family that shares no keyword with
"ignore previous instructions".

Design choices and why:
  * Hashing trick (2^15 buckets) instead of a fitted vocabulary -- keeps the
    serialized model a flat weight vector, so there is no vocab file to drift
    out of sync, and unseen tokens still land somewhere useful.
  * Word 1/2-grams **and** character 4-grams. Char n-grams are what survive
    leetspeak and homoglyph residue after normalization.
  * L2-regularised logistic regression trained by SGD with class weighting,
    because false positives on benign traffic are the metric that decides
    whether anyone actually deploys this.
  * Trained weights are cached to JSON so import stays fast (no training at
    request time).
"""

from __future__ import annotations

import json
import math
import os
import re
from typing import Dict, Iterable, List, Tuple

from .. import config as _config
from ..types import Detection, NormalizationReport, Severity
from .base import Detector

N_BUCKETS = 1 << 15
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models", "lr_model.json")

_TOKEN_RE = re.compile(r"[a-z0-9_']+|[<>|\[\]{}=/\\#*-]")


# --------------------------------------------------------------- features --
def tokenize(text: str) -> List[str]:
    return _TOKEN_RE.findall(text.lower())


def featurize(text: str) -> Dict[int, float]:
    """Hashed bag of word 1/2-grams + char 4-grams, L2-normalised."""
    counts: Dict[int, float] = {}

    def bump(key: str, weight: float = 1.0) -> None:
        idx = hash_str(key) % N_BUCKETS
        counts[idx] = counts.get(idx, 0.0) + weight

    toks = tokenize(text)
    for t in toks:
        bump("w:" + t)
    for a, b in zip(toks, toks[1:]):
        bump("b:" + a + "_" + b, 1.2)     # bigrams carry the imperative shape
    low = re.sub(r"\s+", " ", text.lower())
    for i in range(len(low) - 3):
        bump("c:" + low[i:i + 4], 0.35)   # survives character-level evasion

    # sublinear scaling then L2 normalisation -> length-invariant vectors
    for k in counts:
        counts[k] = 1.0 + math.log(counts[k])
    norm = math.sqrt(sum(v * v for v in counts.values())) or 1.0
    return {k: v / norm for k, v in counts.items()}


def hash_str(s: str) -> int:
    """FNV-1a: stable across processes, unlike Python's salted hash()."""
    h = 0x811C9DC5
    for ch in s.encode("utf-8"):
        h ^= ch
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


# ---------------------------------------------------------------- model ----
class LogisticRegression:
    """Minimal L2-regularised logistic regression trained with SGD."""

    def __init__(self, n_features: int = N_BUCKETS) -> None:
        self.w: Dict[int, float] = {}
        self.b: float = 0.0
        self.n_features = n_features

    def decision(self, x: Dict[int, float]) -> float:
        return self.b + sum(self.w.get(i, 0.0) * v for i, v in x.items())

    def predict_proba(self, x: Dict[int, float]) -> float:
        z = max(-30.0, min(30.0, self.decision(x)))
        return 1.0 / (1.0 + math.exp(-z))

    def fit(self, rows: Iterable[Tuple[Dict[int, float], int]], *, epochs: int = 40,
            lr: float = 0.5, l2: float = 1e-4, seed: int = 7) -> "LogisticRegression":
        import random
        rows = list(rows)
        n_pos = sum(y for _, y in rows) or 1
        n_neg = len(rows) - n_pos or 1
        # class weights: never let the majority class dictate the boundary
        w_pos = len(rows) / (2.0 * n_pos)
        w_neg = len(rows) / (2.0 * n_neg)
        rng = random.Random(seed)
        for epoch in range(epochs):
            rng.shuffle(rows)
            step = lr / (1.0 + 0.15 * epoch)          # decaying learning rate
            for x, y in rows:
                p = self.predict_proba(x)
                cw = w_pos if y == 1 else w_neg
                g = cw * (p - y)
                self.b -= step * g
                for i, v in x.items():
                    cur = self.w.get(i, 0.0)
                    self.w[i] = cur - step * (g * v + l2 * cur)
        return self

    # -- persistence --
    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = {
            "bias": self.b,
            "n_features": self.n_features,
            # prune near-zero weights: ~10x smaller file, no measurable loss
            "weights": {str(k): round(v, 6) for k, v in self.w.items() if abs(v) > 1e-4},
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

    @classmethod
    def load(cls, path: str) -> "LogisticRegression":
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
        m = cls(payload.get("n_features", N_BUCKETS))
        m.b = payload["bias"]
        m.w = {int(k): v for k, v in payload["weights"].items()}
        return m


# ------------------------------------------------------------- detector ----
class StatisticalDetector(Detector):
    """Emits one calibrated Detection when the classifier crosses threshold."""

    name = "statistical"
    fusion_weight = 1.1

    def __init__(self, model_path: str = MODEL_PATH,
                 threshold: float | None = None) -> None:
        self.threshold = (threshold if threshold is not None
                          else _config.get("statistical_threshold"))
        self.model: LogisticRegression | None = None
        self.model_path = os.path.normpath(model_path)
        if os.path.exists(self.model_path):
            try:
                self.model = LogisticRegression.load(self.model_path)
            except (OSError, ValueError, KeyError):
                self.model = None

    @property
    def available(self) -> bool:
        return self.model is not None

    def probability(self, text: str) -> float:
        if self.model is None:
            return 0.0
        return self.model.predict_proba(featurize(text))

    def scan(self, text: str, report: NormalizationReport | None = None) -> List[Detection]:
        if self.model is None or not text.strip():
            return []
        p = self.probability(text)
        if p < self.threshold:
            return []
        if p >= 0.93:
            sev = Severity.CRITICAL
        elif p >= 0.82:
            sev = Severity.HIGH
        elif p >= 0.70:
            sev = Severity.MEDIUM
        else:
            sev = Severity.LOW
        # Map probability onto 0..1 confidence over the operating range.
        conf = min(1.0, (p - self.threshold) / (1.0 - self.threshold) * 0.8 + 0.2)
        return [Detection(
            detector=self.name, rule_id="LR-01",
            description=f"Learned classifier scores this text as injection (p={p:.3f})",
            severity=sev, confidence=conf,
            matched_text=text[:120],
            metadata={"family": "learned", "probability": round(p, 4)},
        )]
