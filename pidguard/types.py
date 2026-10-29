"""Core data types shared across the PID-Guard middleware pipeline."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TrustTier(str, Enum):
    """Provenance of a text span. Lower trust => stricter policy thresholds.

    The single most important idea in the middleware: an LLM agent cannot tell
    *instructions* from *data* on its own, so we attach trust to the channel
    the text arrived on and let policy, not the model, decide what may act.
    """

    SYSTEM = "system"      # developer-authored prompt, fully trusted
    USER = "user"          # the human operator, trusted but not privileged
    TOOL = "tool"          # output of a tool the agent called
    RETRIEVED = "retrieved"  # RAG / document store content
    WEB = "web"            # arbitrary internet content, untrusted

    @property
    def weight(self) -> float:
        """Risk multiplier applied to the fused detector score."""
        return {
            TrustTier.SYSTEM: 0.0,
            TrustTier.USER: 0.75,
            TrustTier.TOOL: 1.15,
            TrustTier.RETRIEVED: 1.25,
            TrustTier.WEB: 1.40,
        }[self]


class Decision(str, Enum):
    """Terminal verdict produced by the policy engine."""

    ALLOW = "allow"        # forward unchanged
    SANITIZE = "sanitize"  # forward, but neutralized + spotlighted
    BLOCK = "block"        # do not forward to the model at all


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def score(self) -> float:
        return {
            Severity.LOW: 0.25,
            Severity.MEDIUM: 0.50,
            Severity.HIGH: 0.80,
            Severity.CRITICAL: 1.0,
        }[self]


@dataclass
class Detection:
    """A single piece of evidence emitted by one detector."""

    detector: str
    rule_id: str
    description: str
    severity: Severity
    confidence: float                     # 0..1, detector's own certainty
    span: Optional[tuple] = None          # (start, end) offsets in normalized text
    matched_text: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def weighted_score(self) -> float:
        return self.severity.score * max(0.0, min(1.0, self.confidence))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "span": list(self.span) if self.span else None,
            "matched_text": self.matched_text[:200],
            "metadata": self.metadata,
        }


@dataclass
class NormalizationReport:
    """What the normalizer had to undo to reach canonical text.

    Obfuscation is itself a signal: benign documents rarely need
    zero-width stripping and base64 unwrapping to become readable.
    """

    original: str
    normalized: str
    transforms: List[str] = field(default_factory=list)
    decoded_payloads: List[str] = field(default_factory=list)
    invisible_chars_removed: int = 0
    homoglyphs_folded: int = 0
    #: Transliterations of wholly non-Latin tokens, carried as an extra view.
    #: Folding confusables everywhere destroyed legitimate foreign text, so a
    #: non-Latin token is preserved and its Latin reading recorded here.
    script_variants: List[str] = field(default_factory=list)

    @property
    def obfuscation_pressure(self) -> float:
        """0..1 heuristic: how much hiding machinery was present.

        Concealment counts, not just encoding. An earlier version scored only
        invisible characters, homoglyphs and decoded payloads, so hiding a
        payload inside an HTML comment -- text invisible to the human reading
        the page but fully visible to the model -- contributed nothing. Our
        adaptive adversary found that immediately: wrapping a caught payload in
        `<!-- ... -->` evaded in a single mutation.
        """
        pressure = 0.0
        pressure += min(0.4, self.invisible_chars_removed * 0.05)
        pressure += min(0.3, self.homoglyphs_folded * 0.04)
        pressure += 0.35 * min(1.0, len(self.decoded_payloads))
        # Deliberate concealment from the human reader. Kept deliberately
        # small: this signal is content-blind, and real pages carry layout
        # comments ("page break", template markers). At 0.45 it blocked eight
        # benign documents outright. The concealed text is handled instead by
        # giving it its own scan window so it is scored undiluted -- see the
        # hidden-content hoist in normalizer.normalize.
        if any("HTML comment" in t or "hidden markdown" in t
               for t in self.transforms):
            pressure += 0.12
        if self.script_variants:
            pressure += min(0.15, 0.05 * len(self.script_variants))
        return min(1.0, pressure)


@dataclass
class GuardResult:
    """Everything the middleware knows about one inspected span."""

    decision: Decision
    risk_score: float
    original_text: str
    safe_text: str
    trust_tier: TrustTier
    detections: List[Detection] = field(default_factory=list)
    normalization: Optional[NormalizationReport] = None
    allowed_tools: List[str] = field(default_factory=list)
    revoked_tools: List[str] = field(default_factory=list)
    latency_ms: float = 0.0
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_attack(self) -> bool:
        return self.decision is not Decision.ALLOW

    @property
    def top_detection(self) -> Optional[Detection]:
        if not self.detections:
            return None
        return max(self.detections, key=lambda d: d.weighted_score)

    def explain(self) -> str:
        """Human-readable justification -- required for auditability."""
        lines = [
            f"[{self.trace_id}] decision={self.decision.value.upper()} "
            f"risk={self.risk_score:.3f} tier={self.trust_tier.value} "
            f"({self.latency_ms:.2f} ms)"
        ]
        if self.normalization and self.normalization.transforms:
            lines.append(f"  normalization: {', '.join(self.normalization.transforms)}")
        for d in sorted(self.detections, key=lambda x: -x.weighted_score):
            lines.append(
                f"  - {d.detector}/{d.rule_id} [{d.severity.value}] "
                f"conf={d.confidence:.2f} :: {d.description}"
            )
            if d.matched_text:
                lines.append(f"      match: {d.matched_text[:90]!r}")
        if self.revoked_tools:
            lines.append(f"  tools revoked: {', '.join(self.revoked_tools)}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "decision": self.decision.value,
            "risk_score": round(self.risk_score, 4),
            "trust_tier": self.trust_tier.value,
            "latency_ms": round(self.latency_ms, 3),
            "detections": [d.to_dict() for d in self.detections],
            "allowed_tools": self.allowed_tools,
            "revoked_tools": self.revoked_tools,
            "transforms": self.normalization.transforms if self.normalization else [],
            "metadata": self.metadata,
        }
