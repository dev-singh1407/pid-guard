"""Stage 3 -- Risk fusion and policy decision.

Fusion, not voting. Each detector returns evidence with a severity and a
confidence; the engine combines them with a noisy-OR so that several
independent weak signals can add up to a decision, while one detector cannot
be trivially saturated by repeating the same match.

The trust tier then scales the fused score: identical text is treated
differently depending on whether the operator typed it or a scraped web page
supplied it. That asymmetry is the whole point -- a user may legitimately ask
"ignore my previous message", a web page never may.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence

from . import config as _config
from .types import Decision, Detection, Severity, TrustTier

# Families whose presence should gate specific capabilities even when the
# fused score alone would not block. Defence in depth: if the text merely
# *mentions* wiring money, the payments tool comes off the table.
FAMILY_TOOL_GATES: Dict[str, Sequence[str]] = {
    "exfiltration": ("http_request", "send_email", "browser", "webhook", "upload_file"),
    "tool_abuse": ("shell", "execute_sql", "wire_transfer", "delete_records", "deploy"),
    "prompt_leak": ("read_config", "read_file", "dump_context"),
    "instruction_override": ("shell", "execute_sql", "wire_transfer", "delete_records"),
    "delimiter_escape": ("shell", "execute_sql", "wire_transfer"),
}


@dataclass
class PolicyConfig:
    """Operating point of the middleware. Tuned on the validation split."""

    sanitize_threshold: float = field(
        default_factory=lambda: _config.get("sanitize_threshold"))
    block_threshold: float = field(
        default_factory=lambda: _config.get("block_threshold"))
    #: any single detection at or above this severity blocks outright
    hard_block_severity: Severity = Severity.CRITICAL
    #: a CRITICAL from the rule base blocks only if confidence clears this
    hard_block_confidence: float = 0.90
    #: detectors whose evidence is treated as fusion input, with weights
    detector_weights: Dict[str, float] = field(default_factory=lambda: {
        "heuristic": 1.00,
        "multilingual": 1.00,
        "statistical": 1.10,
        "semantic": 0.90,
        "structural": 0.85,
    })
    #: cap on how much one detector can contribute, so no single noisy
    #: detector can drive the decision on its own
    per_detector_cap: float = 0.80
    #: tools this agent is allowed to use before any gating is applied
    default_tools: Sequence[str] = ()
    #: when True, SYSTEM-tier text is never inspected (saves latency)
    trust_system_tier: bool = True
    #: Multiple-comparisons correction for windowed scanning.
    #: Taking the MAX risk over N windows inflates document-level false
    #: positives with N: a 4,000-character benign page offers ~20 independent
    #: chances to trip a threshold that was calibrated on single snippets. We
    #: measured this -- FPR on benign documents rose from 8% at 0 filler
    #: characters to 92-100% at 4,000. Both decision thresholds are therefore
    #: inflated by (1 + window_penalty * log2(N)), the discrete analogue of a
    #: Bonferroni correction, which holds document-level FPR roughly flat in
    #: document length instead of letting it grow with it.
    window_penalty: float = field(
        default_factory=lambda: _config.get("window_penalty"))
    #: Corroboration requirement for evidence-free detectors.
    #: Measured on the dilution study: the signature rules have 0.0% FPR, and
    #: essentially every false positive we recorded came from the learned
    #: classifier firing alone on long benign prose it never saw in training.
    #: So a lone non-signature detector is discounted hard -- it may raise
    #: suspicion but it may not carry a decision by itself. The rule base is
    #: exempt: a CRITICAL signature hit is precise enough to stand alone.
    solo_penalty: float = field(
        default_factory=lambda: _config.get("solo_penalty"))
    #: minimum weighted evidence score before a detection may revoke a tool
    gate_min_score: float = 0.35


def _noisy_or(scores: Iterable[float]) -> float:
    """P(at least one signal is real), assuming rough independence."""
    prod = 1.0
    for s in scores:
        prod *= (1.0 - max(0.0, min(1.0, s)))
    return 1.0 - prod


class PolicyEngine:
    """Turns a bag of Detections into a Decision plus a capability set."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()

    # ---------------------------------------------------------- scoring ----
    def fuse(self, detections: Sequence[Detection], tier: TrustTier) -> float:
        if not detections:
            return 0.0
        cfg = self.config
        by_detector: Dict[str, List[float]] = {}
        for d in detections:
            by_detector.setdefault(d.detector, []).append(d.weighted_score)

        per_detector: List[float] = []
        for name, scores in by_detector.items():
            weight = cfg.detector_weights.get(name, 1.0)
            # within a detector: noisy-OR, then cap, then weight
            combined = min(cfg.per_detector_cap, _noisy_or(scores))
            per_detector.append(min(1.0, combined * weight))

        fused = _noisy_or(per_detector)

        # Agreement bonus: independent detector families concurring is the
        # strongest evidence we have, and it is what separates a real attack
        # from one noisy regex.
        if len(by_detector) >= 3:
            fused = min(1.0, fused * 1.12)
        elif len(by_detector) == 1:
            solo = next(iter(by_detector))
            fused *= (0.88 if solo in ("heuristic", "multilingual")
                      else cfg.solo_penalty)

        return min(1.0, fused * tier.weight)

    # --------------------------------------------------------- decision ----
    def decide(self, detections: Sequence[Detection], tier: TrustTier,
               risk_multiplier: float = 1.0, n_windows: int = 1,
               concentration: float = 0.0) -> tuple:
        """Return (Decision, risk_score).

        `risk_multiplier` folds in document-level evidence no single detector
        can see (the risk-concentration bonus). `n_windows` and
        `concentration` drive the
        multiple-comparisons correction described on PolicyConfig.
        """
        cfg = self.config
        if tier is TrustTier.SYSTEM and cfg.trust_system_tier:
            return Decision.ALLOW, 0.0

        risk = min(1.0, self.fuse(detections, tier) * risk_multiplier)

        # Hard block: an unambiguous critical signature from an untrusted
        # channel does not need corroboration. Signature rules measured 0.0
        # FPR, so they are exempt from the multiple-comparisons correction.
        if tier is not TrustTier.USER:
            for d in detections:
                if (d.severity is Severity.CRITICAL
                        and d.confidence >= cfg.hard_block_confidence
                        and d.detector in ("heuristic", "multilingual")):
                    return Decision.BLOCK, max(risk, 0.9)

        # Multiple-comparisons correction, damped by how concentrated the risk
        # is.
        #
        # The plain correction was an attack surface. Our adaptive-adversary
        # search found that padding a payload with benign prose was the single
        # most potent evasion operator: more filler means more windows, more
        # windows means a higher threshold, so the attacker buys leniency by
        # the paragraph.
        #
        # The resolution is that the two cases look different. A long *benign*
        # document is uniformly mildly suspicious -- low concentration -- and
        # genuinely needs the correction, because it really is N independent
        # chances to trip. A padded *attack* has one hot window surrounded by
        # nothing -- high concentration -- and needs no correction at all; the
        # dilution is itself the evidence. So the correction is scaled by
        # (1 - concentration), which keeps the false-positive benefit on prose
        # while removing the discount the attacker was buying.
        conc = max(0.0, min(1.0, concentration))
        inflation = 1.0 + cfg.window_penalty * math.log2(max(1, n_windows)) * (1.0 - conc)
        block_at = min(0.97, cfg.block_threshold * inflation)
        sanitize_at = min(0.90, cfg.sanitize_threshold * inflation)

        if risk >= block_at:
            return Decision.BLOCK, risk
        if risk >= sanitize_at:
            return Decision.SANITIZE, risk
        return Decision.ALLOW, risk

    # -------------------------------------------------- capability gate ----
    def gate_tools(self, detections: Sequence[Detection],
                   available_tools: Sequence[str] | None = None) -> tuple:
        """Return (allowed_tools, revoked_tools) for this turn.

        Least privilege applied per-turn: an agent that just read a page
        containing exfiltration language keeps its summarisation ability but
        loses its network egress until the turn ends.
        """
        tools = list(available_tools if available_tools is not None
                     else self.config.default_tools)
        if not tools:
            return [], []
        # Only evidence that actually carries weight may revoke a capability.
        # Without this floor, the semantic detector's *nearest-neighbour
        # family* gated tools on pages the policy had already decided to
        # ALLOW -- a benign support page lost its network egress because one
        # sentence was weakly nearest to a tool_abuse exemplar. Gating is a
        # real cost to the user, so it needs real evidence.
        families = {d.metadata.get("family") for d in detections
                    if d.weighted_score >= self.config.gate_min_score}
        revoked: set = set()
        for family in families:
            for tool in FAMILY_TOOL_GATES.get(family or "", ()):
                if tool in tools:
                    revoked.add(tool)
        allowed = [t for t in tools if t not in revoked]
        return allowed, sorted(revoked)
