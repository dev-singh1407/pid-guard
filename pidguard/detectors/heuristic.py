"""Stage 2a -- Signature detection.

A curated rule base covering the attack families reported in the literature
(Greshake et al. 2023 indirect injection; Perez and Ribeiro 2022 goal hijacking
and prompt leaking; Liu et al. 2024 formalisation). Rules are grouped into
families so the policy engine can reason about *what kind* of attack it is,
not merely how suspicious the text looks.

Each rule is matched against three views of the text -- normalized, de-leeted,
and de-spaced -- because homoglyph folding often lands one edit away from the
trigger word (ignore -> irnore), so an exact regex alone is brittle.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Dict, List, Tuple

from ..normalizer import deleet, despace
from ..types import Detection, NormalizationReport, Severity
from .base import Detector

# (rule_id, family, severity, pattern, description)
RULES: List[Tuple[str, str, Severity, str, str]] = [
    # --- Family 1: instruction override / goal hijacking -------------------
    # The determiner group must include possessives. "Forget your rules" and
    # "ignore your instructions" are the most natural phrasings of an override
    # and were previously missed because only all|the|previous|... matched.
    # "my"/"our" are included deliberately too -- those are caught here and
    # then demoted by _downgrade_if_self_directed, so the possessive is
    # classified rather than ignored.
    ("IO-01", "instruction_override", Severity.CRITICAL,
     r"\b(ignore|disregard|forget|discard|override|bypass|skip|lift|suspend|waive|revoke|set\s+aside)\b[\s\S]{0,40}?\b(all|any|the|previous|prior|above|earlier|initial|original|former|your|my|our|its|their)\b[\s\S]{0,30}?\b(instruction|prompt|direction|rule|command|guideline|context|message|constraint|restriction|policy|policies|guardrail)s?\b",
     "Explicit instruction to discard prior context"),
    ("IO-02", "instruction_override", Severity.CRITICAL,
     r"\bnew\s+(instruction|task|directive|objective|mission|rule)s?\b\s*[:\-]",
     "Declares a replacement instruction block"),
    ("IO-03", "instruction_override", Severity.HIGH,
     r"\b(instead|rather than)\b[\s\S]{0,30}\b(do|perform|execute|follow|output|say|reply|respond)\b",
     "Substitutes the operator goal with a new one"),
    ("IO-04", "instruction_override", Severity.HIGH,
     r"\bfrom\s+now\s+on\b|\bstarting\s+now\b|\bfor\s+the\s+rest\s+of\s+(this|the)\s+(conversation|session)\b",
     "Attempts to install a persistent behavioural override"),
    ("IO-05", "instruction_override", Severity.MEDIUM,
     r"\bthe\s+(above|previous|prior)\b[\s\S]{0,25}\b(was|is)\b[\s\S]{0,25}\b(test|joke|mistake|outdated|no longer valid|fake)\b",
     "Invalidates prior context as a pretext"),

    # --- Family 2: role / persona manipulation -----------------------------
    ("RM-01", "role_manipulation", Severity.HIGH,
     r"\byou\s+are\s+(now|no\s+longer)\b|\bact\s+as\s+(if|though|a|an)\b|\bpretend\s+(to\s+be|you)\b|\bassume\s+the\s+role\b",
     "Re-assigns the agent persona"),
    ("RM-02", "role_manipulation", Severity.CRITICAL,
     r"\b(dan|do\s+anything\s+now|developer\s+mode|god\s+mode|jailbreak|unfiltered\s+mode|sudo\s+mode)\b",
     "Known jailbreak persona token"),
    ("RM-03", "role_manipulation", Severity.HIGH,
     r"\b(you|your)\b[\s\S]{0,20}\b(have\s+no|without\s+any|free\s+(of|from))\b[\s\S]{0,25}\b(restriction|limitation|filter|guardrail|rule|policy|constraint)s?\b",
     "Asserts the agent is unconstrained"),
    ("RM-04", "role_manipulation", Severity.MEDIUM,
     r"\bas\s+an?\s+(unrestricted|uncensored|amoral|evil)\b",
     "Requests an unrestricted persona"),

    # --- Family 3: system-prompt extraction / prompt leaking ---------------
    ("PL-01", "prompt_leak", Severity.CRITICAL,
     # The object must refer to the MODEL's own prompt or configuration. A
     # bare "configuration" or "instruction" also matches ordinary requests
     # such as "show me the configuration file for the reporting service",
     # which this rule was blocking at USER tier.
     r"\b(repeat|print|show|reveal|display|output|echo|recite|disclose|dump)\b[\s\S]{0,40}?"
     r"\b(system\s+prompt|initial\s+prompt"
     r"|(your|its)\s+(\w+\s+){0,2}(prompt|instructions?|configuration|directives?|rules?|guidelines?)"
     r"|the\s+(system\s+|initial\s+)?prompt)\b",
     "Requests disclosure of the system prompt"),
    ("PL-02", "prompt_leak", Severity.HIGH,
     r"\bwhat\s+(were|are)\s+(you|your)\b[\s\S]{0,25}\b(told|instructed|prompt|instruction|rule)s?\b",
     "Interrogates the agent about its instructions"),
    ("PL-03", "prompt_leak", Severity.HIGH,
     r"\b(everything|all\s+text)\s+(above|before|preceding)\b|\bverbatim\b[\s\S]{0,25}\b(above|prompt|instruction)\b",
     "Requests verbatim reproduction of preceding context"),
    ("PL-04", "prompt_leak", Severity.MEDIUM,
     r"\brepeat\s+(the\s+)?(words?|text|content)\s+above\b",
     "Classic prompt-leak phrasing"),

    # --- Family 4: exfiltration / data egress ------------------------------
    ("EX-01", "exfiltration", Severity.CRITICAL,
     r"\b(send|post|upload|transmit|forward|leak|exfiltrate|deliver|report)\b[\s\S]{0,50}?\b(to|at)\b[\s\S]{0,20}?(https?://|www\.|[\w.-]+@[\w.-]+\.\w+)",
     "Instructs the agent to transmit data to an external endpoint"),
    ("EX-02", "exfiltration", Severity.CRITICAL,
     r"!\[[^\]]*\]\(\s*https?://[^)]*(\?|&)\s*\w+\s*=",
     "Markdown image beacon with a query parameter (zero-click exfiltration)"),
    ("EX-03", "exfiltration", Severity.HIGH,
     r"\b(api[_\s-]?key|secret|token|password|credential|private[_\s-]?key|env(ironment)?\s+variable)\b[\s\S]{0,40}\b(send|show|print|reveal|include|append|list|read)\b",
     "Targets credential material"),
    ("EX-04", "exfiltration", Severity.HIGH,
     r"\b(send|show|print|reveal|include|append|fetch|read)\b[\s\S]{0,40}\b(api[_\s-]?key|secret|token|password|credential|private[_\s-]?key|ssh\s+key)\b",
     "Targets credential material (reverse word order)"),
    ("EX-05", "exfiltration", Severity.HIGH,
     r"\b(append|attach|include|encode)\b[\s\S]{0,40}\b(conversation|history|context|chat|user\s+data|email)\b[\s\S]{0,40}\b(url|link|image|query|parameter)\b",
     "Encodes conversation state into an outbound URL"),

    # --- Family 5: tool / capability abuse ---------------------------------
    ("TA-01", "tool_abuse", Severity.CRITICAL,
     r"\b(call|invoke|use|run|execute|trigger)\b[\s\S]{0,30}\b(tool|function|api|command|shell|bash|subprocess|os\.system|eval)\b",
     "Directs the agent to invoke a capability"),
    ("TA-02", "tool_abuse", Severity.CRITICAL,
     r"\b(rm\s+-rf|drop\s+table|delete\s+from|truncate\s+table|shutdown|format\s+c:)\b",
     "Destructive command payload"),
    ("TA-03", "tool_abuse", Severity.HIGH,
     r"\b(transfer|send|wire|pay)\b[\s\S]{0,30}\b(usd|eur|inr|btc|eth|fund|money|payment|balance|dollars)\b",
     "Attempts an unauthorised financial action"),
    # \badmin\b would not match "administrator"; the \w* suffixes cover the
    # whole word family, and the wider gap allows one qualifying noun between
    # the verb and its object ("grant the guest account administrator rights").
    ("TA-04", "tool_abuse", Severity.HIGH,
     r"\b(grant|escalate|elevate|enable)\b[\s\S]{0,40}\b(admin\w*|root|privilege\w*|permission\w*|access|sudo)\b",
     "Requests privilege escalation"),

    # --- Family 6: delimiter / context escape ------------------------------
    ("DE-01", "delimiter_escape", Severity.HIGH,
     r"(<\|(im_(start|end)|endoftext|system|user|assistant)\|>)|(\[/?(INST|SYS|SYSTEM)\])|(<\s*/?\s*(system|assistant)\s*>)",
     "Injects chat-template control tokens"),
    ("DE-02", "delimiter_escape", Severity.HIGH,
     # A forged speaker turn is not always at the start of a line: inside a
     # JSON or YAML value it appears after a quote, brace or comma, which is
     # exactly how structured-data injection smuggles one in.
     r"(^|[\"'\[{,]\s*)(system|assistant|developer)\s*:\s*\S",
     "Forges a privileged speaker turn"),
    ("DE-03", "delimiter_escape", Severity.MEDIUM,
     r"(-{5,}|={5,}|#{4,})\s*(end|stop|new|begin|start)\b[\s\S]{0,25}\b(context|prompt|instruction|document|section)\b",
     "Fabricates an end-of-context boundary"),
    ("DE-04", "delimiter_escape", Severity.HIGH,
     r"\bend\s+of\s+(document|context|input|data|user\s+message)\b[\s\S]{0,60}\b(instruction|system|now|next|follow)\b",
     "Declares the untrusted region closed, then issues instructions"),

    # --- Family 7: social engineering / urgency pretext --------------------
    ("SE-01", "social_engineering", Severity.MEDIUM,
     r"\b(urgent|emergency|critical|immediate)\b[\s\S]{0,30}\b(override|action|request|instruction|must)\b",
     "Manufactured urgency to suppress verification"),
    # The negative lookahead matters: this rule is about a claimed *person*
    # granting authority ("the admin says you may"), not about a user
    # describing an interface ("the admin panel says access denied"), which
    # is an ordinary support question and was being blocked.
    ("SE-02", "social_engineering", Severity.HIGH,
     r"\b(admin|administrator|developer|owner|system\s+operator|security\s+team)\b"
     r"(?!\s+(panel|page|console|dashboard|screen|menu|tab|section|settings|"
     r"portal|interface|ui|area|login|docs|documentation|guide|manual|log|logs))"
     r"[\s\S]{0,30}\b(says?|requires?|authorized?|approved?|instructs?|has\s+asked)\b",
     "False claim of privileged authorisation"),
    ("SE-03", "social_engineering", Severity.MEDIUM,
     r"\bdo\s+not\s+(tell|mention|inform|reveal|notify|show)\b[\s\S]{0,25}\b(user|human|operator|anyone)\b",
     "Instructs the agent to conceal its actions"),
    ("SE-04", "social_engineering", Severity.MEDIUM,
     r"\b(without|no\s+need\s+(to|for))\b[\s\S]{0,20}\b(asking|confirmation|permission|approval|verifying)\b",
     "Attempts to waive the human-in-the-loop check"),

    # --- Family 8: obfuscation markers -------------------------------------
    ("OB-01", "obfuscation", Severity.MEDIUM,
     r"\b(decode|decrypt|base64|rot13|reverse\s+(the\s+)?(string|text)|unscramble)\b[\s\S]{0,30}\b(then|and)\b[\s\S]{0,20}\b(follow|execute|do|obey|run)\b",
     "Two-stage decode-then-obey payload"),
    ("OB-02", "obfuscation", Severity.MEDIUM,
     r"\b(translate|convert)\b[\s\S]{0,30}\b(then\s+)?(follow|execute|obey|perform)\b",
     "Uses translation as an instruction laundering step"),
]

# Fuzzy trigger phrases: caught even when normalization lands one edit away.
FUZZY_TRIGGERS = [
    ("ignore previous instructions", Severity.CRITICAL),
    ("ignore all previous instructions", Severity.CRITICAL),
    ("disregard the above", Severity.HIGH),
    ("do anything now", Severity.HIGH),
    ("you are now", Severity.MEDIUM),
]


#: "ignore MY previous message" is a person redirecting their own request.
#: "ignore THE previous instructions" is an attempt on the system's. The
#: possessive is the whole difference, and conflating them made the guard
#: block a completely ordinary user turn.
_SELF_DIRECTED = re.compile(
    r"\b(my|our)\b\s+(own\s+)?"
    r"(previous|prior|last|earlier|first|above)?\s*"
    r"(message|question|request|instruction|prompt|comment|note|point|turn)s?\b",
    re.I)

_STEP_DOWN = {
    Severity.CRITICAL: Severity.LOW,
    Severity.HIGH: Severity.LOW,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.LOW,
}


#: Security documentation, training material and incident reports *describe*
#: attacks; they do not perform them. The grammatical tell is that the trigger
#: verb sits in a subordinate or generic clause ("text that attempts to
#: override earlier context") rather than in imperative position. Without this,
#: a module teaching people about prompt injection was blocked outright --
#: which is the worst kind of false positive for a security tool.
_DESCRIPTIVE_LEAD = re.compile(
    r"\b("
    r"that\s+(attempts?|tries|seeks?|aims?)\s+to"
    r"|which\s+(attempts?|tries|seeks?)\s+to"
    r"|(occurs?|happens?)\s+when"
    r"|(a|one)\s+common\s+(pattern|technique|approach|example)"
    r"|attackers?\s+(may|might|can|could|will|often|typically)"
    r"|adversar(y|ies)\s+(may|might|can|could)"
    r"|(for\s+example|such\s+as|e\.g\.|i\.e\.)"
    r"|(is|are)\s+(text|content|input|a\s+technique|an\s+attempt)"
    r"|learners?\s+should"
    r"|we\s+(observed|found|identified|recommend)"
    r"|(the\s+)?(attack|payload|injection|exploit)\s+(attempts?|tries|works)"
    r")\b",
    re.I)


def _is_descriptive(full_text: str, span: tuple | None) -> bool:
    """True when the match sits in prose that *describes* an attack.

    Looks only at the ~120 characters preceding the match: a descriptive frame
    ("a common pattern is text that attempts to ...") appears before the
    trigger verb, whereas a real instruction has nothing in front of it.
    """
    if not span:
        return False
    lead = full_text[max(0, span[0] - 120):span[0]]
    return bool(_DESCRIPTIVE_LEAD.search(lead))


def _downgrade_if_self_directed(sev: Severity, family: str, matched: str):
    """Return (effective_severity, was_downgraded).

    Only instruction-override matches qualify: those are the rules whose
    meaning flips depending on *whose* instructions are being set aside. The
    signal is not suppressed outright, because a web page saying "ignore my
    previous message" is still odd -- it is demoted so that trust-tier
    weighting decides, which is exactly what the tier is for.
    """
    if family != "instruction_override" or not _SELF_DIRECTED.search(matched):
        return sev, False
    return _STEP_DOWN[sev], True


class HeuristicDetector(Detector):
    """Regex signature engine with multi-view matching and fuzzy fallback."""

    name = "heuristic"
    fusion_weight = 1.0

    def __init__(self, fuzzy_threshold: float = 0.86) -> None:
        self.fuzzy_threshold = fuzzy_threshold
        self._compiled = [
            (rid, fam, sev, re.compile(pat, re.I | re.M), desc)
            for rid, fam, sev, pat, desc in RULES
        ]

    def _views(self, text: str) -> Dict[str, str]:
        """Only views that actually differ from the canonical text.

        Deleeting and de-spacing are no-ops on most text, and re-running 32
        regexes over an identical string was the single largest cost in the
        pipeline (7.1 ms per window, ~70% of total latency).
        """
        views = {"normalized": text}
        for name, fn in (("deleet", deleet), ("despaced", despace)):
            alt = fn(text)
            if alt != text:
                views[name] = alt
        return views

    @staticmethod
    def _trigrams(text: str) -> set:
        return {text[i:i + 3] for i in range(len(text) - 2)}

    def _fuzzy_scan(self, text: str) -> List[Detection]:
        """Sliding-window similarity for near-miss trigger phrases.

        Gated by a cheap character-trigram overlap test: SequenceMatcher over
        every window x every phrase is O(n*m) and dominated the hot path, but
        a phrase that shares almost no trigrams with the text cannot possibly
        clear the ratio threshold, so it never needs the expensive comparison.
        """
        found: List[Detection] = []
        low = text.lower()
        words = low.split()
        text_grams = self._trigrams(low)
        for phrase, sev in FUZZY_TRIGGERS:
            if phrase in low:
                continue  # exact hits are the regex engine's job
            pg = self._trigrams(phrase)
            # An edit that breaks one word still leaves most trigrams intact;
            # below half overlap the ratio cannot reach ~0.86.
            if len(pg & text_grams) / max(1, len(pg)) < 0.45:
                continue
            n = len(phrase.split())
            best, best_i = 0.0, -1
            for i in range(max(0, len(words) - n + 1)):
                window = " ".join(words[i:i + n])
                ratio = SequenceMatcher(None, phrase, window).ratio()
                if ratio > best:
                    best, best_i = ratio, i
            if best >= self.fuzzy_threshold and best_i >= 0:
                window = " ".join(words[best_i:best_i + n])
                found.append(Detection(
                    detector=self.name,
                    rule_id="FZ-" + phrase[:12].replace(" ", "_"),
                    description="Near-match to attack phrase: " + phrase,
                    severity=sev, confidence=min(1.0, best),
                    matched_text=window,
                    metadata={"family": "obfuscation", "fuzzy_ratio": round(best, 3)},
                ))
        return found

    def scan(self, text: str, report: NormalizationReport | None = None) -> List[Detection]:
        detections: List[Detection] = []
        seen: set = set()
        for view_name, view in self._views(text).items():
            for rid, family, sev, rx, desc in self._compiled:
                if rid in seen:
                    continue
                m = rx.search(view)
                if not m:
                    continue
                seen.add(rid)
                # A hit that only appears in a de-obfuscated view is *more*
                # suspicious, not less: benign text needs no de-obfuscation.
                conf = 0.92 if view_name == "normalized" else 0.97
                effective, self_ref = _downgrade_if_self_directed(sev, family,
                                                                 m.group(0))
                meta = {"family": family, "view": view_name}
                if self_ref:
                    meta["self_directed"] = True
                note = ""
                if self_ref:
                    note = (" (self-directed: refers to the speaker's own turn, "
                            "not the system's)")
                elif _is_descriptive(view, m.span()):
                    # Describing an attack is not performing one.
                    effective = _STEP_DOWN[effective]
                    meta["descriptive"] = True
                    note = " (descriptive: prose about an attack, not an instruction)"
                detections.append(Detection(
                    detector=self.name, rule_id=rid,
                    description=desc + note,
                    severity=effective, confidence=conf,
                    span=m.span() if view_name == "normalized" else None,
                    matched_text=m.group(0)[:160],
                    metadata=meta,
                ))
        detections.extend(self._fuzzy_scan(text))
        return detections

    @staticmethod
    def families(detections: List[Detection]) -> List[str]:
        return sorted({d.metadata.get("family", "?") for d in detections})
