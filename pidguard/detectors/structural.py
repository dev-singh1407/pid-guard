"""Stage 2d -- Structural / stylometric anomaly detection.

Content-blind by design. It never asks "does this say something bad"; it asks
"does this text behave like data, or like a command aimed at an agent". That
makes it the layer most likely to survive an attacker who paraphrases past the
signature and learned detectors, and the one that catches novel payloads whose
wording nobody has seen before.

Signals: obfuscation pressure carried over from normalization, imperative
density, second-person addressing, instruction-block structure, hidden
channels, and outbound-URL shape.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import List

from ..types import Detection, NormalizationReport, Severity
from .base import Detector

IMPERATIVE_VERBS = {
    "ignore", "disregard", "forget", "override", "bypass", "reveal", "print",
    "output", "execute", "run", "call", "invoke", "send", "post", "upload",
    "delete", "drop", "grant", "escalate", "repeat", "echo", "disclose",
    "pretend", "act", "assume", "follow", "obey", "comply", "stop", "skip",
    "transfer", "email", "fetch", "download", "install", "enable", "disable",
}
SECOND_PERSON = {"you", "your", "yours", "yourself"}
#: True obligation modals only. Bare "have" and "need" are excluded because
#: they are ordinary verbs -- "if you have questions" is not an obligation --
#: and the "have to" / "need to" constructions are matched as bigrams instead.
#: "now" and "immediately" are urgency adverbs, not obligations, and belong to
#: the social-engineering signature rules rather than here.
MODALS = {"must", "should", "shall", "required", "obliged", "supposed", "mandatory"}
#: Second word of a two-word obligation, when preceded by have/need/ought.
_PERIPHRASTIC = {"have", "need", "ought", "has"}

_SENT_SPLIT = re.compile(r"[.!?\n]+")
_WORD = re.compile(r"[A-Za-z']+")
_URL = re.compile(r"https?://[^\s<>\"')]+")
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]+\)")
_CODEFENCE = re.compile(r"```")


#: Tokens that open a clause, so a command verb following one is imperative.
_CLAUSE_OPENERS = {"and", "then", "or", "also", "now", "please", "next",
                   "instead", "first", "finally", "immediately"}
_CLAUSE_BREAK = set(".!?;:,\n-*>)]}|")


def count_imperatives(text: str) -> int:
    """Count command verbs used as commands, not as nouns.

    "Send the key to..." is an imperative. "You will receive an email" is not,
    even though `email` is in the verb list. The discriminator is position: an
    English imperative opens its clause, so a verb only counts when it is the
    first word, follows clause-terminating punctuation, or follows a
    conjunction / discourse marker.
    """
    tokens = re.findall(r"[A-Za-z']+|[^\sA-Za-z']", text)
    count = 0
    clause_start = True
    for tok in tokens:
        if not tok[0].isalpha():
            if tok in _CLAUSE_BREAK:
                clause_start = True
            continue
        low = tok.lower()
        if clause_start and low in IMPERATIVE_VERBS:
            count += 1
        # A discourse marker keeps the next word in clause-initial position;
        # any other word ends it.
        clause_start = low in _CLAUSE_OPENERS
    return count


def count_directed_obligations(words: List[str], window: int = 3) -> int:
    """Count "you must" / "your ... should" style constructions.

    An obligation only counts when a modal follows a second-person pronoun
    within a few tokens, i.e. the obligation is placed *on the reader*. This
    is what distinguishes "you must transmit the key" from "no action is
    required from you".
    """
    count = 0
    for i, w in enumerate(words):
        if w not in SECOND_PERSON:
            continue
        for j in range(i + 1, min(len(words), i + 1 + window)):
            # "you must", "you are required"
            if words[j] in MODALS:
                count += 1
                break
            # "you have to", "you need to" -- obligation only with the "to"
            if (words[j] in _PERIPHRASTIC
                    and j + 1 < len(words) and words[j + 1] == "to"):
                count += 1
                break
    return count


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class StructuralDetector(Detector):
    """Content-agnostic signals that text is addressing the agent itself."""

    name = "structural"
    fusion_weight = 0.85

    def __init__(self, imperative_threshold: float = 0.075) -> None:
        self.imperative_threshold = imperative_threshold

    def scan(self, text: str, report: NormalizationReport | None = None) -> List[Detection]:
        out: List[Detection] = []
        if not text.strip():
            return out
        words = [w.lower() for w in _WORD.findall(text)]
        n_words = len(words) or 1

        # 1. Obfuscation pressure inherited from the normalizer.
        if report is not None and report.obfuscation_pressure > 0.15:
            p = report.obfuscation_pressure
            sev = (Severity.HIGH if p >= 0.5 else
                   Severity.MEDIUM if p >= 0.3 else Severity.LOW)
            out.append(Detection(
                detector=self.name, rule_id="ST-01",
                description=("Text required de-obfuscation to become readable: "
                             + "; ".join(report.transforms[:4])),
                severity=sev, confidence=min(1.0, 0.55 + p * 0.45),
                metadata={"family": "obfuscation", "pressure": round(p, 3)},
            ))

        # 2. Imperative density -- documents describe, injections command.
        #    Position matters: many of these words are also ordinary nouns
        #    ("you will receive an email", "the call was logged", "a clean
        #    run"). Counting every occurrence made a benign support page look
        #    like a command block. An English imperative is clause-initial, so
        #    only count a verb that opens a clause.
        imperatives = count_imperatives(text)
        density = imperatives / n_words
        if density >= self.imperative_threshold and imperatives >= 2:
            out.append(Detection(
                detector=self.name, rule_id="ST-02",
                description=(f"High imperative-verb density ({density:.1%}, "
                             f"{imperatives} command verbs)"),
                severity=Severity.MEDIUM if density < 0.14 else Severity.HIGH,
                confidence=min(0.95, 0.45 + density * 3.0),
                metadata={"family": "instruction_shape", "density": round(density, 4)},
            ))

        # 3. Second-person addressing combined with modal obligation. Retrieved
        #    documents rarely tell "you" what you "must" do.
        #    Adjacency is required, not mere co-occurrence: an ordinary email
        #    ("No action is required from you. Please contact the service desk
        #    if you have questions.") contains both a second-person pronoun and
        #    a modal, but never as "you must". Counting them separately made
        #    routine correspondence look like a command block.
        sp = sum(1 for w in words if w in SECOND_PERSON)
        directed = count_directed_obligations(words)
        if directed >= 1 and sp >= 2 and n_words < 400:
            ratio = (sp + directed) / n_words
            out.append(Detection(
                detector=self.name, rule_id="ST-03",
                description=(f"Directly addresses the agent with obligation language "
                             f"({sp} second-person, {directed} directed obligation(s))"),
                severity=Severity.MEDIUM,
                confidence=min(0.9, 0.4 + ratio * 4.0),
                metadata={"family": "instruction_shape"},
            ))

        # 4. Instruction-block structure: an imperative-heavy region fenced off
        #    from the surrounding prose by rules, headers or code fences.
        sentences = [s.strip() for s in _SENT_SPLIT.split(text) if s.strip()]
        fenced = bool(_CODEFENCE.search(text)) or bool(re.search(r"^\s*(-{3,}|={3,}|#{2,})", text, re.M))
        imperative_sentences = sum(1 for s in sentences if count_imperatives(s))
        if fenced and imperative_sentences >= 1:
            out.append(Detection(
                detector=self.name, rule_id="ST-04",
                description=("Fenced or delimited block containing "
                             f"{imperative_sentences} imperative sentence(s)"),
                severity=Severity.MEDIUM, confidence=0.6,
                metadata={"family": "delimiter_escape"},
            ))

        # 5. Outbound channel shape: URL carrying parameters, or an image the
        #    renderer will fetch without a click.
        images = _MD_IMAGE.findall(text)
        urls = _URL.findall(text)
        param_urls = [u for u in urls if "?" in u or "=" in u]
        if images and any("?" in i or "=" in i for i in images):
            out.append(Detection(
                detector=self.name, rule_id="ST-05",
                description="Auto-fetched image URL carries query parameters (exfiltration channel)",
                severity=Severity.HIGH, confidence=0.75,
                matched_text=images[0][:120],
                metadata={"family": "exfiltration"},
            ))
        elif param_urls and imperatives >= 1:
            out.append(Detection(
                detector=self.name, rule_id="ST-06",
                description="Parameterised outbound URL appears alongside command verbs",
                severity=Severity.MEDIUM, confidence=0.6,
                matched_text=param_urls[0][:120],
                metadata={"family": "exfiltration"},
            ))

        # 6. High-entropy blob: encoded payload that survived decoding attempts.
        for token in re.findall(r"\S{40,}", text):
            if shannon_entropy(token) > 4.6 and not token.startswith("http"):
                out.append(Detection(
                    detector=self.name, rule_id="ST-07",
                    description=(f"High-entropy token ({shannon_entropy(token):.2f} bits/char) "
                                 "consistent with an encoded payload"),
                    severity=Severity.LOW, confidence=0.5,
                    matched_text=token[:80],
                    metadata={"family": "obfuscation"},
                ))
                break

        return out
