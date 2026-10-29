"""Windowed scanning -- the answer to signal dilution.

A three-sentence injection hidden in a 4,000-word scraped page is the *normal*
case for indirect prompt injection, and it is exactly the case a whole-document
scorer fails on: every density-based signal (imperative ratio, classifier
probability, cosine similarity) is averaged away by the surrounding benign
prose. Our own first evaluation showed it -- recall on document-embedded
attacks was 43% while recall on the same payloads standalone was 97%.

The fix is to score *windows*, not documents, and take the maximum. An attack
only has to be concentrated somewhere; a benign document is benign everywhere.
Windows overlap by one sentence so a payload split across a boundary is still
seen intact by at least one window.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

# Sentence-ish boundaries, plus the structural boundaries that matter in
# scraped content: line breaks, list bullets, HTML block tags, comment edges.
# Note: every boundary is a lookahead or a FIXED-width lookbehind. Python's
# re rejects variable-width lookbehind, so closing tags are matched with a
# lookahead rather than by looking back past them.
_SPLIT = re.compile(
    r"(?<=[.!?])\s+"
    r"|\n+"
    r"|(?=<!--)|(?<=-->)"
    r"|(?=<\s*/?\s*(?:p|div|br|li|td|h[1-6])\b)",
    re.I,
)

DEFAULT_WINDOW_CHARS = 320
DEFAULT_MIN_UNITS = 1


@dataclass
class Window:
    """One scannable region of a larger document."""

    text: str
    start: int
    end: int
    index: int

    def __len__(self) -> int:
        return len(self.text)


def split_units(text: str) -> List[str]:
    """Break text into atomic units (sentences / lines / block elements)."""
    units = [u for u in _SPLIT.split(text) if u is not None]
    return [u for u in units if u.strip()]


def windows(text: str, window_chars: int = DEFAULT_WINDOW_CHARS,
            overlap_units: int = 1) -> List[Window]:
    """Group units into overlapping windows of at most `window_chars`.

    Windowing is applied to any multi-unit text, not only to long ones. A
    two-sentence injection appended to a 200-character product review is
    still diluted, and skipping the split for "short" documents was measured
    to cost ~50 points of recall on document-embedded attacks.
    """
    units = split_units(text)
    if len(units) <= 1:
        return [Window(text=text, start=0, end=len(text), index=0)]

    out: List[Window] = []
    i = 0
    idx = 0
    cursor = 0          # search offset for locating units in the original text
    while i < len(units):
        chunk: List[str] = []
        size = 0
        j = i
        while j < len(units) and (size + len(units[j]) <= window_chars or not chunk):
            chunk.append(units[j])
            size += len(units[j]) + 1
            j += 1
        joined = " ".join(chunk)
        start = text.find(chunk[0], cursor)
        if start < 0:
            start = cursor
        end = min(len(text), start + len(joined))
        out.append(Window(text=joined, start=start, end=end, index=idx))
        idx += 1
        cursor = start + max(1, len(chunk[0]))
        if j >= len(units):
            break
        # step back `overlap_units` so a payload straddling a boundary is
        # still contained whole in the following window
        i = max(i + 1, j - overlap_units)
    return out


def concentration(window_risks: List[float]) -> float:
    """How localised the risk is: 1.0 = one hot window, 0.0 = uniform.

    A high value is itself evidence of injection -- benign documents do not
    have one paragraph that looks ten times more like a command than the rest.
    """
    if len(window_risks) < 2:
        return 0.0
    top = max(window_risks)
    if top <= 0:
        return 0.0
    rest = [r for r in window_risks]
    rest.remove(top)
    mean_rest = sum(rest) / len(rest)
    return max(0.0, min(1.0, (top - mean_rest) / top))
