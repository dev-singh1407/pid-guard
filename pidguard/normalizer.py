"""Stage 1 -- Canonicalisation.

Attackers hide instructions from *pattern matchers* while keeping them
readable to the *model*: zero-width joiners between letters, Cyrillic
homoglyphs, base64 blobs, HTML comments, leetspeak. This stage undoes those
tricks so downstream detectors see the same string the model will effectively
see, and records how much undoing was required.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from typing import List

from .types import NormalizationReport

# Format/invisible characters used to break up trigger words.
INVISIBLE = (
    "​‌‍‎‏⁠⁡⁢⁣⁤"
    "﻿­᠎؜⁦⁧⁨⁩‪‫"
    "‬‭‮"
)
_INVISIBLE_RE = re.compile(f"[{INVISIBLE}]")

# Confusable script characters -> ASCII skeleton.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ɡ": "g", "ⅼ": "l",
    "α": "a", "ο": "o", "ρ": "p", "ϲ": "c", "ν": "v", "τ": "t", "κ": "k",
    "Ι": "I", "Ε": "E", "Α": "A", "Ο": "O", "Ρ": "P", "С": "C", "Т": "T",
    "𝗂": "i", "𝖺": "a", "𝗇": "n", "０": "0", "１": "1",
    "г": "r", "м": "m", "н": "h", "в": "b", "к": "k", "п": "n", "и": "u",
    "ѵ": "v", "ԛ": "q", "ѡ": "w", "ᴜ": "u", "ʟ": "l", "ɑ": "a", "ɛ": "e",
    "ᴏ": "o", "ѐ": "e", "ї": "i", "ǥ": "g", "ｌ": "l", "Ѕ": "S", "Ν": "N",
    "Μ": "M", "Η": "H", "Κ": "K", "Β": "B", "Χ": "X", "Υ": "Y", "Ζ": "Z",
}

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

_B64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b")
_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}[\s:]?){12,}\b")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_MD_HIDDEN_RE = re.compile(r"\[[^\]]*\]\(#[^)]*\)|<span[^>]*display\s*:\s*none[^>]*>(.*?)</span>", re.I | re.DOTALL)
_URL_ENC_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
_WS_RE = re.compile(r"[ \t  - ]{2,}")


_TOKEN_SPLIT = re.compile(r"(\w+)", re.UNICODE)


def _is_latin(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z")


def _fold_homoglyphs(text: str) -> tuple:
    """Return (folded_text, n_folded, variants).

    Mixed-script tokens are folded in place -- that is the attack. Wholly
    non-Latin tokens are preserved, and when they contain confusables their
    folded reading is returned separately as an extra view.
    """
    folded_total = 0
    variants: List[str] = []
    out: List[str] = []

    for part in _TOKEN_SPLIT.split(text):
        if not part or not part.isalnum():
            out.append(part)
            continue
        confusables = sum(1 for ch in part if ch in HOMOGLYPHS)
        if not confusables:
            out.append(part)
            continue
        has_latin = any(_is_latin(ch) for ch in part)
        skeleton = "".join(HOMOGLYPHS.get(ch, ch) for ch in part)
        if has_latin:
            # Mixed script: unambiguously an evasion attempt.
            out.append(skeleton)
            folded_total += confusables
        else:
            # Wholly non-Latin: keep it, but offer the transliteration too.
            out.append(part)
            if skeleton != part and any(_is_latin(ch) for ch in skeleton):
                variants.append(skeleton)
    return "".join(out), folded_total, variants


def _try_base64(blob: str) -> str | None:
    try:
        pad = "=" * (-len(blob) % 4)
        raw = base64.b64decode(blob + pad, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(c.isprintable() or c.isspace() for c in text)
    if not text or printable / len(text) < 0.85 or len(text) < 8:
        return None
    return text


def _try_hex(blob: str) -> str | None:
    cleaned = re.sub(r"[\s:]", "", blob)
    if len(cleaned) % 2 or len(cleaned) < 24:
        return None
    try:
        text = bytes.fromhex(cleaned).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if sum(c.isprintable() or c.isspace() for c in text) / len(text) < 0.85:
        return None
    return text


#: High-frequency English function words. Present in almost any real sentence
#: and absent from ROT13 ciphertext, which makes their count a cheap and
#: robust "is this English" signal.
_COMMON_EN = frozenset("""
the be to of and a in that have i it for not on with he as you do at this but
his by from they we say her she or an will my one all would there their what
so up out if about who get which go me when make can like time no just him
know take people into year your good some could them see other than then now
look only come its over think also back after use two how our work first well
way even new want because any these give day most us is are was were been has
had does did should must may might shall please your you're yours
""".split())

_LETTERS = re.compile(r"[A-Za-z']+")


def _englishness(text: str) -> float:
    """Fraction of tokens that are common English function words."""
    words = [w.lower() for w in _LETTERS.findall(text)]
    if len(words) < 4:
        return 0.0
    return sum(1 for w in words if w in _COMMON_EN) / len(words)


_ROT13_HINT = re.compile(r"\brot[\s\-_]?13\b", re.I)


def _try_rot13(text: str) -> str | None:
    """Decode ROT13 when the result is plausibly English.

    The previous version only decoded if the plaintext happened to contain one
    of five hardcoded keywords. Our adaptive-adversary search drove a truck
    through that: ROT13 wrapping alone accounted for 41 of 47 successful
    evasions, because any payload phrased without those exact words sailed
    through unexamined.

    A keyword list cannot work here -- the attacker chooses the words. What the
    attacker cannot avoid is that their plaintext has to be readable language,
    while the ciphertext is not. So we compare how English-like each side is,
    and additionally always decode when the text itself names the cipher.
    """
    before = _englishness(text)
    if before > 0.18 and not _ROT13_HINT.search(text):
        # Already plainly English; ROT13 of it would be noise. Skipping here
        # keeps the check off the hot path for the common case.
        return None
    candidate = codecs.encode(text, "rot_13")
    if _ROT13_HINT.search(text):
        # The payload tells the model to apply ROT13; take it at its word.
        return candidate
    after = _englishness(candidate)
    # Require a clear margin so ordinary prose is never "decoded" into noise.
    if after > 0.12 and after > before * 2.0:
        return candidate
    return None


def normalize(text: str, unwrap_encodings: bool = True) -> NormalizationReport:
    """Return canonical text plus a report of every transform applied."""
    report = NormalizationReport(original=text, normalized=text)
    work = text

    # 1. Strip invisible / bidi control characters.
    invisible_hits = _INVISIBLE_RE.findall(work)
    if invisible_hits:
        work = _INVISIBLE_RE.sub("", work)
        report.invisible_chars_removed = len(invisible_hits)
        report.transforms.append(f"stripped {len(invisible_hits)} invisible/bidi chars")

    # 2. Unicode compatibility fold (handles fullwidth, math-alphanumerics, ligatures).
    folded = unicodedata.normalize("NFKC", work)
    if folded != work:
        report.transforms.append("NFKC compatibility normalization")
        work = folded

    # 3. Homoglyph skeleton -- per token, not per character.
    #
    #    Folding every confusable character everywhere destroys legitimate
    #    non-Latin text: Russian "Игнорируй" became "Urhopupyй", so a genuine
    #    Russian injection was unreadable to every downstream detector and
    #    scored 0.224. The homoglyph *attack* is a mixed-script token -- Latin
    #    letters with a few lookalikes substituted in ("Ignоre"). A token that
    #    is wholly non-Latin is ordinary foreign text and must survive intact.
    #
    #    A token that is wholly confusable is ambiguous: it could be Cyrillic
    #    prose or a fully-disguised English word. Those are not folded in
    #    place; the folded form is appended as an extra view so detectors see
    #    both readings and neither language is lost.
    work, homo, variants = _fold_homoglyphs(work)
    if homo:
        report.homoglyphs_folded = homo
        report.transforms.append(f"folded {homo} homoglyph(s) in mixed-script tokens")
    if variants:
        report.script_variants = variants
        report.transforms.append(
            f"added {len(variants)} transliterated variant(s) of non-Latin tokens")
        # Appended immediately, from the local list rather than via the report,
        # so a wholly-Cyrillic disguise of an English instruction is readable to
        # the English rule base while the original foreign text stays intact.
        work = work + "\n" + " ".join(variants)

    # 4. Reveal text hidden from human readers but visible to the model.
    hidden = _HTML_COMMENT_RE.findall(work)
    if hidden:
        work = _HTML_COMMENT_RE.sub(lambda m: " " + m.group(1) + " ", work)
        report.transforms.append(f"revealed {len(hidden)} HTML comment(s)")
        # Hoist the concealed text onto its own line as well. The segmenter
        # splits on newlines, so the hidden content becomes its own scan
        # window and is scored on its own merits instead of being averaged
        # into the visible page around it. Our adaptive adversary evaded in a
        # single mutation by wrapping a payload in <!-- -->: inline, the
        # revealed instruction was diluted by the surrounding markup. This
        # fixes that without penalising ordinary layout comments, because a
        # benign comment scored undiluted is still benign.
        substantive = [h.strip() for h in hidden if len(h.strip()) >= 12]
        if substantive:
            work = work + "\n" + "\n".join(substantive)
    if _MD_HIDDEN_RE.search(work):
        report.transforms.append("revealed hidden markdown/CSS span")
        work = _MD_HIDDEN_RE.sub(lambda m: " " + (m.group(1) or "") + " ", work)

    # 5. Unwrap encoded payloads and append them so detectors can read them.
    if unwrap_encodings:
        for blob in set(_B64_RE.findall(work)):
            decoded = _try_base64(blob)
            if decoded:
                report.decoded_payloads.append(decoded)
                report.transforms.append("decoded base64 payload")
        for blob in set(_HEX_RE.findall(work)):
            decoded = _try_hex(blob)
            if decoded:
                report.decoded_payloads.append(decoded)
                report.transforms.append("decoded hex payload")
        if _URL_ENC_RE.search(work):
            from urllib.parse import unquote
            decoded = unquote(work)
            if decoded != work:
                report.decoded_payloads.append(decoded)
                report.transforms.append("decoded percent-encoding")
        rot = _try_rot13(work)
        if rot:
            report.decoded_payloads.append(rot)
            report.transforms.append("decoded ROT13 payload")
        if report.decoded_payloads:
            work = work + "\n" + "\n".join(report.decoded_payloads)

    # 6. Collapse padding whitespace used to push instructions off-screen.
    collapsed = _WS_RE.sub(" ", work)
    if collapsed != work:
        report.transforms.append("collapsed padding whitespace")
        work = collapsed

    report.normalized = work.strip()
    return report


def deleet(text: str) -> str:
    """Secondary view used only by the signature detector (1gn0re -> ignore)."""
    return text.translate(LEET)


def despace(text: str) -> str:
    """Collapse i g n o r e -> ignore for spaced-out evasion."""
    # The trailing (?![A-Za-z]) matters: without it the run greedily swallows
    # the first letter of the next real word ("G r a n t the" -> "Grantt he").
    return re.sub(r"(?<![A-Za-z])(?:[A-Za-z][ .\-_*]{1,2}){2,}[A-Za-z](?![A-Za-z])",
                  lambda m: re.sub(r"[\s.\-_*]", "", m.group(0)), text)
