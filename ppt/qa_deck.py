"""Geometric QA for the generated deck.

LibreOffice is not available in this environment, so slides cannot be
rasterised for visual inspection. This checks the defects that a render would
have surfaced, analytically:

  * shapes outside the slide, or inside the 0.5" margin
  * estimated text overflow (wrapped line count x line height vs box height)
  * overlapping text frames

Text metrics are estimates -- average glyph width per point size -- so the
overflow check is a screen, not a proof. Anything it flags gets looked at.

Run:  python ppt/qa_deck.py [deck.pptx]
"""

from __future__ import annotations

import sys
from pptx import Presentation
from pptx.util import Emu

EMU = 914400.0
MARGIN = 0.5

# Average advance width as a fraction of font size, per family.
WIDTH_FACTOR = {"Cambria": 0.50, "Calibri": 0.48, "Courier New": 0.60, "Arial": 0.52}
LINE_FACTOR = 1.22          # line height as a multiple of font size


def in_(v) -> float:
    return (v or 0) / EMU


def est_lines(text: str, width_in: float, font_pt: float, face: str) -> int:
    if not text.strip() or width_in <= 0:
        return 0
    cpl = max(1, int(width_in * 72.0 / (font_pt * WIDTH_FACTOR.get(face, 0.50))))
    lines = 0
    for para in text.split("\n"):
        lines += max(1, -(-len(para) // cpl))     # ceil division
    return lines


def frames(slide):
    out = []
    for sh in slide.shapes:
        if not sh.has_text_frame:
            continue
        text = sh.text_frame.text
        if not text.strip():
            continue
        # Take the max of the sizes actually set. Seeding this at 12.0 (as an
        # earlier version did) floors every box at 12pt and reports phantom
        # overflow on any text deliberately set smaller.
        sizes, face = [], "Calibri"
        for para in sh.text_frame.paragraphs:
            for run in para.runs:
                if run.font.size:
                    sizes.append(run.font.size.pt)
                if run.font.name:
                    face = run.font.name
        size = max(sizes) if sizes else 12.0
        out.append({"shape": sh, "text": text, "size": size, "face": face,
                    "x": in_(sh.left), "y": in_(sh.top),
                    "w": in_(sh.width), "h": in_(sh.height)})
    return out


def overlap(a, b) -> float:
    dx = min(a["x"] + a["w"], b["x"] + b["w"]) - max(a["x"], b["x"])
    dy = min(a["y"] + a["h"], b["y"] + b["h"]) - max(a["y"], b["y"])
    return dx * dy if dx > 0 and dy > 0 else 0.0


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "ppt/Prompt_Injection_Defense_LLM_Agents.pptx"
    prs = Presentation(path)
    SW, SH = in_(prs.slide_width), in_(prs.slide_height)
    print(f"deck: {path}\nslide size: {SW:.2f} x {SH:.2f} in, {len(prs.slides.__iter__.__self__._sldIdLst)} slides\n")

    issues = 0
    for idx, slide in enumerate(prs.slides, 1):
        problems = []
        for sh in slide.shapes:
            x, y, w, h = in_(sh.left), in_(sh.top), in_(sh.width), in_(sh.height)
            if x < -0.01 or y < -0.01 or x + w > SW + 0.01 or y + h > SH + 0.01:
                problems.append(f"OFF-SLIDE  {sh.shape_type} at "
                                f"({x:.2f},{y:.2f}) {w:.2f}x{h:.2f}")

        fr = frames(slide)
        for f in fr:
            if f["x"] < MARGIN - 0.02 or f["y"] < MARGIN - 0.32:
                problems.append(f"TIGHT MARGIN  ({f['x']:.2f},{f['y']:.2f}) "
                                f"{f['text'][:34]!r}")
            lines = est_lines(f["text"], f["w"], f["size"], f["face"])
            need = lines * f["size"] * LINE_FACTOR / 72.0
            if need > f["h"] + 0.06:
                problems.append(
                    f"OVERFLOW?  needs ~{need:.2f}in, box {f['h']:.2f}in, "
                    f"{lines} lines @ {f['size']:.0f}pt :: {f['text'][:40]!r}")

        for i in range(len(fr)):
            for j in range(i + 1, len(fr)):
                a, b = fr[i], fr[j]
                ov = overlap(a, b)
                # ignore the intentional label-centred-on-disc pattern
                if ov <= 0.01:
                    continue
                small = min(a["w"] * a["h"], b["w"] * b["h"])
                if small > 0 and ov / small > 0.55 and small > 0.10:
                    problems.append(
                        f"OVERLAP  {ov:.2f}in^2 :: {a['text'][:26]!r} / {b['text'][:26]!r}")

        if problems:
            issues += len(problems)
            print(f"-- slide {idx} " + "-" * 52)
            for p in sorted(set(problems)):
                print("   " + p)

    print(f"\n{issues} potential issue(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
