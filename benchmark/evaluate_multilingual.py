"""Cross-lingual evaluation, with and without the multilingual detector.

Reports the before/after that motivated the detector, per language, plus the
hard-negative controls that decide whether the lexicon is usable or merely
sensitive.

Run:  python benchmark/evaluate_multilingual.py [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pidguard import PromptInjectionGuard, TrustTier  # noqa: E402
from pidguard.audit import AuditLog  # noqa: E402
from pidguard.detectors import (HeuristicDetector, MultilingualDetector,  # noqa: E402
                                SemanticDetector, StatisticalDetector,
                                StructuralDetector)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data", "corpus_multilingual.jsonl")


def load() -> List[Dict]:
    with open(DATA, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def english_only_ensemble():
    """The ensemble as it was before this work: no multilingual layer."""
    return [HeuristicDetector(), StatisticalDetector(),
            SemanticDetector(), StructuralDetector()]


def full_ensemble():
    return [HeuristicDetector(), MultilingualDetector(), StatisticalDetector(),
            SemanticDetector(), StructuralDetector()]


def run(rows: List[Dict], detectors) -> List[bool]:
    guard = PromptInjectionGuard(detectors=detectors,
                                 audit=AuditLog(max_records=1))
    return [guard.inspect(r["text"], TrustTier.WEB).is_attack for r in rows]


def metrics(rows: List[Dict], preds: List[bool]) -> Dict[str, float]:
    tp = sum(1 for r, p in zip(rows, preds) if r["label"] == 1 and p)
    fn = sum(1 for r, p in zip(rows, preds) if r["label"] == 1 and not p)
    fp = sum(1 for r, p in zip(rows, preds) if r["label"] == 0 and p)
    tn = sum(1 for r, p in zip(rows, preds) if r["label"] == 0 and not p)
    rec = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"recall": rec, "fpr": fpr, "precision": prec, "f1": f1,
            "tp": tp, "fn": fn, "fp": fp, "tn": tn}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write results here")
    args = ap.parse_args()

    rows = load()
    langs = sorted({r["language"] for r in rows})
    n_atk = sum(r["label"] for r in rows)

    print("=" * 78)
    print(f"Cross-lingual evaluation  |  {len(rows)} samples, {len(langs)} languages")
    print(f"{n_atk} attacks / {len(rows) - n_atk} hard negatives  |  tier=web")
    print("=" * 78)

    before = run(rows, english_only_ensemble())
    after = run(rows, full_ensemble())
    m_before, m_after = metrics(rows, before), metrics(rows, after)

    print("\n-- OVERALL -------------------------------------------------------")
    print(f"{'configuration':<34}{'recall':>9}{'FPR':>8}{'F1':>8}")
    print("-" * 60)
    print(f"{'English-only ensemble (before)':<34}{m_before['recall']:>9.3f}"
          f"{m_before['fpr']:>8.3f}{m_before['f1']:>8.3f}")
    print(f"{'+ multilingual detector (after)':<34}{m_after['recall']:>9.3f}"
          f"{m_after['fpr']:>8.3f}{m_after['f1']:>8.3f}")

    print("\n-- RECALL BY LANGUAGE --------------------------------------------")
    print(f"{'language':<14}{'before':>9}{'after':>9}   {'controls kept':>14}")
    print("-" * 60)
    per_lang: Dict[str, Dict] = {}
    for lang in langs:
        idx = [i for i, r in enumerate(rows) if r["language"] == lang]
        atk = [i for i in idx if rows[i]["label"] == 1]
        ctl = [i for i in idx if rows[i]["label"] == 0]
        rb = sum(before[i] for i in atk) / len(atk)
        ra = sum(after[i] for i in atk) / len(atk)
        kept = sum(1 for i in ctl if not after[i])
        per_lang[lang] = {"recall_before": round(rb, 3), "recall_after": round(ra, 3),
                          "controls_total": len(ctl), "controls_kept": kept}
        flag = "" if kept == len(ctl) else "   <-- control blocked"
        print(f"{lang:<14}{rb:>9.3f}{ra:>9.3f}   {kept:>7}/{len(ctl):<6}{flag}")

    print("\n-- RECALL BY FAMILY (after) --------------------------------------")
    fam = defaultdict(lambda: [0, 0])
    for r, p in zip(rows, after):
        if r["label"] == 1:
            fam[r["family"]][1] += 1
            fam[r["family"]][0] += int(p)
    fam_out = {}
    for f, (hit, tot) in sorted(fam.items()):
        fam_out[f] = round(hit / tot, 3)
        print(f"  {f:<24}{hit}/{tot}   {hit / tot:.3f}")

    missed = [(rows[i]["language"], rows[i]["family"], rows[i]["text"][:56])
              for i in range(len(rows)) if rows[i]["label"] == 1 and not after[i]]
    blocked = [(rows[i]["language"], rows[i]["text"][:56])
               for i in range(len(rows)) if rows[i]["label"] == 0 and after[i]]

    print("\n-- MISSED ATTACKS ------------------------------------------------")
    print("  none" if not missed else "")
    for lang, f, t in missed:
        print(f"  {lang:<12}{f:<22}{t!r}")

    print("\n-- BLOCKED CONTROLS (false positives) ----------------------------")
    print("  none" if not blocked else "")
    for lang, t in blocked:
        print(f"  {lang:<12}{t!r}")

    print("\n-- SUMMARY -------------------------------------------------------")
    print(f"  recall, English-only ensemble : {m_before['recall']:.1%}")
    print(f"  recall, with multilingual     : {m_after['recall']:.1%}")
    print(f"  false positives on controls   : {m_after['fp']}/{len(rows) - n_atk}"
          f"  ({m_after['fpr']:.1%})")
    print("=" * 78)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"n_samples": len(rows), "n_attack": n_atk,
                       "languages": langs,
                       "before": m_before, "after": m_after,
                       "per_language": per_lang, "recall_by_family": fam_out,
                       "missed": missed, "blocked_controls": blocked}, fh, indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
