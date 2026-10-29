"""Controlled dilution study: how does detection decay as the host document
grows around a fixed payload?

Why this exists. The window-size parameter could not be chosen from the
validation split -- validation F1 saturates at ~0.99 and every setting ties.
Rather than resolve the tie by peeking at the test split, this script measures
the mechanism directly, using training data only: one attack payload is
embedded in benign filler of increasing length, and recall is plotted against
filler length for each window size.

That turns a hyperparameter choice into a controlled experiment on the exact
failure mode the parameter exists to address.

Run:  python benchmark/dilution.py [--json results.json]
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pidguard import PromptInjectionGuard, TrustTier  # noqa: E402
from pidguard.audit import AuditLog  # noqa: E402
from pidguard.policy import PolicyConfig  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN_FILE = os.path.join(ROOT, "data", "corpus_train.jsonl")

FILLER_LENGTHS = [0, 250, 500, 1000, 2000, 4000]
WINDOW_SETTINGS = [("120", 120), ("220", 220), ("320", 320), ("no-window", 10 ** 6)]
#: strengths of the multiple-comparisons correction to compare
PENALTIES = [0.0, 0.06, 0.12, 0.20]

PROSE_FILE = os.path.join(ROOT, "data", "prose_filler.txt")


def load_prose() -> List[str]:
    """Realistic benign document prose for the filler.

    Deliberately NOT the benign user-request seeds: fifty stacked imperatives
    is not a benign document, it is structurally an injection, and using them
    as filler made the control arm adversarial against our own structural
    detector. See the header of data/prose_filler.txt.
    """
    with open(PROSE_FILE, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh
                if ln.strip() and not ln.lstrip().startswith("#")]



def load(path: str) -> List[Dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def build_filler(benign_sentences: List[str], target_chars: int,
                 rng: random.Random) -> str:
    if target_chars <= 0:
        return ""
    out: List[str] = []
    size = 0
    while size < target_chars:
        s = rng.choice(benign_sentences)
        out.append(s)
        size += len(s) + 1
    return " ".join(out)[:target_chars]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write results here")
    args = ap.parse_args()

    rows = load(TRAIN_FILE)
    payloads = [r for r in rows if r["label"] == 1 and r["variant"] == "plain"]
    benign_sentences = [r["text"] for r in rows
                        if r["label"] == 0 and r["variant"] == "plain"]
    prose = load_prose()          # filler must be document prose, not requests
    rng = random.Random(99)

    print("=" * 76)
    print("Dilution study -- recall vs. host-document length (training data only)")
    print(f"{len(payloads)} payloads x {len(FILLER_LENGTHS)} filler lengths "
          f"x {len(WINDOW_SETTINGS)} window settings")
    print("=" * 76)
    header = "filler chars ".ljust(16) + "".join(f"{name:>12}" for name, _ in WINDOW_SETTINGS)
    print("\n" + header)
    print("-" * len(header))

    # Documents are built once per filler length and reused across every
    # (window, penalty) cell, so the only thing varying is the parameter.
    corpora: Dict[int, Dict[str, List[str]]] = {}
    for filler_len in FILLER_LENGTHS:
        docs, controls = [], []
        for p in payloads:
            pre = build_filler(prose, filler_len // 2, rng)
            post = build_filler(prose, filler_len - filler_len // 2, rng)
            docs.append(" ".join(x for x in (pre, p["text"], post) if x))
        for b in benign_sentences:
            pre = build_filler(prose, filler_len // 2, rng)
            post = build_filler(prose, filler_len - filler_len // 2, rng)
            controls.append(" ".join(x for x in (pre, b, post) if x))
        corpora[filler_len] = {"docs": docs, "controls": controls}

    results: Dict[str, Dict[str, float]] = {}
    fpr_results: Dict[str, Dict[str, float]] = {}
    for filler_len in FILLER_LENGTHS:
        # Control arm: identical construction, benign centre sentence. Smaller
        # windows raise sensitivity everywhere, so recall alone would always
        # favour the smallest window -- this is what keeps the choice honest.
        docs = corpora[filler_len]["docs"]
        controls = corpora[filler_len]["controls"]

        row = f"{filler_len:<16}"
        for name, wchars in WINDOW_SETTINGS:
            guard = PromptInjectionGuard(window_chars=wchars,
                                         audit=AuditLog(max_records=1))
            hits = sum(1 for d in docs if guard.inspect(d, TrustTier.WEB).is_attack)
            false_hits = sum(1 for d in controls
                             if guard.inspect(d, TrustTier.WEB).is_attack)
            recall = hits / len(docs)
            fpr = false_hits / len(controls)
            results.setdefault(name, {})[str(filler_len)] = round(recall, 4)
            fpr_results.setdefault(name, {})[str(filler_len)] = round(fpr, 4)
            row += f"{recall:>12.3f}"
        print(row)

    print("\nfalse-positive rate on the benign control arm")
    print(header)
    print("-" * len(header))
    for filler_len in FILLER_LENGTHS:
        row = f"{filler_len:<16}"
        for name, _ in WINDOW_SETTINGS:
            row += f"{fpr_results[name][str(filler_len)]:>12.3f}"
        print(row)

    print("\n-- INTERPRETATION ------------------------------------------------")
    FP_PENALTY = 0.55          # same objective the calibration uses
    scored = []
    for name, wchars in WINDOW_SETTINGS:
        rec = [results[name][str(f)] for f in FILLER_LENGTHS]
        fps = [fpr_results[name][str(f)] for f in FILLER_LENGTHS]
        mean_rec = sum(rec) / len(rec)
        mean_fpr = sum(fps) / len(fps)
        obj = mean_rec - FP_PENALTY * mean_fpr
        scored.append((obj, name, wchars, mean_rec, mean_fpr))
        print(f"  {name:<10} recall {rec[0]:.3f} -> {rec[-1]:.3f} across "
              f"0..{FILLER_LENGTHS[-1]} chars | mean recall {mean_rec:.3f} "
              f"mean FPR {mean_fpr:.3f} | objective {obj:.3f}")

    scored.sort(reverse=True)
    best = scored[0]
    print(f"\n  best objective (mean recall - {FP_PENALTY} x mean FPR): "
          f"window={best[1]} ({best[2]} chars)")

    # ---- multiple-comparisons correction sweep -------------------------
    print("\n" + "=" * 76)
    print("Multiple-comparisons correction: thresholds inflated by "
          "(1 + k*log2(N_windows))")
    print("=" * 76)
    grid: Dict[str, Dict] = {}
    for name, wchars in WINDOW_SETTINGS:
        for k in PENALTIES:
            recs, fps = [], []
            for filler_len in FILLER_LENGTHS:
                guard = PromptInjectionGuard(
                    window_chars=wchars,
                    policy=PolicyConfig(window_penalty=k),
                    audit=AuditLog(max_records=1))
                docs = corpora[filler_len]["docs"]
                controls = corpora[filler_len]["controls"]
                recs.append(sum(1 for d in docs
                                if guard.inspect(d, TrustTier.WEB).is_attack) / len(docs))
                fps.append(sum(1 for d in controls
                               if guard.inspect(d, TrustTier.WEB).is_attack) / len(controls))
            mean_rec = sum(recs) / len(recs)
            mean_fpr = sum(fps) / len(fps)
            # Penalise the *worst* document length too: a filter that is fine
            # on snippets and useless on long pages is not deployable.
            obj = mean_rec - FP_PENALTY * mean_fpr - 0.25 * max(fps)
            grid[f"{name}|k={k}"] = {
                "window_chars": wchars, "penalty": k,
                "mean_recall": round(mean_rec, 4), "mean_fpr": round(mean_fpr, 4),
                "worst_fpr": round(max(fps), 4), "objective": round(obj, 4),
                "recall_curve": [round(v, 3) for v in recs],
                "fpr_curve": [round(v, 3) for v in fps]}
            print(f"  window={name:<10} k={k:<5} mean recall={mean_rec:.3f} "
                  f"mean FPR={mean_fpr:.3f} worst FPR={max(fps):.3f} "
                  f"obj={obj:.3f}")

    winner = max(grid.items(), key=lambda kv: kv[1]["objective"])
    print(f"\n  chosen: {winner[0]}  -> window_chars={winner[1]['window_chars']}, "
          f"window_penalty={winner[1]['penalty']}")
    print(f"  recall curve {winner[1]['recall_curve']}")
    print(f"  FPR curve    {winner[1]['fpr_curve']}  (filler {FILLER_LENGTHS})")
    print("=" * 76)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"filler_lengths": FILLER_LENGTHS,
                       "recall": results, "fpr": fpr_results,
                       "n_payloads": len(payloads),
                       "n_controls": len(benign_sentences),
                       "fp_penalty": FP_PENALTY,
                       "correction_grid": grid,
                       "chosen": {"key": winner[0], **winner[1]}}, fh, indent=2)
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
