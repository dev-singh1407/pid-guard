"""Focused sweep of the two false-positive controls, on training data only.

Motivated by a measured failure, not a hunch. The dilution study showed
document-level FPR on *benign* pages climbing sharply with document length,
and -- critically -- it did so even with windowing disabled entirely. That
rules out windowing as the sole cause and points at the learned classifier:
it is trained on one-to-three sentence spans and is out of distribution on a
4,000-character page, where it fires with nothing corroborating it.

Filler is realistic document prose (data/prose_filler.txt), not benign user
requests. An earlier version used the latter and measured a false-positive
rate that was an artefact of the control arm rather than a property of the
system -- fifty stacked imperatives is structurally an injection.

Two controls are swept here:
  window_penalty  k  -- multiple-comparisons correction, thresholds scaled by
                        (1 + k*log2 N_windows)
  solo_penalty    s  -- discount applied when exactly one non-signature
                        detector fires, i.e. when nothing corroborates it

Selection keeps recall as a hard constraint and then minimises the worst-case
FPR across document lengths, because a filter that is clean on snippets and
useless on long pages is not deployable.

Run:  python benchmark/sweep_correction.py
"""

from __future__ import annotations

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
OUT = os.path.join(ROOT, "benchmark", "results_correction.json")

FILLER_LENGTHS = [0, 500, 2000, 4000]
WINDOWS = [120, 220]
PENALTIES = [0.06, 0.20]
SOLO = [1.00, 0.70, 0.55, 0.40]
MIN_RECALL = 0.90            # hard constraint: never trade recall for FPR

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


def build_filler(sentences: List[str], target: int, rng: random.Random) -> str:
    if target <= 0:
        return ""
    out, size = [], 0
    while size < target:
        s = rng.choice(sentences)
        out.append(s)
        size += len(s) + 1
    return " ".join(out)[:target]


def main() -> None:
    rows = load(TRAIN_FILE)
    payloads = [r["text"] for r in rows if r["label"] == 1 and r["variant"] == "plain"]
    benign = [r["text"] for r in rows if r["label"] == 0 and r["variant"] == "plain"]
    prose = load_prose()
    rng = random.Random(4242)

    corpora = {}
    for L in FILLER_LENGTHS:
        docs, controls = [], []
        for p in payloads:
            pre, post = build_filler(prose, L // 2, rng), build_filler(prose, L - L // 2, rng)
            docs.append(" ".join(x for x in (pre, p, post) if x))
        for b in benign:
            pre, post = build_filler(prose, L // 2, rng), build_filler(prose, L - L // 2, rng)
            controls.append(" ".join(x for x in (pre, b, post) if x))
        corpora[L] = (docs, controls)

    print("=" * 80)
    print("False-positive control sweep (training data only)")
    print(f"{len(payloads)} payloads / {len(benign)} controls x {len(FILLER_LENGTHS)} lengths")
    print("=" * 80)
    print(f"\n{'window':>7} {'k':>6} {'solo':>6} | {'recall':>7} {'meanFPR':>8} "
          f"{'worstFPR':>9} | FPR by filler length {FILLER_LENGTHS}")
    print("-" * 80)

    grid: Dict[str, Dict] = {}
    for w in WINDOWS:
        for k in PENALTIES:
            for s in SOLO:
                recs, fps = [], []
                for L in FILLER_LENGTHS:
                    guard = PromptInjectionGuard(
                        window_chars=w,
                        policy=PolicyConfig(window_penalty=k, solo_penalty=s),
                        audit=AuditLog(max_records=1))
                    docs, controls = corpora[L]
                    recs.append(sum(1 for d in docs
                                    if guard.inspect(d, TrustTier.WEB).is_attack) / len(docs))
                    fps.append(sum(1 for d in controls
                                   if guard.inspect(d, TrustTier.WEB).is_attack) / len(controls))
                mean_rec = sum(recs) / len(recs)
                mean_fpr = sum(fps) / len(fps)
                worst = max(fps)
                grid[f"w{w}|k{k}|s{s}"] = {
                    "window_chars": w, "window_penalty": k, "solo_penalty": s,
                    "mean_recall": round(mean_rec, 4), "mean_fpr": round(mean_fpr, 4),
                    "worst_fpr": round(worst, 4),
                    "recall_curve": [round(v, 3) for v in recs],
                    "fpr_curve": [round(v, 3) for v in fps],
                    "feasible": mean_rec >= MIN_RECALL}
                flag = " " if mean_rec >= MIN_RECALL else "x"
                print(f"{w:>7} {k:>6} {s:>6} | {mean_rec:>7.3f} {mean_fpr:>8.3f} "
                      f"{worst:>9.3f} |{flag} {[round(v, 2) for v in fps]}")

    feasible = {kk: vv for kk, vv in grid.items() if vv["feasible"]}
    if not feasible:
        print("\nNo setting met the recall constraint; falling back to best recall.")
        feasible = grid
    # minimise worst-case FPR, then mean FPR, then prefer higher recall
    winner_key = min(feasible,
                     key=lambda kk: (feasible[kk]["worst_fpr"],
                                     feasible[kk]["mean_fpr"],
                                     -feasible[kk]["mean_recall"]))
    win = feasible[winner_key]
    print("\n-- CHOSEN --------------------------------------------------------")
    print(f"  {winner_key}")
    print(f"  window_chars={win['window_chars']}  window_penalty={win['window_penalty']}  "
          f"solo_penalty={win['solo_penalty']}")
    print(f"  recall {win['recall_curve']}   (mean {win['mean_recall']:.3f})")
    print(f"  FPR    {win['fpr_curve']}   (worst {win['worst_fpr']:.3f})")
    print(f"  filler lengths {FILLER_LENGTHS}")
    print("=" * 80)

    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump({"filler_lengths": FILLER_LENGTHS, "min_recall": MIN_RECALL,
                   "grid": grid, "chosen": {"key": winner_key, **win}}, fh, indent=2)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
