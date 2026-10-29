"""Fits the learned detector, builds the exemplar index, and calibrates every
threshold in the pipeline.

Protocol -- this is the part that makes the reported numbers mean something:

  1. data/corpus_train.jsonl is split 75/25 into TRAIN and VAL, **grouped by
     seed_id**. All obfuscation variants of one seed sentence stay in the same
     fold, so an augmented near-duplicate can never leak across the boundary.
  2. Logistic-regression hyperparameters are chosen by VAL score.
  3. Semantic threshold, window size, concentration bonus and the two policy
     thresholds are then swept, one group at a time, against VAL.
  4. Only after everything is fixed is the model refitted on the full training
     file and the calibration written out.
  5. data/corpus_test.jsonl is never opened by this script.

Selection objective is F1 with an explicit false-positive penalty: a filter
that blocks 3% of legitimate traffic gets uninstalled in week one, so FPR is
not a tiebreaker, it is part of the objective.

Run:  python benchmark/train.py
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
from typing import Dict, List, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pidguard import config as pidconfig  # noqa: E402
from pidguard.detectors import (HeuristicDetector, SemanticDetector,  # noqa: E402
                                StatisticalDetector, StructuralDetector)
from pidguard.detectors.semantic import ExemplarIndex  # noqa: E402
from pidguard.detectors.statistical import (MODEL_PATH, LogisticRegression,  # noqa: E402
                                            featurize)
from pidguard.middleware import PromptInjectionGuard  # noqa: E402
from pidguard.normalizer import normalize  # noqa: E402
from pidguard.policy import PolicyConfig  # noqa: E402
from pidguard.types import TrustTier  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN_FILE = os.path.join(ROOT, "data", "corpus_train.jsonl")
EXEMPLARS = os.path.join(ROOT, "pidguard", "models", "exemplars.json")
VAL_EXEMPLARS = os.path.join(ROOT, "pidguard", "models", "_exemplars_trainfold.json")

#: cost of one false positive relative to one point of F1
FP_PENALTY = 0.55
#: Hard recall floor, from the project's stated target (>= 90% detection).
#: Without it the FP-weighted objective alone picks a conservative operating
#: point that maximises F1 by giving up recall -- which is the wrong trade for
#: a security control whose job is catching attacks. Settings that clear the
#: floor are preferred; the objective only ranks among them.
MIN_RECALL = 0.90


def prefer(cand: dict, best: dict | None, *extra_keys) -> bool:
    """Feasibility first (recall floor), then objective, then tie-breakers."""
    if best is None:
        return True
    cf, bf = cand["recall"] >= MIN_RECALL, best["recall"] >= MIN_RECALL
    if cf != bf:
        return cf
    if abs(cand["objective"] - best["objective"]) > 0.004:
        return cand["objective"] > best["objective"]
    for k in extra_keys:
        if k in cand and k in best and cand[k] != best[k]:
            return cand[k] > best[k] if k != "ms_per_span" else cand[k] < best[k]
    return False


def load(path: str) -> List[Dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def grouped_split(rows: List[Dict], val_frac: float = 0.25,
                  seed: int = 11) -> Tuple[List[Dict], List[Dict]]:
    """Split by seed_id so no augmented variant crosses the fold boundary."""
    groups = sorted({r["seed_id"] for r in rows})
    rng = random.Random(seed)
    rng.shuffle(groups)
    n_val = max(1, int(len(groups) * val_frac))
    val_groups = set(groups[:n_val])
    train = [r for r in rows if r["seed_id"] not in val_groups]
    val = [r for r in rows if r["seed_id"] in val_groups]
    return train, val


def score(y_true: Sequence[int], y_pred: Sequence[int]) -> Dict[str, float]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"f1": f1, "precision": prec, "recall": rec, "fpr": fpr,
            "objective": f1 - FP_PENALTY * fpr,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


# ------------------------------------------------------- 1. classifier -----
def fit_classifier(train: List[Dict], val: List[Dict]) -> Tuple[Dict, List[Dict]]:
    print("\n[1/4] logistic-regression hyperparameter search")
    Xtr = [(featurize(normalize(r["text"]).normalized), r["label"]) for r in train]
    Xva = [(featurize(normalize(r["text"]).normalized), r["label"]) for r in val]
    yva = [y for _, y in Xva]

    grid = [(ep, l2, lr)
            for ep in (12, 25, 40)
            for l2 in (1e-4, 1e-3, 5e-3)
            for lr in (0.3, 0.5)]
    trials: List[Dict] = []
    best = None
    for ep, l2, lr in grid:
        m = LogisticRegression().fit(Xtr, epochs=ep, lr=lr, l2=l2)
        probs = [m.predict_proba(x) for x, _ in Xva]
        # pick the probability threshold along with the hyperparameters
        for thr in (0.5, 0.6, 0.7, 0.8):
            s = score(yva, [int(p >= thr) for p in probs])
            trial = {"epochs": ep, "l2": l2, "lr": lr, "threshold": thr, **s}
            trials.append(trial)
            if prefer(trial, best):
                best = trial
    assert best is not None
    print(f"      best: epochs={best['epochs']} l2={best['l2']} lr={best['lr']} "
          f"thr={best['threshold']} | val F1={best['f1']:.3f} "
          f"FPR={best['fpr']:.3f} obj={best['objective']:.3f}")
    return best, trials


# --------------------------------------------------------- 2. semantic -----
def calibrate_semantic(train: List[Dict], val: List[Dict]) -> Dict:
    print("\n[2/4] semantic-detector threshold sweep")
    idx = ExemplarIndex()
    for r in train:
        if r["label"] == 1 and r["variant"] == "plain":
            idx.add(r["text"], r["family"])
    idx.save(VAL_EXEMPLARS)
    det = SemanticDetector(index_path=VAL_EXEMPLARS, threshold=0.0)
    sims = [(det.index.nearest(normalize(r["text"]).normalized)[0], r["label"])
            for r in val]
    best = None
    for thr in [round(0.10 + 0.025 * i, 3) for i in range(29)]:
        s = score([y for _, y in sims], [int(sim >= thr) for sim, _ in sims])
        cand = {"threshold": thr, **s}
        if prefer(cand, best):
            best = cand
    assert best is not None
    print(f"      exemplars={len(idx)}  best threshold={best['threshold']} "
          f"| val F1={best['f1']:.3f} FPR={best['fpr']:.3f} "
          f"recall={best['recall']:.3f}")
    return best


# ---------------------------------------------- 3. windowing + policy ------
def calibrate_pipeline(rows: List[Dict], stat_thr: float, sem_thr: float,
                       lr_best: Dict) -> Dict:
    """Leave-one-family-out sweep for the pipeline-level knobs.

    A plain train/val split cannot tune these: validation F1 saturates at
    ~0.99 because held-out seeds are phrased like training seeds, so every
    window size scores identically. Leave-one-family-out removes an entire
    attack category from the classifier and the exemplar index, then measures
    recall on that unseen category -- which is precisely the regime where
    dilution decides whether an attack is caught, and precisely the gap
    between validation and a genuinely novel attack in production.
    """
    print("\n[3/4] window size, concentration bonus and policy thresholds")
    print("      protocol: leave-one-family-out (classifier + exemplars refit per fold)")

    families = sorted({r["family"] for r in rows if r["label"] == 1})
    benign = [r for r in rows if r["label"] == 0]
    rng = random.Random(3)
    benign_sample = rng.sample(benign, min(60, len(benign)))

    # Pre-fit one model + index per fold; reused across every grid point.
    folds = []
    for fam in families:
        fit_rows = [r for r in rows if r["family"] != fam]
        model = LogisticRegression().fit(
            [(featurize(normalize(r["text"]).normalized), r["label"]) for r in fit_rows],
            epochs=lr_best["epochs"], lr=lr_best["lr"], l2=lr_best["l2"])
        model_path = os.path.join(ROOT, "pidguard", "models", f"_fold_{fam}.json")
        model.save(model_path)
        idx = ExemplarIndex()
        for r in fit_rows:
            if r["label"] == 1 and r["variant"] == "plain":
                idx.add(r["text"], r["family"])
        idx_path = os.path.join(ROOT, "pidguard", "models", f"_foldidx_{fam}.json")
        idx.save(idx_path)
        held = [r for r in rows if r["family"] == fam]
        folds.append({"family": fam, "model_path": model_path, "idx_path": idx_path,
                      "eval_rows": held + benign_sample})
        print(f"      fold {fam:<22} refit on {len(fit_rows)} rows, "
              f"{len(held)} held-out attacks")

    def evaluate(window_chars: int, bonus: float, san: float, blk: float) -> Dict:
        """Aggregate confusion counts across all folds."""
        tp = fp = tn = fn = 0
        embedded_hit = embedded_tot = 0
        t0 = time.perf_counter()
        n_spans = 0
        for fold in folds:
            guard = PromptInjectionGuard(
                detectors=[HeuristicDetector(),
                           StatisticalDetector(model_path=fold["model_path"],
                                               threshold=stat_thr),
                           SemanticDetector(index_path=fold["idx_path"],
                                            threshold=sem_thr),
                           StructuralDetector()],
                policy=PolicyConfig(sanitize_threshold=san, block_threshold=blk),
                window_chars=window_chars, concentration_bonus=bonus)
            for r in fold["eval_rows"]:
                pred = int(guard.inspect(r["text"], TrustTier.WEB).is_attack)
                n_spans += 1
                if r["label"] == 1:
                    tp += pred
                    fn += 1 - pred
                    if r["variant"] == "wrap_indirect":
                        embedded_tot += 1
                        embedded_hit += pred
                else:
                    fp += pred
                    tn += 1 - pred
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        return {"f1": f1, "precision": prec, "recall": rec, "fpr": fpr,
                "objective": f1 - FP_PENALTY * fpr,
                "tp": tp, "fp": fp, "tn": tn, "fn": fn,
                "hard_recall": embedded_hit / embedded_tot if embedded_tot else 0.0,
                "ms_per_span": round((time.perf_counter() - t0) * 1000 / max(1, n_spans), 3)}

    def better(cand: Dict, best: Dict | None) -> bool:
        """Recall floor, then objective; near-ties go to embedded-attack
        recall, then to the cheaper setting."""
        if best is None:
            return True
        cf, bf = cand["recall"] >= MIN_RECALL, best["recall"] >= MIN_RECALL
        if cf != bf:
            return cf
        if cand["objective"] > best["objective"] + 0.004:
            return True
        if cand["objective"] < best["objective"] - 0.004:
            return False
        if abs(cand["hard_recall"] - best["hard_recall"]) > 0.01:
            return cand["hard_recall"] > best["hard_recall"]
        return cand["ms_per_span"] < best["ms_per_span"]

    best = None
    for window_chars in (120, 220, 320, 100000):
        for bonus in (0.0, 0.18, 0.35):
            s = evaluate(window_chars, bonus, 0.35, 0.62)
            cand = {"window_chars": window_chars, "concentration_bonus": bonus,
                    "sanitize_threshold": 0.35, "block_threshold": 0.62, **s}
            label = "no-window" if window_chars > 9999 else str(window_chars)
            print(f"      window={label:<9} bonus={bonus:<5} "
                  f"LOFO F1={s['f1']:.3f} recall={s['recall']:.3f} "
                  f"FPR={s['fpr']:.3f} embedded={s['hard_recall']:.3f} "
                  f"{s['ms_per_span']:.2f}ms")
            if better(cand, best):
                best = cand
    assert best is not None

    for san in (0.25, 0.30, 0.35, 0.42):
        for blk in (0.50, 0.58, 0.62, 0.70):
            if blk <= san:
                continue
            s = evaluate(best["window_chars"], best["concentration_bonus"], san, blk)
            cand = {"window_chars": best["window_chars"],
                    "concentration_bonus": best["concentration_bonus"],
                    "sanitize_threshold": san, "block_threshold": blk, **s}
            if better(cand, best):
                best = cand

    for fold in folds:                       # clean up per-fold artefacts
        for path in (fold["model_path"], fold["idx_path"]):
            if os.path.exists(path):
                os.remove(path)

    label = "no-window" if best["window_chars"] > 9999 else best["window_chars"]
    print(f"      chosen: window={label} bonus={best['concentration_bonus']} "
          f"sanitize={best['sanitize_threshold']} block={best['block_threshold']} "
          f"| LOFO F1={best['f1']:.3f} FPR={best['fpr']:.3f} "
          f"embedded={best['hard_recall']:.3f}")
    return best


# ------------------------------------------------------------ 4. refit -----
def main() -> None:
    rows = load(TRAIN_FILE)
    train, val = grouped_split(rows)
    print(f"corpus: {len(rows)} rows -> train {len(train)} / val {len(val)} "
          f"(grouped by seed_id, {len({r['seed_id'] for r in val})} held-out seeds)")

    t0 = time.perf_counter()
    lr_best, lr_trials = fit_classifier(train, val)
    sem_best = calibrate_semantic(train, val)

    pipe_best = calibrate_pipeline(rows, lr_best["threshold"],
                                   sem_best["threshold"], lr_best)

    print("\n[4/4] refitting on the full training file with chosen settings")
    Xall = [(featurize(normalize(r["text"]).normalized), r["label"]) for r in rows]
    final = LogisticRegression().fit(Xall, epochs=lr_best["epochs"],
                                     lr=lr_best["lr"], l2=lr_best["l2"])
    final.save(os.path.normpath(MODEL_PATH))
    kb = os.path.getsize(os.path.normpath(MODEL_PATH)) / 1024
    print(f"      model -> {len(final.w)} non-zero weights, {kb:.1f} KB")

    idx = ExemplarIndex()
    for r in rows:
        if r["label"] == 1 and r["variant"] == "plain":
            idx.add(r["text"], r["family"])
    idx.save(EXEMPLARS)
    print(f"      exemplar index -> {len(idx)} entries")

    settings = {
        "statistical_threshold": lr_best["threshold"],
        "semantic_threshold": sem_best["threshold"],
        "window_chars": pipe_best["window_chars"],
        "concentration_bonus": pipe_best["concentration_bonus"],
        "sanitize_threshold": pipe_best["sanitize_threshold"],
        "block_threshold": pipe_best["block_threshold"],
        "lr_epochs": lr_best["epochs"],
        "lr_l2": lr_best["l2"],
        "lr_rate": lr_best["lr"],
    }
    report = {
        "protocol": "grouped 75/25 train/val split by seed_id; test split untouched",
        "objective": f"maximise F1 - {FP_PENALTY} * FPR subject to recall >= {MIN_RECALL}",
        "n_train_rows": len(train), "n_val_rows": len(val),
        "classifier_best": lr_best,
        "classifier_trials": len(lr_trials),
        "semantic_best": sem_best,
        "pipeline_protocol": "leave-one-family-out over 8 attack families",
        "pipeline_best": pipe_best,
        "elapsed_sec": round(time.perf_counter() - t0, 1),
    }
    pidconfig.save(pidconfig.CALIBRATION_PATH, settings, report)
    if os.path.exists(VAL_EXEMPLARS):
        os.remove(VAL_EXEMPLARS)

    print(f"\ncalibration written -> {pidconfig.CALIBRATION_PATH}")
    for k, v in settings.items():
        print(f"      {k:<24} {v}")
    print(f"\ntotal {time.perf_counter() - t0:.1f}s")


if __name__ == "__main__":
    main()
