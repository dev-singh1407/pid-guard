"""Held-out evaluation of PID-Guard.

Reports, on data/corpus_test.jsonl (never seen during training):
  * a keyword-blocklist baseline, to show what the naive approach costs
  * an ablation over the four detectors, so each layer has to justify itself
  * per-family and per-obfuscation-variant recall
  * end-to-end latency percentiles

Run:  python benchmark/evaluate.py [--json results.json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
import time
from collections import defaultdict
from typing import Dict, List, Sequence

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pidguard import PromptInjectionGuard, TrustTier  # noqa: E402
from pidguard.audit import AuditLog  # noqa: E402
from pidguard.detectors import (HeuristicDetector, SemanticDetector,  # noqa: E402
                                StatisticalDetector, StructuralDetector)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST = os.path.join(ROOT, "data", "corpus_test.jsonl")

# The straw man every prompt-injection blog post recommends.
BASELINE_KEYWORDS = [
    "ignore previous", "ignore all previous", "disregard", "system prompt",
    "jailbreak", "developer mode", "you are now", "new instructions",
    "forget everything", "override",
]


def load(path: str) -> List[Dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


# ------------------------------------------------------------- metrics ----
def confusion(y_true: Sequence[int], y_pred: Sequence[int]) -> Dict[str, float]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": (tp + tn) / max(1, len(y_true)),
        "precision": precision,
        "recall": recall,          # = true positive rate / attack detection rate
        "f1": f1,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "specificity": tn / (tn + fp) if tn + fp else 0.0,
    }


def fmt(name: str, m: Dict[str, float]) -> str:
    return (f"{name:<28} acc={m['accuracy']:.3f}  P={m['precision']:.3f}  "
            f"R={m['recall']:.3f}  F1={m['f1']:.3f}  FPR={m['fpr']:.3f}  "
            f"(tp={m['tp']} fp={m['fp']} tn={m['tn']} fn={m['fn']})")


# ------------------------------------------------------------ baseline ----
def run_baseline(rows: List[Dict]) -> Dict[str, float]:
    pred = []
    for r in rows:
        low = r["text"].lower()
        pred.append(int(any(k in low for k in BASELINE_KEYWORDS)))
    return confusion([r["label"] for r in rows], pred)


# ------------------------------------------------------------ ablation ----
CONFIGS = [
    ("heuristic only", lambda: [HeuristicDetector()]),
    ("statistical only", lambda: [StatisticalDetector()]),
    ("semantic only", lambda: [SemanticDetector()]),
    ("structural only", lambda: [StructuralDetector()]),
    ("heuristic + statistical", lambda: [HeuristicDetector(), StatisticalDetector()]),
    ("heuristic + stat + semantic", lambda: [HeuristicDetector(), StatisticalDetector(),
                                             SemanticDetector()]),
    ("FULL ENSEMBLE", lambda: [HeuristicDetector(), StatisticalDetector(),
                               SemanticDetector(), StructuralDetector()]),
]


def run_guard(rows: List[Dict], detectors, tier: TrustTier):
    guard = PromptInjectionGuard(detectors=detectors, audit=AuditLog(max_records=10000))
    preds, latencies, results = [], [], []
    for r in rows:
        t0 = time.perf_counter()
        res = guard.inspect(r["text"], tier)
        latencies.append((time.perf_counter() - t0) * 1000)
        preds.append(int(res.is_attack))
        results.append(res)
    return preds, latencies, results


def percentiles(values: List[float]) -> Dict[str, float]:
    s = sorted(values)
    def p(q):
        return s[min(len(s) - 1, int(len(s) * q))]
    return {"mean": round(statistics.fmean(s), 3), "p50": round(p(0.5), 3),
            "p95": round(p(0.95), 3), "p99": round(p(0.99), 3),
            "max": round(s[-1], 3)}


# ---------------------------------------------------------------- main ----
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write full results to this path")
    ap.add_argument("--tier", default="web",
                    choices=[t.value for t in TrustTier])
    args = ap.parse_args()

    rows = load(TEST)
    y = [r["label"] for r in rows]
    tier = TrustTier(args.tier)
    n_atk = sum(y)
    print("=" * 78)
    print(f"PID-Guard held-out evaluation   |  {len(rows)} samples "
          f"({n_atk} attack / {len(rows) - n_atk} benign)  |  tier={tier.value}")
    print("=" * 78)

    results_blob: Dict[str, object] = {"n_samples": len(rows), "n_attack": n_atk,
                                       "tier": tier.value}

    print("\n-- BASELINE ------------------------------------------------------")
    base = run_baseline(rows)
    print(fmt("keyword blocklist", base))
    results_blob["baseline"] = base

    print("\n-- ABLATION ------------------------------------------------------")
    ablation = {}
    full_results = None
    full_latency = None
    for name, factory in CONFIGS:
        preds, lat, res = run_guard(rows, factory(), tier)
        m = confusion(y, preds)
        ablation[name] = m
        print(fmt(name, m))
        if name == "FULL ENSEMBLE":
            full_results, full_latency = res, lat
    results_blob["ablation"] = ablation

    assert full_results is not None and full_latency is not None

    print("\n-- LATENCY (full ensemble, single-threaded CPU) -------------------")
    lat = percentiles(full_latency)
    print(f"mean={lat['mean']} ms   p50={lat['p50']} ms   p95={lat['p95']} ms   "
          f"p99={lat['p99']} ms   max={lat['max']} ms")
    results_blob["latency_ms"] = lat

    print("\n-- RECALL BY ATTACK FAMILY (full ensemble) -----------------------")
    by_family = defaultdict(lambda: [0, 0])
    for r, res in zip(rows, full_results):
        if r["label"] == 1:
            by_family[r["family"]][1] += 1
            by_family[r["family"]][0] += int(res.is_attack)
    fam_out = {}
    for fam, (hit, tot) in sorted(by_family.items()):
        fam_out[fam] = round(hit / tot, 3)
        print(f"  {fam:<24} {hit}/{tot}   recall={hit / tot:.3f}")
    results_blob["recall_by_family"] = fam_out

    print("\n-- RECALL BY OBFUSCATION VARIANT (full ensemble) ------------------")
    by_var = defaultdict(lambda: [0, 0])
    for r, res in zip(rows, full_results):
        if r["label"] == 1:
            by_var[r["variant"]][1] += 1
            by_var[r["variant"]][0] += int(res.is_attack)
    var_out = {}
    for var, (hit, tot) in sorted(by_var.items()):
        var_out[var] = round(hit / tot, 3)
        print(f"  {var:<24} {hit}/{tot}   recall={hit / tot:.3f}")
    results_blob["recall_by_variant"] = var_out

    print("\n-- DECISION MIX (full ensemble) ----------------------------------")
    mix = defaultdict(int)
    for res in full_results:
        mix[res.decision.value] += 1
    for k, v in sorted(mix.items()):
        print(f"  {k:<12} {v:>4}  ({v / len(full_results):.1%})")
    results_blob["decision_mix"] = dict(mix)

    print("\n-- FALSE POSITIVES (full ensemble) -------------------------------")
    fps = [(r, res) for r, res in zip(rows, full_results)
           if r["label"] == 0 and res.is_attack]
    if not fps:
        print("  none")
    for r, res in fps[:8]:
        top = res.top_detection
        print(f"  risk={res.risk_score:.2f} [{res.decision.value}] "
              f"{r['text'][:70]!r}")
        if top:
            print(f"      driver: {top.detector}/{top.rule_id} -- {top.description[:70]}")
    results_blob["false_positives"] = [
        {"text": r["text"], "risk": round(res.risk_score, 3),
         "decision": res.decision.value} for r, res in fps]

    print("\n-- FALSE NEGATIVES (full ensemble) -------------------------------")
    fns = [(r, res) for r, res in zip(rows, full_results)
           if r["label"] == 1 and not res.is_attack]
    if not fns:
        print("  none")
    for r, res in fns[:8]:
        print(f"  risk={res.risk_score:.2f} [{r['family']}/{r['variant']}] "
              f"{r['text'][:70]!r}")
    results_blob["false_negatives"] = [
        {"text": r["text"], "family": r["family"], "variant": r["variant"],
         "risk": round(res.risk_score, 3)} for r, res in fns]

    print("\n-- SUMMARY -------------------------------------------------------")
    full = ablation["FULL ENSEMBLE"]
    print(f"  attack detection rate (recall) : {full['recall']:.1%}")
    print(f"  false positive rate            : {full['fpr']:.1%}")
    print(f"  precision                      : {full['precision']:.1%}")
    print(f"  F1                             : {full['f1']:.3f}")
    print(f"  baseline recall / FPR          : {base['recall']:.1%} / {base['fpr']:.1%}")
    print(f"  median added latency           : {lat['p50']} ms per span")
    print("=" * 78)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results_blob, fh, indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
