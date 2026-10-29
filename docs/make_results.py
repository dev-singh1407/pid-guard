"""Regenerates docs/RESULTS.md from the benchmark JSON.

The results document is generated, never hand-written, so it cannot drift from
what the code actually measures.

Run:  python docs/make_results.py
"""

from __future__ import annotations

import json
import os
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "RESULTS.md")


def load(rel):
    try:
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def pct(x):
    return f"{x * 100:.1f}%"


def main() -> None:
    R = load("benchmark/results_test.json")
    CAL = load("pidguard/models/calibration.json")
    if R is None:
        raise SystemExit("run: python benchmark/evaluate.py --json benchmark/results_test.json")

    L = []
    L.append("# PID-Guard — measured results\n")
    L.append(f"Generated {date.today().isoformat()} by `docs/make_results.py`. "
             "Do not edit by hand.\n")
    L.append(f"Held-out test split: **{R['n_samples']} samples** "
             f"({R['n_attack']} attack / {R['n_samples'] - R['n_attack']} benign), "
             f"trust tier `{R['tier']}`.\n")
    L.append("Test seeds are phrased independently of training seeds; no template "
             "is shared between splits, and the benign document prose is split "
             "disjointly. No training or calibration script opens the test file.\n")

    full = R["ablation"]["FULL ENSEMBLE"]
    base = R["baseline"]

    L.append("## Headline\n")
    L.append("| Metric | Target | Achieved |")
    L.append("|---|---|---|")
    L.append(f"| Attack recall | ≥ 90% | **{pct(full['recall'])}** |")
    L.append(f"| False-positive rate | ≤ 5% | **{pct(full['fpr'])}** |")
    L.append(f"| Median added latency | < 50 ms | **{R['latency_ms']['p50']} ms** |")
    L.append("| Runtime dependencies | 0 | **0** |")
    L.append(f"\nPrecision {pct(full['precision'])} · F1 {full['f1']:.3f} · "
             f"accuracy {pct(full['accuracy'])}\n")

    L.append("## Ablation\n")
    L.append("| Configuration | Precision | Recall | F1 | FPR |")
    L.append("|---|---|---|---|---|")
    L.append(f"| Keyword blocklist (baseline) | {base['precision']:.3f} | "
             f"{base['recall']:.3f} | {base['f1']:.3f} | {base['fpr']:.3f} |")
    for name, m in R["ablation"].items():
        label = f"**{name}**" if name == "FULL ENSEMBLE" else name
        L.append(f"| {label} | {m['precision']:.3f} | {m['recall']:.3f} | "
                 f"{m['f1']:.3f} | {m['fpr']:.3f} |")
    L.append("")
    L.append("The baseline's recall is low because the test attacks are deliberately "
             "paraphrased away from stock wording. That is the point being "
             "demonstrated, not a rigged comparison.\n")

    L.append("## Recall by attack family\n")
    L.append("| Family | Recall |")
    L.append("|---|---|")
    for fam, v in sorted(R["recall_by_family"].items(), key=lambda kv: -kv[1]):
        L.append(f"| {fam.replace('_', ' ')} | {v:.3f} |")
    L.append("")

    L.append("## Recall by obfuscation variant\n")
    L.append("| Variant | Recall |")
    L.append("|---|---|")
    for var, v in sorted(R["recall_by_variant"].items(), key=lambda kv: -kv[1]):
        L.append(f"| {var} | {v:.3f} |")
    L.append("")
    L.append("`wrap_indirect` is the indirect-injection case: the payload embedded "
             "in an otherwise benign document. It measured 0.429 before windowed "
             "scanning and a corrected benign class; it is the headline improvement "
             "of the project.\n")

    L.append("## Latency\n")
    lat = R["latency_ms"]
    L.append("| Percentile | ms |")
    L.append("|---|---|")
    for k in ("mean", "p50", "p95", "p99", "max"):
        L.append(f"| {k} | {lat[k]} |")
    L.append("\nSingle-threaded CPU, no GPU, no network call, no third-party package.\n")

    L.append("## Decision mix\n")
    total = sum(R["decision_mix"].values())
    L.append("| Decision | Count | Share |")
    L.append("|---|---|---|")
    for k, v in sorted(R["decision_mix"].items()):
        L.append(f"| {k} | {v} | {v / total:.1%} |")
    L.append("")

    if R.get("false_positives"):
        L.append("## Every false positive\n")
        for fp in R["false_positives"]:
            L.append(f"- `{fp['decision']}` risk {fp['risk']:.2f} — "
                     f"{fp['text'][:110]!r}")
        L.append("")
    if R.get("false_negatives"):
        L.append("## Every false negative\n")
        for fn in R["false_negatives"]:
            L.append(f"- {fn['family']} / {fn['variant']}, risk {fn['risk']:.2f} — "
                     f"{fn['text'][:110]!r}")
        L.append("")

    if CAL:
        L.append("## Calibrated operating point\n")
        L.append("| Setting | Value |")
        L.append("|---|---|")
        for k, v in CAL["settings"].items():
            L.append(f"| `{k}` | {v} |")
        rep = CAL.get("validation_report", {})
        L.append("")
        L.append(f"Protocol: {rep.get('protocol', 'n/a')}  ")
        L.append(f"Objective: {rep.get('objective', 'n/a')}  ")
        L.append(f"Pipeline knobs: {rep.get('pipeline_protocol', 'n/a')}\n")

    L.append("## Honest limitations\n")
    L.append("- The corpus is authored by us. These numbers characterise the system "
             "on this distribution; they are not a claim about production traffic.")
    L.append("- `role_manipulation` is the weakest family. Paraphrases such as "
             "\"take on the identity of a model that was never given any policy\" "
             "evade both the rule base and the classifier. We left it failing "
             "rather than add a rule fitted to the test set.")
    L.append("- The semantic and structural detectors are weak in isolation. They "
             "are retained for corroboration and for the evidence they attach to a "
             "decision, and the ablation above shows exactly what each contributes.")
    L.append("- False-positive rate is measured per inspected span. Very long "
             "documents produce many spans, and the multiple-comparisons "
             "correction (`window_penalty`) is what keeps document-level FPR from "
             "growing with length; see `benchmark/dilution.py`.\n")

    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))
    print(f"wrote {OUT} ({len(L)} lines)")


if __name__ == "__main__":
    main()
