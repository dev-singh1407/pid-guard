"""One-click demonstration runner for the project review.

Runs the whole story in order, pausing between sections so you can talk over
each one. Press Enter to advance; Ctrl+C to stop early.

Run:  python demo/run_all.py
      python demo/run_all.py --no-pause     (run straight through)
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# (section title, what to say while it runs, command)
STEPS = [
    ("1. THE TEST SUITE",
     "41 automated tests covering every stage of the pipeline. This is the "
     "correctness evidence.",
     [sys.executable, os.path.join("tests", "test_pidguard.py")]),

    ("2. THE ATTACK, WITH AND WITHOUT THE DEFENCE",
     "Same agent, same poisoned web page, twice. Scenario 1 has no middleware "
     "and leaks the credentials. Scenario 2 has PID-Guard and stops it.",
     [sys.executable, os.path.join("demo", "demo_agent.py")]),

    ("3. LIVE SHOWCASE ACROSS EVERY ATTACK FAMILY",
     "20 inputs: 14 attacks including six evasion techniques, and 6 benign "
     "controls that must NOT be blocked. Watch the risk bars.",
     [sys.executable, os.path.join("demo", "showcase.py")]),

    ("4. THE HELD-OUT BENCHMARK",
     "The numbers on the slides, regenerated live. Note the ablation: each "
     "detector has to justify its place.",
     [sys.executable, os.path.join("benchmark", "evaluate.py")]),
]

BANNER = r"""
   ___  _  ___    ___                 _
  / _ \(_)|   \  / __|_  _ __ _ _ _ __| |
 | (_) | || |) || (_ | || / _` | '_/ _` |
  \___/|_||___/  \___|\_,_\__,_|_| \__,_|

  Prompt Injection Defense for LLM Agents
  Dev Singh (23BCE0794) . Sanchit Baghel (23BCE0241)
"""


def rule(char: str = "=") -> str:
    return char * 78


def wait(prompt: str, enabled: bool) -> None:
    """Pause for Enter. Never crash when there is no keyboard attached --
    the runner is also used non-interactively (CI, piped output)."""
    if not enabled:
        return
    try:
        input(prompt)
    except (EOFError, KeyboardInterrupt):
        raise SystemExit(0)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-pause", action="store_true",
                    help="run every section without waiting")
    args = ap.parse_args()

    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")

    print(BANNER)
    print(rule())
    print(f"  {len(STEPS)} sections. Press Enter to advance through each one.")
    print(rule())
    wait("\n  Ready? Press Enter to begin... ", not args.no_pause)

    for title, narration, cmd in STEPS:
        print("\n" * 2 + rule())
        print(f"  {title}")
        print(rule())
        print(f"  {narration}\n")
        wait("  Press Enter to run... ", not args.no_pause)
        print()
        started = time.perf_counter()
        result = subprocess.run(cmd, cwd=ROOT, env=env)
        elapsed = time.perf_counter() - started
        if result.returncode != 0:
            print(f"\n  [section exited with code {result.returncode}]")
        print(f"\n  -- section finished in {elapsed:.1f}s --")
        wait("  Press Enter to continue... ", not args.no_pause)

    print("\n" * 2 + rule())
    print("  DONE. Headline numbers:")
    print(rule())
    print("""
    Attack recall          94.3%   (target >= 90%)
    False-positive rate     2.2%   (target <= 5%)
    F1                      0.953
    Median added latency    3.4 ms (target < 50 ms)
    Runtime dependencies    0

    Full breakdown, including every individual false positive and
    false negative, is in docs/RESULTS.md
""")
    print(rule())
    print("""
  To try your own text live, run this and paste anything you like:

      python demo/try_it.py
""")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  stopped.\n")
