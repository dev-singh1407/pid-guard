# Every command, and what it actually does

Each entry says **what the part is**, **why it exists**, **the command**, and
**what you will see**. Timings are measured on this laptop, not estimated.

Run everything from the project folder:

```bash
cd "C:\Users\dev singh\OneDrive\Desktop\prompt-injection-defense"
```

If `python` is not recognised, use `py` instead throughout.

---

# PART A — The three things you need for the review

## A1 · The web console

**What it is.** A browser interface over the real pipeline. It starts a small
web server on your own laptop; the page posts text to that Python process and
shows the actual output. No detection logic is reimplemented in the browser,
which is why you can claim the demo is genuine.

**Why it exists.** A terminal demo is hard for a panel to follow. This makes
the same thing visible, and lets a reviewer type their own input.

**Double-click** `WEB_CONSOLE.bat`, or:

```bash
python web/server.py
```

**You will see:** a banner printing the address, then a browser opening at
`http://127.0.0.1:8787`. Six tabs: Inspect, Attack gallery, Agent comparison,
Egress guard, Live LLM, Results. *Leave the black window open — closing it
kills the server.*

## A2 · The interactive prompt

**What it is.** The same engine without the browser. You type text, it returns
the verdict and the evidence.

**Why it exists.** A fallback if the browser misbehaves, and faster for
rapid-fire questions.

**Double-click** `TRY_IT.bat`, or:

```bash
python demo/try_it.py
```

**You will see:** a `[web] >` prompt. Type anything. Commands inside it:
`:tier user` / `:tier web` to change the trust level, `:case 1.2` to load one
of the 50 bundled cases, `:list` to see them, `:paste` for multi-line input
ending with `:end`, `:quit` to exit.

## A3 · The fixed showcase — your safety net

**What it is.** Twenty hard-coded cases run through the pipeline, printed as a
table with risk bars.

**Why it exists.** It has no browser, no server, no interactivity and no
dependencies, so it works when nothing else does. If anything breaks
mid-review, run this.

```bash
python demo/showcase.py
```

**Takes 0.5 s.** **You will see:** `20/20 correct (14 attacks, 6 benign)`, then
the neutralisation, egress and audit sections.

---

# PART B — Demonstrations

## B1 · The guarded vs unguarded agent

**What it is.** The same poisoned support page sent through an agent twice,
once without the middleware and once with it.

**Why it exists.** It is the clearest single illustration of the problem: the
unguarded agent reads a hidden instruction, opens the credentials file and
posts the key to an attacker, while the user sees a normal summary.

```bash
python demo/demo_agent.py
```

**Takes 0.5 s.** **You will see:** three scenarios — unguarded (compromised),
guarded (blocked, tools revoked, leak redacted), and a clean page passing with
all capabilities intact.

## B2 · The scripted full run

**What it is.** A runner that executes the test suite, the agent comparison,
the showcase and the benchmark in sequence, pausing between each.

**Why it exists.** For presenting without typing. You press Enter to advance
and talk over each section.

**Double-click** `RUN_DEMO.bat`, or:

```bash
python demo/run_all.py
```

Add `--no-pause` to run straight through without stopping.

---

# PART C — Tests

## C1 · The test suite

**What it is.** 60 tests covering every stage: normalisation, all five
detectors, policy, segmentation, sanitiser, egress, the LLM layer, and the 50
bundled demo cases.

**Why it exists.** It is the correctness evidence. Several tests are
regressions for bugs found during development — each one encodes a mistake
that was actually made, so it cannot come back.

```bash
python tests/test_pidguard.py
```

**Takes 7.6 s.** **You will see:** `60/60 passed`. Any failure prints the test
name and the assertion.

It also runs under pytest if you prefer:

```bash
python -m pytest tests/ -q
```

---

# PART D — Building the data

> You do not need these for the review. The corpus files are already built and
> committed. Run them only to demonstrate reproducibility.

## D1 · The English corpus

**What it is.** The generator for the 753-sample corpus — 528 training, 225
held out for testing.

**Why it exists.** The corpus is generated from hand-written seeds plus
obfuscation augmentation, so the whole dataset is reproducible from source
rather than being an opaque file. It also enforces the methodology: test seeds
are phrased independently, and every variant of a seed carries the same
`seed_id` so grouped splitting can keep them in one fold.

```bash
python data/build_corpus.py
```

**Takes 0.2 s.** **Writes** `data/corpus_train.jsonl` and
`data/corpus_test.jsonl`.

## D2 · The cross-lingual corpus

**What it is.** The generator for the 108-sample, 12-language evaluation set —
48 attacks and 60 hard negatives.

**Why it exists.** The hard negatives are the point: foreign-language documents
that use the *same vocabulary* as the attacks (password, settings, system,
instructions). Without them, a lexicon detector that simply fires on any of
those words would look perfect.

```bash
python data/build_multilingual.py
```

**Takes 0.2 s.** **Writes** `data/corpus_multilingual.jsonl`.

---

# PART E — Training and calibration

## E1 · Fit the classifier and calibrate every threshold

**What it is.** Trains the logistic-regression detector and selects every
threshold in the pipeline.

**Why it exists.** This is where the methodology lives. It splits the training
file 75/25 **grouped by seed_id**, searches the classifier hyperparameters,
sweeps the semantic threshold, and then chooses the pipeline parameters by
**leave-one-family-out** — withholding an entire attack category and measuring
recall on it, because a conventional validation split saturated near 1.0 and
could not tell settings apart. It never opens the test file.

```bash
python benchmark/train.py
```

**Takes about 2–3 minutes.** **Writes** `pidguard/models/lr_model.json`,
`exemplars.json` and `calibration.json`.

> Only run this if you want to show the training. The committed model is
> already calibrated, and re-running will shift the reported figures slightly.

---

# PART F — Evaluation (where your numbers come from)

## F1 · The main held-out benchmark

**What it is.** Evaluates the full system on the 225 held-out samples and runs
the ablation — each detector alone, then in combination.

**Why it exists.** It produces the headline figures and forces each layer to
justify itself. It also prints every individual false positive and false
negative, so nothing is hidden behind an average.

```bash
python benchmark/evaluate.py
```

Add `--json benchmark/results_test.json` to save the figures, which the deck,
the report and the console all read from.

**Takes 5.6 s.** **You will see:** the baseline, the seven-row ablation,
latency percentiles, recall by family and by evasion technique, then the
summary — **94.3% recall, 2.9% false positives, F1 0.948**.

## F2 · The cross-lingual benchmark

**What it is.** Runs the ensemble over the 12-language set twice — once with
the multilingual detector disabled, once with it enabled.

**Why it exists.** It measures a bypass we found and closed. An English-only
ensemble caught almost nothing in other languages; an attacker only had to
change language.

```bash
python benchmark/evaluate_multilingual.py
```

**Takes 1.4 s.** **You will see:** recall before and after per language, the
controls-kept column, and the summary — **2.1% → 100%, 0/60 false positives**.

## F3 · The adaptive adversary

**What it is.** A hill-climbing evasion search. For every payload the system
currently catches, it applies mutation operators — encodings, homoglyphs,
spacing, HTML-comment concealment, dilution, politeness reframing, lexical
translation — keeps whichever lowered the risk score, and repeats until it
evades or exhausts a budget.

**Why it exists.** Every other benchmark measures the attacks we thought of.
This measures what happens when the attacker adapts. It is deliberately
**white-box** — it reads the exact risk score — so the evasion rate is an
*upper bound* on a real attacker.

```bash
python benchmark/redteam.py --budget 40
```

**Takes 28 s.** **You will see:** per-payload results, evasion rate by family,
which mutation operators bought the most risk reduction, and the summary —
**86.7% robustness, 15.4 mean queries to evade**.

## F4 · End-to-end against a real model

**What it is.** Runs a local Ollama model through a genuine agent loop over
poisoned and clean documents, under three conditions: a naive agent with no
defensive instruction, the same agent with a prompt-level defence, and the
agent behind the middleware.

**Why it exists.** Everything else measures the filter. This measures whether
an agent is actually hijacked. Attack success is **behavioural** — the model
invoked a dangerous tool — not a text match on its reply.

```bash
python benchmark/evaluate_llm.py --model qwen2.5:1.5b-instruct --n 12
```

**Takes about 2–3 minutes.** Needs Ollama running; everything else works
without it. **You will see:** all three conditions at 0% attack success, 83%
of payloads withheld, utility 100% → 100%.

## F5 · The positive control for F4

**What it is.** The operator legitimately asks the model to do each dangerous
action, and we check whether it complies and whether our parser sees it.

**Why it exists.** **A 0% attack rate is exactly what a broken harness also
reports.** This proves the measurement could have observed a hijack. Writing it
found two bugs in our own measurement code, both biasing attack success
downward.

```bash
python benchmark/llm_sanity.py --model qwen2.5:1.5b-instruct
```

**Takes about 1 minute.** **You will see:** `SENSITIVE` — the model calls
`read_file` and `send_email`, and the parser recognises both.

## F6 · The dilution study *(supporting experiment)*

**What it is.** Measures how detection decays as a payload is buried in an
increasingly long benign document, across several window sizes.

**Why it exists.** It turned a hyperparameter choice into a controlled
experiment, using training data only rather than peeking at the test split.

```bash
python benchmark/dilution.py
```

**Takes several minutes.**

## F7 · The false-positive control sweep *(supporting experiment)*

**What it is.** Sweeps the two controls that hold the false-positive rate down
on long documents — the multiple-comparisons correction and the corroboration
discount.

```bash
python benchmark/sweep_correction.py
```

**Takes several minutes.**

---

# PART G — Regenerating the documents

> All three artefacts read the benchmark JSON at build time, so they cannot
> drift from the measured results. Re-run F1–F3 first if you want them to
> reflect a fresh measurement.

## G1 · The results document

**What it is.** Regenerates `docs/RESULTS.md` from the benchmark output.

**Why it exists.** The results document is generated, never hand-written, so it
cannot disagree with the code.

```bash
python docs/make_results.py
```

**Takes 0.2 s.**

## G2 · The short deck (9 slides)

```bash
node ppt/build_deck.js
```

**Writes** `ppt/Prompt_Injection_Defense_LLM_Agents.pptx`. Use this one if you
have ten minutes.

## G3 · The detailed deck (27 slides)

**What it is.** The chapter-by-chapter deck, mapped onto the eight chapters of
the report.

```bash
node ppt/build_detailed3.js
```

**Writes** `ppt/PID-Guard_Detailed_Presentation.pptx`. *Run `build_detailed3.js`
— it pulls in parts 1 and 2 itself.*

## G4 · Check a deck's layout

**What it is.** A geometric check for text overflow, off-slide shapes, tight
margins and overlapping boxes.

**Why it exists.** LibreOffice is not installed here, so slides cannot be
rendered to images. This checks analytically instead.

```bash
python ppt/qa_deck.py ppt/PID-Guard_Detailed_Presentation.pptx
```

**Takes 2.4 s.** **You will see:** `0 potential issue(s)` when clean.

## G5 · The report

```bash
node report/generate2.js
```

**Writes** `report/Project_I_Report_PID-Guard.docx`. *Run `generate2.js` — it
pulls in `generate.js` and `build_report.js` itself.*

To produce the PDF, open the .docx in Word and **Save As → PDF**. (The PDF in
`_deliverables` was produced that way, so it is exactly what an examiner sees.)

---

# PART H — If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `'python' is not recognized` | Python not on PATH from this shell | use `py` instead |
| Console tab misbehaves, or Live LLM 404s | an old server still holds the port | close **every** black window, re-run `WEB_CONSOLE.bat` |
| Garbled characters in the terminal | code page is not UTF-8 | run `chcp 65001` first |
| Unicode demo inputs paste wrongly | CMD mangles Devanagari / Cyrillic | use `:case 7.3` etc. instead of pasting |
| Ollama tab says unavailable | Ollama not running | start Ollama, or ignore — everything else works |
| Files unreadable / very slow | OneDrive is de-hydrating the folder | right-click the folder → *Always keep on this device* |

---

# One-line summary of the whole project

```bash
python tests/test_pidguard.py && python benchmark/evaluate.py && python demo/showcase.py
```

Three commands, about 14 seconds: the tests pass, the benchmark reproduces the
headline numbers, and the showcase demonstrates the system working.
