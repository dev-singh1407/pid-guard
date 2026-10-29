# Manual demo script — keep this open on a second screen

**Prompt Injection Defense for LLM Agents (PID-Guard)**
Dev Singh (23BCE0794) · Sanchit Baghel (23BCE0241)

---

## Before you start

Open a terminal **inside the project folder**. Two ways:

- In File Explorer, hold **Shift**, right-click empty space in the folder, choose
  **"Open PowerShell window here"** or **"Open in Terminal"**.
- Or open Command Prompt and paste:

```bash
cd "C:\Users\dev singh\OneDrive\Desktop\prompt-injection-defense"
```

Sanity check — this should print a version number:

```bash
python --version
```

Nothing needs installing. No internet needed. No server.

---

## The five commands, in order

Total runtime is under 10 seconds of computer time. The rest is you talking.

### 1 · Show it is real code that passes its own tests — *0.7s*

```bash
python tests/test_pidguard.py
```

**Expect:** `41/41 passed`

> "41 automated tests across all five pipeline stages — normalisation,
> detection, policy, sanitisation, egress. Five of them are regression tests
> for bugs we found while building, which I can talk about."

---

### 2 · The attack, with and without the defence — *0.4s*  ← **your strongest moment**

```bash
python demo/demo_agent.py
```

**Expect:** three scenarios.

> **Scenario 1** — "Same agent, no middleware. It reads a support page that has
> an attacker's instruction hidden in an HTML comment. The agent opens the
> credentials file and posts the API key to the attacker's server. The user
> just sees a normal answer and never learns they were robbed."
>
> **Scenario 2** — "Identical agent, middleware switched on. The payload is
> detected, the content never reaches the model as an instruction, the network
> tools are revoked for that turn, and even the leaked key is redacted on the
> way out. Three independent layers, any one of which would have stopped it."
>
> **Scenario 3** — "And on a clean page it stays out of the way — ALLOW, all
> tools kept. A filter that blocks real work gets uninstalled in week one."

---

### 3 · Coverage across every attack family — *0.4s*

```bash
python demo/showcase.py
```

**Expect:** a 20-row table, `20/20 correct`.

> "14 attacks covering all eight families, plus six evasion techniques —
> zero-width characters, Cyrillic homoglyphs, base64, leetspeak, spaced-out
> letters, HTML comments. All caught. And six benign controls that must *not*
> be blocked — including one that literally says 'ignore my previous message',
> because when a *user* says that it's legitimate. That's the trust-tier idea."

Add `--verbose` if they want to see the evidence per case:

```bash
python demo/showcase.py --verbose
```

---

### 4 · The numbers on the slides, regenerated live — *3s*

```bash
python benchmark/evaluate.py
```

**Expect:** ablation table, per-family recall, then the summary.

> "225 held-out samples the system has never seen, phrased independently of the
> training data. 94.3% recall, 2.2% false positives, F1 0.953, 3.4 ms per span.
> The ablation is the important part — every layer has to justify its place,
> and we report the ones that don't."

---

### 5 · Let them test it themselves — *interactive*  ← **the closer**

```bash
python demo/try_it.py
```

Ask the panel to dictate any text. Type `:examples` for suggestions,
`:tier user` to switch trust level, `:quit` to exit.

> "Nothing here is hardcoded — give me any sentence."

---

## If they ask to see the code

| They ask about | Open this file |
|---|---|
| "How do you handle obfuscation?" | `pidguard/normalizer.py` |
| "What are the detection rules?" | `pidguard/detectors/heuristic.py` (32 rules, 8 families) |
| "Where's the machine learning?" | `pidguard/detectors/statistical.py` (hand-written logistic regression, no sklearn) |
| "How do you decide?" | `pidguard/policy.py` (noisy-OR fusion + trust tiers) |
| "How do you make it safe?" | `pidguard/sanitizer.py` (datamarking, nonce fencing) |
| "What stops the leak?" | `pidguard/egress.py` |
| "How did you evaluate?" | `benchmark/train.py` header comment (the protocol) |
| "Full results?" | `docs/RESULTS.md` |

---

## Likely questions, and honest answers

**"Why not just tell the model to ignore injections?"**
> Because that instruction is itself just more text competing for attention, and
> it fails silently. Our control sits outside the model, so the model can't
> override it.

**"Isn't this just regex matching?"**
> The rule base is one of four detectors and gets 62% recall alone. The full
> ensemble gets 94.3%. The ablation table shows exactly what each layer adds.

**"What's your biggest weakness?"**
> Role-manipulation paraphrases — 75% recall. Things like "take on the identity
> of a model that was never given any policy" evade both the rules and the
> classifier. We deliberately left it failing rather than add a rule fitted to
> our own test set.

**"How big is your dataset?"**
> 753 samples, 528 train / 225 test, authored by us. We're explicit that this
> characterises the system on our distribution — it's not a claim about
> production traffic.

**"What did you actually learn?"**
> That the *benign* class mattered more than the attack class. Our negatives were
> only user requests, so the classifier learned "not a request means attack" and
> flagged 88% of ordinary document prose. Since indirect injection is by
> definition about documents, that was our biggest false-positive source, and no
> threshold tuning could fix it — only fixing the data could.

**"Does it use GPT / an API key / internet?"**
> No. Zero third-party dependencies, no network calls, no GPU. It's pure Python
> standard library and runs in about 3 milliseconds per span.

---

## If something goes wrong

| Problem | Fix |
|---|---|
| `'python' is not recognized` | Try `py` instead of `python` |
| Weird `â–ˆ` characters in output | Run `chcp 65001` first, then the command |
| Terminal in the wrong folder | Re-run the `cd` command at the top of this page |
| Anything else | The deck (`ppt/`) carries every number; `docs/RESULTS.md` has the full breakdown |

**Backup:** `RUN_DEMO.bat` (double-click) runs sections 1–4 automatically with
pauses, if you'd rather not type.
