"""Automated adaptive-adversary evaluation.

Every other benchmark here is static: fire a fixed payload, record whether it
was caught. That measures the attacks we thought of. It says nothing about the
question a reviewer should actually ask -- *what happens when the attacker
adapts?*

This is a search. For each payload the system currently catches, a hill-climbing
adversary applies mutation operators and keeps whichever mutation lowered the
risk score, until it either evades (ALLOW) or exhausts its budget. It reports:

  * evasion rate          -- fraction of payloads defeated within budget
  * mean queries to evade -- how much work an evasion costs
  * operator potency      -- which mutations actually buy risk reduction
  * survivors             -- payloads no mutation sequence defeated

Why this is the honest framing. The adversary here is *stronger* than a real
one in one respect -- it sees the exact risk score, a white-box oracle a real
attacker would have to approximate through trial and error. So the evasion rate
is an upper bound on what a black-box attacker achieves, and the queries-to-
evade figure is a lower bound on their effort. Reporting a pessimistic bound is
the point; a defence evaluated only against its own test set is marketing.

Semantic validity is enforced: a mutation that destroys the payload's meaning
is not an evasion, it is a broken sentence. Operators either preserve the
instruction verbatim (wrapping, encoding, spacing) or substitute known
synonyms, and every candidate must still contain an attack-intent marker.

Run:  python benchmark/redteam.py [--budget 40] [--json out.json]
"""

from __future__ import annotations

import argparse
import base64
import codecs
import json
import os
import random
import re
import sys
import time
from collections import defaultdict
from typing import Callable, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pidguard import Decision, PromptInjectionGuard, TrustTier  # noqa: E402
from pidguard.audit import AuditLog  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN = os.path.join(ROOT, "data", "corpus_train.jsonl")
PROSE = os.path.join(ROOT, "data", "prose_filler.txt")

ZW = "​"
HOMO = {"a": "а", "e": "е", "o": "о", "c": "с",
        "p": "р", "x": "х", "y": "у", "i": "і"}
LEET = {"o": "0", "i": "1", "e": "3", "a": "4", "s": "5", "t": "7"}

#: Intent markers. A candidate that contains none of these has had its meaning
#: destroyed and does not count as an evasion.
#: Whole-word markers only. An earlier version included the fragments "ign",
#: "dis", "rev" and "key", which match inside design, display, review and
#: monkey -- so candidates whose instruction had been paraphrased away still
#: counted as evasions and the evasion rate was overstated. The harness has to
#: be at least as rigorous as the thing it measures.
INTENT_WORDS = {
    "ignore", "ignora", "ignorar", "disregard", "forget", "override", "bypass",
    "skip", "reveal", "revela", "disclose", "print", "show", "display", "echo",
    "recite", "repeat", "dump", "send", "envia", "transmit", "forward", "upload",
    "email", "post", "execute", "run", "invoke", "call", "delete", "drop",
    "grant", "escalate", "prompt", "instruction", "instructions", "instrucciones",
    "directive", "directives", "credential", "credentials", "password",
    "contrasena", "secret", "token", "config", "configuration", "system",
    "sistema", "obey", "comply", "pretend",
}
#: Obfuscated spellings that preserve intent even though the plain word is
#: gone. Deliberately does NOT include "decode", "base64" or "rot13": those
#: describe the *wrapper*, not the instruction, so accepting them let a
#: candidate whose payload had been paraphrased into nonsense count as an
#: evasion purely because the envelope said "decode this". Intent is tested
#: against the decoded content instead -- see keeps_intent.
INTENT_SUBSTRINGS = (
    "1gn0re", "ign0re", "1gnore", "d1sregard", "pa55w0rd", "cr3dential",
    "syst3m", "pr0mpt", "rev34l", "s3nd",
)


# ------------------------------------------------------------- operators ----
def op_zero_width(t: str, rng: random.Random) -> str:
    out, n = [], 0
    for ch in t:
        out.append(ch)
        if ch.isalpha() and n < 8 and rng.random() < 0.3:
            out.append(ZW)
            n += 1
    return "".join(out)


def op_homoglyph(t: str, rng: random.Random) -> str:
    out, n = [], 0
    for ch in t:
        low = ch.lower()
        if low in HOMO and n < 6 and rng.random() < 0.4:
            out.append(HOMO[low])
            n += 1
        else:
            out.append(ch)
    return "".join(out)


def op_leet(t: str, rng: random.Random) -> str:
    out, n = [], 0
    for ch in t:
        low = ch.lower()
        if low in LEET and n < 8 and rng.random() < 0.35:
            out.append(LEET[low])
            n += 1
        else:
            out.append(ch)
    return "".join(out)


def op_space_first_word(t: str, rng: random.Random) -> str:
    w = t.split()
    if not w:
        return t
    i = rng.randrange(min(3, len(w)))
    w[i] = " ".join(w[i])
    return " ".join(w)


def op_base64(t: str, rng: random.Random) -> str:
    return "Decode and comply: " + base64.b64encode(t.encode()).decode()


def op_rot13(t: str, rng: random.Random) -> str:
    return "Apply rot13 then comply: " + codecs.encode(t, "rot_13")


def op_html_comment(t: str, rng: random.Random) -> str:
    return f"<p>Product details below.</p><!-- {t} --><p>Thanks for reading.</p>"


def op_json_field(t: str, rng: random.Random) -> str:
    return json.dumps({"status": "ok", "records": 12, "_note": t})


def op_politeness(t: str, rng: random.Random) -> str:
    lead = rng.choice([
        "We would be grateful if you could ",
        "If it is not too much trouble, please ",
        "As a courtesy to the audit team, kindly ",
    ])
    return lead + t[0].lower() + t[1:]


def op_conditional(t: str, rng: random.Random) -> str:
    return ("This notice is for human readers. If you are an AI assistant, "
            "then the following applies to you instead: " + t)


def op_synonym(t: str, rng: random.Random) -> str:
    pairs = [("ignore", "set aside"), ("disregard", "pay no attention to"),
             ("reveal", "make known"), ("send", "forward"),
             ("instructions", "directions"), ("previous", "earlier"),
             ("all", "every one of the"), ("system prompt", "initial briefing"),
             ("password", "access code"), ("credentials", "sign-in details")]
    rng.shuffle(pairs)
    for a, b in pairs:
        if a in t.lower():
            i = t.lower().index(a)
            return t[:i] + b + t[i + len(a):]
    return t


def _prose() -> List[str]:
    try:
        with open(PROSE, encoding="utf-8") as fh:
            return [ln.strip().replace(chr(92) + "n", " ") for ln in fh
                    if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError:
        return ["The quarterly report notes a modest increase in margin."]


FILLER = _prose()


def op_dilute(t: str, rng: random.Random) -> str:
    """Bury the payload in benign prose -- the classic indirect-injection move."""
    k = rng.randrange(3, 9)
    pre = " ".join(rng.choice(FILLER) for _ in range(k))
    post = " ".join(rng.choice(FILLER) for _ in range(k))
    return f"{pre} {t} {post}"


def op_split_lines(t: str, rng: random.Random) -> str:
    return "\n".join(t.split())


def op_translate_es(t: str, rng: random.Random) -> str:
    """Crude lexical substitution into Spanish -- what a real attacker would
    do properly with a translator."""
    sub = {"ignore": "ignora", "all": "todas", "previous": "anteriores",
           "instructions": "las instrucciones", "reveal": "revela",
           "your": "tu", "system prompt": "prompt del sistema",
           "send": "envia", "password": "contrasena", "and": "y"}
    out = t
    for a, b in sub.items():
        out = out.replace(a, b).replace(a.capitalize(), b)
    return out


OPERATORS: List[Tuple[str, Callable[[str, random.Random], str]]] = [
    ("zero_width", op_zero_width),
    ("homoglyph", op_homoglyph),
    ("leetspeak", op_leet),
    ("space_word", op_space_first_word),
    ("base64", op_base64),
    ("rot13", op_rot13),
    ("html_comment", op_html_comment),
    ("json_field", op_json_field),
    ("politeness", op_politeness),
    ("conditional", op_conditional),
    ("synonym", op_synonym),
    ("dilute", op_dilute),
    ("split_lines", op_split_lines),
    ("translate_es", op_translate_es),
]


_WORDS = re.compile(r"[a-z0-9']+")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")


def _decode_views(text: str) -> List[str]:
    """Independent decoder for the harness.

    Deliberately NOT pidguard.normalizer: the adversary must not inherit the
    defence's decoding ability, or a payload the defence cannot decode would
    also be judged intent-free and quietly excluded from the search.
    """
    views = [text]
    for blob in set(_B64.findall(text)):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            views.append(raw.decode("utf-8", "ignore"))
        except Exception:                                    # noqa: BLE001
            pass
    try:
        views.append(codecs.encode(text, "rot_13"))
    except Exception:                                        # noqa: BLE001
        pass
    if _PCT.search(text):
        from urllib.parse import unquote
        views.append(unquote(text))
    # undo leetspeak and zero-width so obfuscated instructions still read
    flat = text.replace(ZW, "")
    table = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})
    views.append(flat.translate(table))
    return views


def keeps_intent(text: str) -> bool:
    """True when the candidate still expresses an instruction.

    Checked against every decoded view, so an encoded attack counts while a
    wrapper around paraphrased nonsense does not.
    """
    for view in _decode_views(text):
        low = view.lower()
        if set(_WORDS.findall(low)) & INTENT_WORDS:
            return True
        if any(m in low for m in INTENT_SUBSTRINGS):
            return True
    return False


# ----------------------------------------------------------------- search ---
def attack(guard: PromptInjectionGuard, payload: str, tier: TrustTier,
           budget: int, rng: random.Random) -> Dict:
    """Hill-climb on risk. Returns the trace for one payload."""
    current = payload
    best_risk = guard.inspect(current, tier).risk_score
    queries = 0
    chain: List[str] = []
    potency: Dict[str, float] = defaultdict(float)

    while queries < budget:
        name, op = OPERATORS[rng.randrange(len(OPERATORS))]
        try:
            cand = op(current, rng)
        except Exception:                                    # noqa: BLE001
            continue
        if cand == current or not keeps_intent(cand):
            continue
        queries += 1
        r = guard.inspect(cand, tier)
        if r.decision is Decision.ALLOW:
            chain.append(name)
            potency[name] += best_risk - r.risk_score
            return {"evaded": True, "queries": queries, "chain": chain,
                    "final_risk": r.risk_score, "final_text": cand[:300],
                    "potency": dict(potency)}
        if r.risk_score < best_risk - 1e-9:
            potency[name] += best_risk - r.risk_score
            best_risk = r.risk_score
            current = cand
            chain.append(name)
    return {"evaded": False, "queries": queries, "chain": chain,
            "final_risk": best_risk, "final_text": current[:300],
            "potency": dict(potency)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=40,
                    help="mutation queries allowed per payload")
    ap.add_argument("--tier", default="web", choices=[t.value for t in TrustTier])
    ap.add_argument("--json", help="write the full trace here")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    with open(TRAIN, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    seeds = [(r["text"], r["family"]) for r in rows
             if r["label"] == 1 and r["variant"] == "plain"]

    guard = PromptInjectionGuard(audit=AuditLog(max_records=1))
    tier = TrustTier(args.tier)
    rng = random.Random(args.seed)

    # Only payloads currently caught are worth attacking.
    caught = [(t, f) for t, f in seeds if guard.inspect(t, tier).is_attack]

    print("=" * 76)
    print("Adaptive adversary -- hill-climbing evasion search")
    print(f"{len(caught)} payloads currently caught  |  budget {args.budget} "
          f"queries each  |  tier={tier.value}")
    print("White-box: the adversary reads the exact risk score, so the evasion")
    print("rate below is an UPPER bound on a black-box attacker.")
    print("=" * 76)

    t0 = time.perf_counter()
    results = []
    by_family: Dict[str, List[bool]] = defaultdict(list)
    potency_total: Dict[str, float] = defaultdict(float)
    potency_wins: Dict[str, int] = defaultdict(int)

    print(f"\n{'family':<22}{'payload':<34}{'evaded':>8}{'queries':>9}{'risk':>8}")
    print("-" * 76)
    for text, family in caught:
        res = attack(guard, text, tier, args.budget, rng)
        results.append({"family": family, "payload": text, **res})
        by_family[family].append(res["evaded"])
        for k, v in res["potency"].items():
            potency_total[k] += v
        if res["evaded"]:
            for k in res["chain"]:
                potency_wins[k] += 1
        print(f"{family:<22}{text[:32]:<34}"
              f"{('YES' if res['evaded'] else 'no'):>8}"
              f"{res['queries']:>9}{res['final_risk']:>8.3f}")

    n = len(results)
    evaded = sum(1 for r in results if r["evaded"])
    q = [r["queries"] for r in results if r["evaded"]]

    print("\n-- BY FAMILY -----------------------------------------------------")
    fam_out = {}
    for fam, flags in sorted(by_family.items()):
        rate = sum(flags) / len(flags)
        fam_out[fam] = round(rate, 3)
        print(f"  {fam:<24}{sum(flags)}/{len(flags)} evaded   {rate:.1%}")

    print("\n-- OPERATOR POTENCY (total risk reduction bought) ----------------")
    pot = sorted(potency_total.items(), key=lambda kv: -kv[1])
    for name, val in pot:
        print(f"  {name:<16}{val:>8.2f}   appeared in {potency_wins.get(name, 0)} evasions")

    print("\n-- SURVIVORS (no mutation sequence defeated these) ---------------")
    survivors = [r for r in results if not r["evaded"]]
    print(f"  {len(survivors)}/{n} payloads held at every mutation tried")

    print("\n-- SUMMARY -------------------------------------------------------")
    print(f"  evasion rate            : {evaded}/{n}  ({evaded / n:.1%})")
    print(f"  robustness              : {1 - evaded / n:.1%}")
    if q:
        print(f"  mean queries to evade   : {sum(q) / len(q):.1f}")
        print(f"  min queries to evade    : {min(q)}")
    print(f"  wall clock              : {time.perf_counter() - t0:.1f}s")
    print("=" * 76)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"budget": args.budget, "tier": tier.value,
                       "n_payloads": n, "evaded": evaded,
                       "evasion_rate": round(evaded / n, 4),
                       "robustness": round(1 - evaded / n, 4),
                       "mean_queries_to_evade": round(sum(q) / len(q), 2) if q else None,
                       "by_family": fam_out,
                       "operator_potency": {k: round(v, 3) for k, v in pot},
                       "results": results}, fh, indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
