/**
 * Sections 4-8 and document assembly. Run this, not generate.js:
 *
 *   node report/generate2.js
 */

const fs = require("fs");
const path = require("path");
const H = require("./build_report.js");
const { C, AUTHORS } = require("./generate.js");
const {
  AlignmentType, Document, Footer, PageBreak, PageNumber, Packer, Paragraph,
  TextRun, E, ML, RT, LM, CAL, F, pc, f3, TNR, body, rich, h1, h2, h3, bullet,
  caption, mono, centre, gap, table, figStage, figBand, figArrow, figImage,
  codeBlock,
} = H;

// Set this to the repository URL once the code is pushed. Left empty,
// the report states that the source accompanies the submission.
const REPO_URL = process.env.REPO_URL
  || "Not published; source submitted with this report";

// ═══════════════ 4. DESIGN APPROACH AND DETAILS ═══════════════
C.push(h1("4. Design Approach and Details"),
h2("4.1 System Architecture"),
body("Fig. 2 shows the layered architecture. The presentation layer collects a span of text together with the channel it arrived on and sends a JSON request to the service layer, which validates it and calls the middleware core. The core runs the span through five stages in order: canonicalisation, segmentation into overlapping windows, scoring by five independent detectors, evidence fusion with a policy decision, and neutralisation. Only then does any part of the span reach the language model. On the return path the egress guard inspects the model's reply and validates any tool call it proposes against the capabilities that survived the decision. The detection layer draws its thresholds and weights from read-only JSON artefacts in the model and data layer. The offline training path, drawn dashed because it never runs in the request path, produces those artefacts. Table 4 maps each layer to its modules."),
figImage("fig_architecture.png", 1140 / 724),
caption("Fig. 2. System Architecture"),
table(["Layer", "Files / modules", "Responsibility"], [
  ["Presentation",
   "web/console.html; demo/showcase.py, demo_agent.py, try_it.py; tests/test_pidguard.py",
   "Collects the text and its trust tier, sends the request, and shows the decision with its evidence. No detection logic runs here, so no verdict shown in the browser is computed in the browser."],
  ["Service",
   "web/server.py",
   "Validates requests and enforces size limits; exposes six JSON endpoints over the Python standard-library HTTP server; binds to the loopback interface only."],
  ["Middleware core",
   "pidguard/middleware.py, normalizer.py, segmenter.py, policy.py, sanitizer.py, egress.py, audit.py, types.py, config.py",
   "Composes the six pipeline stages behind one entry point, PromptInjectionGuard. Holds the trust tiers, the fusion rule, the decision thresholds, the capability gate and the audit trail."],
  ["Detection",
   "pidguard/detectors/base.py, heuristic.py, multilingual.py, statistical.py, semantic.py, structural.py",
   "Five independent mechanisms behind a common interface: 32 signature rules, a 12-language lexicon, a logistic-regression classifier, a nearest-neighbour index over 60 exemplars, and content-blind structural analysis."],
  ["Model and data",
   "pidguard/models/lr_model.json, exemplars.json, calibration.json; data/corpus_train.jsonl, corpus_test.jsonl, corpus_multilingual.jsonl",
   "Trained weights, the exemplar index and the calibrated thresholds, loaded once at import. Corpora are held as JSONL so every sample can be inspected directly."],
  ["Offline training and evaluation",
   "data/build_corpus.py, build_multilingual.py; benchmark/train.py, evaluate.py, evaluate_multilingual.py, redteam.py, evaluate_llm.py, llm_sanity.py",
   "Builds the corpora, fits the classifier, selects every threshold by leave-one-family-out cross-validation, and runs the held-out, cross-lingual, adversarial and end-to-end evaluations. None of this is in the request path."],
], [1500, 2950, 4316]),
caption("Table 4. Layers, files, and responsibilities"),
body("The design decision everything else rests on is that trust belongs to the channel the text arrived on, not to the text. Five tiers are distinguished, each carrying a multiplier applied to the fused risk score. The same sentence is therefore treated differently depending on where it came from: a user is entitled to write “ignore my previous message”, and a scraped web page is not. Table 5 gives the tiers."),
table(["Trust tier", "Multiplier", "What arrives on this channel"], [
  ["SYSTEM", "0.00", "The developer's own prompt. Never inspected, because it is supposed to contain instructions."],
  ["USER", "0.75", "What the operator typed. Trusted, but not exempt: an operator can paste in something they were sent."],
  ["TOOL", "1.15", "Output returned by a tool the agent called."],
  ["RETRIEVED", "1.25", "A document fetched from a store or index."],
  ["WEB", "1.40", "Content fetched from the open internet. Trusted least."],
], [1700, 1450, 5616]),
caption("Table 5. Trust tiers and their risk multipliers"),
h2("4.2 Design"),
body("Fig. 3 summarises the decision logic that the two algorithms below implement. A span is inspected unless it came from the developer's own prompt, which is trusted by construction. It is then canonicalised, cut into overlapping windows and scored by five detectors. The scores are fused, weighted by the trust tier and compared against two thresholds, which yields one of three outcomes. Independently of that outcome, every tool associated with a detected attack family is revoked for the duration of the turn."),
figImage("fig_decision.png", 1000 / 700),
caption("Fig. 3. Decision logic and the three outcomes"),
h3("4.2.1 Algorithm 1 — Windowed Detection and Risk Fusion"),
body("This algorithm decides whether a span of text is allowed to influence the agent. Two parts of it are not obvious. Windowing stops a short payload from being diluted by a long, innocent document. The multiple-comparisons correction then stops the resulting maximum-over-windows statistic from pushing up false positives as documents get longer, which is the price windowing would otherwise charge."));
[
  "Input: raw text T, trust tier t, available tool set A.",
  "If t is SYSTEM, return ALLOW; the developer's own prompt is not inspected.",
  "R ← Canonicalise(T): strip zero-width and bidirectional controls; apply Unicode NFKC; fold homoglyphs within mixed-script tokens only; reveal hypertext comments and concealed spans, hoisting their content onto its own line; decode base64, hexadecimal, percent and ROT13 payloads. Record every transformation applied.",
  "W ← Segment(R): split into units at sentence, line and block boundaries; group into overlapping windows of at most " + CAL.settings.window_chars + " characters with one unit of overlap.",
  "For each window w in W: for each detector d in {heuristic, multilingual, statistical, semantic, structural}, collect detections, each carrying a severity and a confidence. A detector that raises an exception contributes a medium-severity detection rather than silence.",
  "For each window, fuse within each detector by noisy-OR over severity × confidence, cap the per-detector contribution, weight by detector, then fuse across detectors by noisy-OR.",
  "Apply an agreement bonus when three or more detectors concur, and a discount when a lone non-signature detector fires without corroboration.",
  "Multiply by the tier multiplier τ(t) to obtain the window risk.",
  "Let Rmax be the greatest window risk and c the concentration, (Rmax − mean of the remainder) / Rmax.",
  "Inflate both decision thresholds by (1 + k · log₂|W| · (1 − c)), a discrete Bonferroni analogue damped by concentration so that padding a document cannot purchase leniency.",
  "Return BLOCK if Rmax exceeds the inflated block threshold, SANITISE if it exceeds the inflated sanitise threshold, otherwise ALLOW; and revoke from A every capability associated with a detected attack family whose evidence exceeds the gating floor.",
].forEach((t, i) => C.push(rich([{ text: (i + 1) + ". ", bold: true }, { text: t }],
  { spacing: { after: 70 } })));

C.push(body("We fuse with noisy-OR instead of a vote for two reasons. Several weak but independent signals ought to be able to add up to a decision, and one detector firing on the same match repeatedly ought not to be able to saturate the score. The concentration term carries information of its own. An innocent document is evenly unremarkable all the way through. A poisoned one has a single region that scores far above everything around it."),
h3("4.2.2 Algorithm 2 — Neutralisation and Egress Control"),
body("If we blocked every suspicious document we would end up with an agent that refuses to read the web, which nobody would use. The second algorithm keeps the information and destroys only its ability to give orders. It then guards the outbound path on the working assumption that the first algorithm may have missed something."));
[
  "Input: canonical text R, tier t, detections D, the model's eventual response S and any proposed tool call (n, args).",
  "Datamark: interleave a private invisible separator (U+2063) into every whitespace position of R, so that the span no longer tokenises as a conversational turn while remaining readable.",
  "Fence: wrap the marked span in delimiters carrying a fresh 64-bit random nonce, so that an adversary cannot close the fence without guessing it.",
  "Defang: rewrite each detected span as inert quoted evidence, so that both the agent and a later auditor can see what was attempted.",
  "Prepend a provenance banner stating the source tier and the detected attack families; the integrator adds the corresponding security contract to the system prompt once.",
  "On egress, scan S for credential material against eight patterns, for verbatim reproduction of protected system-prompt text, and and for zero-click beacons, meaning markdown images whose host is not allow-listed or whose query carries a data-bearing value. Redact each match.",
  "Validate (n, args) against the capability set surviving step 11 of Algorithm 1; reject the call if n was revoked, and recursively scan args as untrusted output in their own right.",
].forEach((t, i) => C.push(rich([{ text: (i + 1) + ". ", bold: true }, { text: t }],
  { spacing: { after: 70 } })));

C.push(h3("4.2.3 The Detector Ensemble"),
body("We chose the five detectors so that they fail in uncorrelated ways. Each one asks a different question about the same piece of text, which means a single evasion trick does not defeat all five at once."),
table(["Detector", "Question answered", "Mechanism"], [
  ["Heuristic", "Does this match a known attack signature?", "32 regular-expression rules across 8 families, matched over up to three text views, with a fuzzy near-miss fallback"],
  ["Multilingual", "Is this an injection in another language?", "Lexicon over " + ML.languages.length + " languages; fires only when two compatible categories co-occur within one language"],
  ["Statistical", "How injection-like is this statistically?", "Hashed word 1–2-grams and character 4-grams into 2¹⁵ buckets; L2-regularised logistic regression trained by SGD"],
  ["Semantic", "Which known attack is this closest to?", "Cosine similarity to an index of 60 exemplars, yielding an auditable nearest neighbour"],
  ["Structural", "Does this behave like a command aimed at an agent?", "Content-blind: clause-initial imperative density, second-person adjacent to obligation, fenced blocks, outbound URL shape, entropy"],
], [1733, 3160, 3873]),
caption("Table 6. The five detectors and their complementary failure modes."),
new Paragraph({ children: [new PageBreak()] }));

// ═══════════ 5. EXPERIMENTAL SETUP AND OUTPUT ═══════════
C.push(h1("5. Experimental Setup and Output"),
h2("5.1 Experimental Setup"),
body("We ran every experiment on an ordinary laptop (x86-64, 8 logical cores, 16 GB memory, Windows 11) under Python 3.11.4, with no third-party runtime dependency. All timings are single-threaded and cover the complete pipeline, not one stage of it."),
body("The corpus is 753 samples we wrote ourselves, split into 528 for training and 225 held out for testing. We applied four safeguards, each aimed at a specific way an evaluation like this can flatter itself:"));
[
  "Test seeds are phrased independently of training seeds, so that no template is shared between splits and the reported figures measure generalisation rather than memorisation.",
  "Splitting is grouped by seed identifier, so that every obfuscated variant of a sentence remains in the same fold; without this an augmented near-duplicate leaks across the boundary and every figure is optimistic.",
  "The test file is never opened by any training or calibration script.",
  "Pipeline-level parameters were chosen by leave-one-family-out cross-validation. A whole attack category is withheld from the classifier and the exemplar index, and recall is then measured on that unseen category. We did this because a conventional validation split saturated near 1.0 and could not tell two settings apart.",
].forEach(t => C.push(bullet(t)));

C.push(body("We ran three further evaluations beyond the held-out set. A cross-lingual benchmark of " + ML.n_samples + " samples spans " + ML.languages.length + " languages, comprising " + ML.n_attack + " attacks and " + (ML.n_samples - ML.n_attack) + " hard negatives, which are foreign-language documents using the same vocabulary as the attacks. An adaptive adversary runs a hill-climbing evasion search over fourteen mutation operators with a budget of forty queries per payload. An end-to-end evaluation puts a local instruct model through a real agent loop under three conditions."),
body("Throughout, the objective we optimised was F1 minus 0.55 times the false-positive rate, subject to a floor on recall. False positives are inside the objective, not used as a tie-breaker afterwards, because a filter that blocks legitimate work gets uninstalled."),
h2("5.2 Output of the Proposed System"),
body("Table 7 gives the ablation on the held-out English set. Each configuration is a strict superset of the one above it, so every row shows what that one extra layer bought."),
table(["Configuration", "Precision", "Recall", "F1", "FPR"],
  [["Keyword blocklist (baseline)", f3(E.baseline.precision), f3(E.baseline.recall), f3(E.baseline.f1), f3(E.baseline.fpr)]]
   .concat(Object.entries(E.ablation).map(([k, v]) =>
     [k === "FULL ENSEMBLE" ? "Full ensemble" : k.charAt(0).toUpperCase() + k.slice(1),
      f3(v.precision), f3(v.recall), f3(v.f1), f3(v.fpr)])),
  [2956, 1453, 1453, 1453, 1451]),
caption("Table 7. Ablation on the held-out set (" + E.n_samples + " samples: " + E.n_attack + " attack, " + (E.n_samples - E.n_attack) + " benign)."),
body("Two things in this table are worth pointing out precisely because they do not flatter us. The semantic and structural detectors are weak on their own, reaching F1 of " + f3(E.ablation["semantic only"].f1) + " and " + f3(E.ablation["structural only"].f1) + " respectively. They earn their place by corroborating the others. Adding the semantic detector to the heuristic and statistical pair lifts recall from " + f3(E.ablation["heuristic + statistical"].recall) + " to " + f3(E.ablation["heuristic + stat + semantic"].recall) + ". They also attach readable evidence to a decision, which a bare probability cannot. The keyword baseline reaches only " + pc(E.baseline.recall) + " recall. That is not a rigged comparison, it is the point being demonstrated: the test attacks were deliberately written away from stock wording, which is exactly what a real attacker would do."),
table(["Attack family", "Recall"], Object.entries(E.recall_by_family)
  .sort((a, b) => b[1] - a[1])
  .map(([k, v]) => [k.replace(/_/g, " "), f3(v)]), [4383, 4383]),
caption("Table 8. Recall by attack family. Role manipulation remains the weakest category."),
table(["Evasion technique", "Recall"], Object.entries(E.recall_by_variant)
  .sort((a, b) => b[1] - a[1])
  .map(([k, v]) => [k.replace(/_/g, " "), f3(v)]), [4383, 4383]),
caption("Table 9. Recall by evasion technique. The wrap-indirect row is the indirect-injection case: a payload embedded in an otherwise benign document."),
table(["Measure", "Value"], [
  ["Median added latency", E.latency_ms.p50 + " ms"],
  ["Mean added latency", E.latency_ms.mean + " ms"],
  ["95th percentile", E.latency_ms.p95 + " ms"],
  ["99th percentile", E.latency_ms.p99 + " ms"],
  ["Runtime dependencies", "0"],
], [4383, 4383]),
caption("Table 10. Latency, single-threaded, complete pipeline."),
new Paragraph({ children: [new PageBreak()] }));

// ═══════════════════ 6. RESULT ANALYSIS ═══════════════════
C.push(h1("6. Result Analysis"),
h2("6.1 Comparison with Existing Systems"),
body("Table 11 compares our system with the defences surveyed in Section 2. Where a direct comparison is possible we evaluated on the same held-out set. Where the published work does not allow one, we describe the difference instead of inventing a number."),
table(["System", "Recall", "FPR", "Model-agnostic", "Fails safe"], [
  ["Keyword blocklist", f3(E.baseline.recall), f3(E.baseline.fpr), "Yes", "Yes"],
  ["Prompt-level instruction (Hines et al.)", "n/a — model-dependent", "n/a", "No", "No — silent"],
  ["Dual LLM pattern (Willison)", "n/a — architectural", "n/a", "Yes", "Yes"],
  ["Signature rules only (ours, ablated)", f3(E.ablation["heuristic only"].recall), f3(E.ablation["heuristic only"].fpr), "Yes", "Yes"],
  ["Proposed system (PID-Guard)", f3(F.recall), f3(F.fpr), "Yes", "Yes"],
], [3058, 1427, 1223, 1529, 1529]),
caption("Table 11. Comparison with existing approaches."),
body("Two honest qualifications go with that table. A prompt-level defence cannot be given a recall figure that is independent of the model it runs on, and that is exactly the criticism of it: how well it works is a property of the model, not of the defence. The dual LLM pattern is an architecture, not a classifier, so there is no comparable measurement to make. It does carry a cost we do not, namely a second inference pass on every request."),
h3("6.1.1 Cross-Lingual Evaluation"),
body("The literature we surveyed is written and evaluated in English. When we ran the same payloads through our ensemble in other languages, we found a complete bypass. An attacker did not need any clever technique. They only had to change language."),
table(["Configuration", "Recall", "FPR on controls"], [
  ["English-only ensemble", pc(ML.before.recall), f3(ML.before.fpr)],
  ["With cross-lingual detector", pc(ML.after.recall), f3(ML.after.fpr)],
], [3669, 2548, 2549]),
caption("Table 12. Cross-lingual benchmark: " + ML.n_samples + " samples, " + ML.languages.length + " languages, " + (ML.n_samples - ML.n_attack) + " hard negatives using the same vocabulary as the attacks."),
body("The hard negatives are the part of this result that matters. Foreign-language documents containing the words for password, settings, system and instructions are not blocked. A detection needs two compatible categories to occur together inside one language, and it needs at least one matched word to be distinctive to that language instead of a cognate it shares with English. Without that second condition the detector fires on any French page that mentions instructions."),
h3("6.1.2 Adaptive Adversary"),
body("A static benchmark only measures the attacks its authors thought of. To get a bound against an attacker who adapts, we wrote a hill-climbing search that mutates each payload we currently catch, keeps whichever mutation lowered the risk score, and repeats until it either evades or uses up a budget of forty queries."),
table(["Measure", "Value"], [
  ["Robustness (40-query budget)", pc(RT.robustness)],
  ["Evasion rate", pc(RT.evasion_rate)],
  ["Mean queries per successful evasion", String(RT.mean_queries_to_evade)],
  ["Payloads never defeated", (RT.n_payloads - RT.evaded) + " of " + RT.n_payloads],
], [4383, 4383]),
caption("Table 13. Adaptive adversary. The search is white-box, meaning it reads our exact risk score, so the evasion rate is an upper bound on what a black-box attacker achieves and the query count a lower bound on their effort."),
body("This evaluation improved the system more than any other. It found two defects that every static test had missed. The first was in our ROT13 handling: we only accepted a decode when the plaintext happened to contain one of five hardcoded keywords, and that alone accounted for most successful evasions. The second was that hiding a payload inside an HTML comment succeeded in a single mutation, because the revealed instruction was averaged in with the surrounding markup. We replaced the keyword check with a language-likeness test, on the reasoning that an attacker picks the words but cannot stop plaintext reading like language while ciphertext does not. For the second we hoist concealed content into a scan window of its own. Robustness went from 21.7% to " + pc(RT.robustness) + "."),
h3("6.1.3 End-to-End Evaluation Against a Language Model"),
body("Everything above measures the filter. The claim that actually matters is whether an agent behind this middleware gets hijacked, and answering that needs a real model. We ran a local instruct model (" + LM.model + ") was run through a genuine agent loop over " + LM.n_poisoned + " poisoned and " + LM.n_clean + " clean documents at temperature zero, under three conditions."),
table(["Condition", "Attack success"], [
  ["A — naive agent, no defensive instruction", pc(LM.asr_naive, 0)],
  ["B — prompt-level defence in the system prompt", pc(LM.asr_prompt_defended, 0)],
  ["C — PID-Guard middleware", pc(LM.asr_guarded, 0)],
  ["Poisoned documents withheld before the model", pc(LM.withheld_rate, 0)],
  ["Utility on clean documents (A → C)", pc(LM.utility_naive, 0) + " → " + pc(LM.utility_guarded, 0)],
], [5504, 3262]),
caption("Table 14. End-to-end evaluation. Attack success is behavioural: the model invoked a dangerous tool."),
body("This model resisted every payload even with no defensive instruction at all, so there is no difference between conditions to claim and we do not claim one. What the figures do support is narrower and still worth having. The guard withheld " + pc(LM.withheld_rate, 0) + " of poisoned documents before the model ever saw them, and clean-document utility was unchanged, which is the usual place a filter goes wrong. We report the result as we measured it."),
body("A zero is also exactly what a broken harness reports, so we built a positive control in which the operator legitimately asks for each dangerous action. The model calls the file-reading and mail-sending tools and our parser recognises both, which establishes that the measurement could have seen a hijack if one had happened. Writing that control exposed two defects in our own measurement code, and both of them had been biasing attack success downward. One was a regular expression that could not match nested JSON, so every genuine tool call was read as no call at all. The other was that truncated tool calls were also being read as refusals. We fixed both and regenerated every figure."),
new Paragraph({ children: [new PageBreak()] }));

// ═══════════ 7. CONCLUSION AND FUTURE WORKS ═══════════
C.push(h1("7. Conclusion and Future Works"),
body("We set out to enforce, outside the model, a separation that the model cannot enforce for itself. The middleware we built reaches " + pc(F.recall) + " recall at " + pc(F.fpr) + " false positives on a held-out English set, " + pc(ML.after.recall) + " recall across " + ML.languages.length + " languages with no false positives on foreign-language controls, and " + pc(RT.robustness) + " robustness against an adaptive white-box adversary, adding " + E.latency_ms.p50 + " milliseconds per span with no third-party dependency."),
body("The findings we learned most from were the negative ones, and three are worth recording. The first is that the makeup of the benign class mattered more than the makeup of the attack class. We first trained the classifier on benign data made up only of user requests. It quietly learned the rule “if this is not a request, it is an attack”, and went on to score eighty-eight per cent of ordinary document prose as injection. Since indirect injection is by definition about documents, that was our single biggest source of false positives, and no amount of threshold tuning would have fixed it. Only fixing the data fixed it. The second is that evaluating in one language hid a complete bypass from us for most of the project. The third is that every evaluation harness we wrote contained at least one defect that made our results look better than they were, and in each case we only found it by building a control for it."),
body("We should be clear about the limitations. The corpus was written by us and holds 753 samples, so our figures describe the system on that distribution and are not a claim about production traffic. Role manipulation is still our weakest family at " + f3(E.recall_by_family.role_manipulation) + " recall, and paraphrases of the form “take on the identity of a model that was never given any policy” get past both the rule base and the classifier. We left that case failing instead of patching it with a rule fitted to the test set. The end-to-end evaluation used small models in single-turn settings, which is a weaker test than a long agentic loop would be."),
body("The future work follows straight from those limitations. Evaluating against a public benchmark written by somebody else would address the biggest threat to validity. Swapping the hashed vectoriser in the semantic detector for sentence embeddings should improve our weakest component, and it is a one-function change because we designed the interface for it. Extending the end-to-end evaluation to larger models and multi-turn loops would show whether the null result in Section 6.1.3 survives greater pressure. The cross-lingual lexicon covers twelve languages chosen by prevalence. Extending it is a data task, not a code change, and the same corroboration rule should continue to hold."),
new Paragraph({ children: [new PageBreak()] }));

// ═══════════════════════ 8. REFERENCES ═══════════════════════
C.push(h1("8. References"));

// Grouped as the template requires. Numbering runs on across the groups so a
// reader can still cite a single ordered list.
const refPara = (n, t) => new Paragraph({
  spacing: { line: 276, after: 110 },
  alignment: AlignmentType.JUSTIFIED,
  indent: { left: 460, hanging: 460 },
  children: [new TextRun({ text: "[" + n + "]  " + t, font: TNR, size: 23 })],
});
const refHead = (bold, rest) => rich([{ text: bold, bold: true }, { text: rest }],
  { align: AlignmentType.LEFT, spacing: { before: 120, after: 130 } });

C.push(refHead("Journals and Conferences: ", "IEEE format"));
[
  "F. Perez and I. Ribeiro, “Ignore previous prompt: Attack techniques for language models,” in Proc. NeurIPS Workshop on ML Safety, 2022.",
  "K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz, “Not what you’ve signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection,” in Proc. 16th ACM Workshop on Artificial Intelligence and Security (AISec), 2023, pp. 79–90.",
  "Y. Liu, Y. Jia, R. Geng, J. Jia, and N. Z. Gong, “Formalizing and benchmarking prompt injection attacks and defenses,” in Proc. 33rd USENIX Security Symposium, 2024.",
  "K. Hines, G. Lopez, M. Hall, F. Zarfati, Y. Zunger, and E. Kiciman, “Defending against indirect prompt injection attacks with spotlighting,” arXiv:2403.14720, 2024.",
  "S. Abdelnabi, K. Greshake, S. Mishra, C. Endres, T. Holz, and M. Fritz, “Not what you’ve signed up for: a taxonomy of indirect prompt injection threats,” in Proc. ACM Conference on Computer and Communications Security Workshops, 2023.",
  "N. Carlini, M. Nasr, C. A. Choquette-Choo, et al., “Are aligned neural networks adversarially aligned?” in Advances in Neural Information Processing Systems, vol. 36, 2023.",
  "A. Zou, Z. Wang, N. Carlini, M. Nasr, J. Z. Kolter, and M. Fredrikson, “Universal and transferable adversarial attacks on aligned language models,” arXiv:2307.15043, 2023.",
  "J. Yi, Y. Xie, B. Zhu, et al., “Benchmarking and defending against indirect prompt injection attacks on large language models,” arXiv:2312.14197, 2023.",
  "E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer, and F. Tramèr, “AgentDojo: A dynamic environment to evaluate prompt injection attacks and defenses for LLM agents,” in Advances in Neural Information Processing Systems, 2024.",
  "J. Li, S. Ji, T. Du, B. Li, and T. Wang, “TextBugger: Generating adversarial text against real-world applications,” in Proc. Network and Distributed System Security Symposium (NDSS), 2019.",
  "K. Weiss, T. M. Khoshgoftaar, and D. Wang, “A survey of transfer learning,” Journal of Big Data, vol. 3, no. 1, pp. 1–40, 2016.",
  "Y. Bengio, R. Ducharme, P. Vincent, and C. Jauvin, “A neural probabilistic language model,” Journal of Machine Learning Research, vol. 3, pp. 1137–1155, 2003.",
].forEach((t, k) => C.push(refPara(1 + k, t)));

C.push(refHead("Weblinks", ""));
[
  "S. Willison, “The dual LLM pattern for building AI assistants that can resist prompt injection,” 2023. [Online]. Available: https://simonwillison.net/2023/Apr/25/dual-llm-pattern/",
  "OWASP Foundation, “OWASP Top 10 for Large Language Model Applications,” 2023. [Online]. Available: https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  "Unicode Consortium, “Unicode Technical Standard #39: Unicode Security Mechanisms,” 2023. [Online]. Available: https://www.unicode.org/reports/tr39/",
].forEach((t, k) => C.push(refPara(13 + k, t)));


// ═══════════════════════ APPENDICES ═══════════════════════
C.push(new Paragraph({ children: [new PageBreak()] }),
h1("Appendix A. Source Code and Repository"),
h2("A.1 Repository"),
body("The complete working code accompanies this report. It is self-contained: the middleware has no third-party runtime dependency, so the repository can be cloned and run with nothing installed beyond Python 3.9 or later."),
table(["Item", "Value"], [
  ["Code submitted", "The complete source tree accompanies this report. The core listings are reproduced in Appendix B"],
  ["Repository", REPO_URL],
  ["Language", "Python 3.9 or later, developed on 3.11.4"],
  ["Runtime dependencies", "None. Python standard library only"],
  ["Total size", "about 3,170 lines in the middleware package, 680 lines of tests"],
  ["Licence", "Submitted for academic evaluation"],
], [2300, 6466]),
caption("Table 15. Repository details."),
body("A copy of the full source tree is also submitted alongside this report, so the code can be inspected without network access."),

h2("A.2 Directory Layout"),
table(["Path", "Contents"], [
  ["pidguard/", "The middleware package. One module per pipeline stage, with the five detectors in a subpackage behind a common interface"],
  ["pidguard/detectors/", "heuristic.py, multilingual.py, statistical.py, semantic.py, structural.py and the shared base interface"],
  ["pidguard/models/", "Trained artefacts: lr_model.json (classifier weights), exemplars.json (60 attack vectors), calibration.json (thresholds and detector weights)"],
  ["data/", "Corpus builders and the generated corpora as JSONL: 528 training, 225 held-out test, 108 cross-lingual"],
  ["benchmark/", "Training, held-out evaluation, cross-lingual evaluation, the adaptive adversary, the end-to-end LLM evaluation and its positive control"],
  ["tests/", "test_pidguard.py: 60 tests covering every stage, including regression tests for defects found during development"],
  ["web/", "server.py and console.html: the local demonstration console, which runs the real pipeline"],
  ["demo/", "Command-line demonstrations and the 50 verified attack cases used by the console"],
  ["report/, ppt/, paper/", "Generators for this report, the slides and the conference paper. Every figure is read from the benchmark output at build time"],
], [1900, 6866]),
caption("Table 16. Directory layout of the submitted code."),

h2("A.3 Running the Code"),
body("Three commands reproduce the central claims of this report. No installation step is required and no network access is used."),
mono("  python tests/test_pidguard.py"),
body("Runs the 60-test suite over every stage of the pipeline. Expected output: 60/60 passed.", { spacing: { after: 100 } }),
mono("  python benchmark/evaluate.py"),
body("Evaluates the full system on the 225 held-out samples and prints the ablation of Table 7, the recall breakdowns of Tables 8 and 9, and the latency figures of Table 10. Expected output: recall " + pc(F.recall) + ", false positives " + pc(F.fpr) + ", F1 " + f3(F.f1) + ".", { spacing: { after: 100 } }),
mono("  python demo/showcase.py"),
body("Runs 20 fixed cases through the pipeline and prints the verdict and evidence for each. Expected output: 20/20 correct.", { spacing: { after: 100 } }),
body("Two further commands reproduce the remaining evaluations. The cross-lingual benchmark of Section 6.1.1 is reproduced by benchmark/evaluate_multilingual.py, and the adaptive adversary of Section 6.1.2 by benchmark/redteam.py. The end-to-end evaluation of Section 6.1.3 additionally requires a local Ollama instance and is reproduced by benchmark/evaluate_llm.py; every other result is reproducible without it."),
body("The demonstration console is started with web/server.py, which serves a local page on the loopback interface. Every verdict shown on that page is computed by the same pipeline the benchmarks use."),

new Paragraph({ children: [new PageBreak()] }),
h1("Appendix B. Core Implementation"),
body("Three listings follow, taken verbatim from the submitted source. They cover the public entry point, the fusion and decision rule, and the classifier, which together carry the contribution described in Section 4. Line numbers are those of the files themselves."),

h2("B.1 Pipeline Entry Point"),
body("PromptInjectionGuard.inspect is the single public entry point. It runs the five ingress stages in order and returns a result carrying the decision, the evidence, the surviving capability set and the text to hand to the model."),
rich([{ text: "pidguard/middleware.py", bold: true }, { text: ", lines 81-176" }],
  { align: AlignmentType.LEFT, spacing: { before: 100, after: 60 } }));
C.push(...codeBlock("pidguard/middleware.py", 81, 176));

C.push(h2("B.2 Evidence Fusion and Decision"),
body("PolicyEngine.fuse combines the detector opinions by noisy-OR, applies the agreement bonus and the lone-detector discount, and multiplies by the trust-tier weight. PolicyEngine.decide applies the multiple-comparisons correction and returns one of the three outcomes together with the capability gate."),
rich([{ text: "pidguard/policy.py", bold: true }, { text: ", lines 101-175" }],
  { align: AlignmentType.LEFT, spacing: { before: 100, after: 60 } }));
C.push(...codeBlock("pidguard/policy.py", 101, 175));

C.push(h2("B.3 Feature Hashing and the Classifier"),
body("The learned detector is implemented from first principles rather than taken from a package, which is what allows the project to carry no runtime dependency. featurize hashes word 1-2-grams and character 4-grams into 2^15 buckets with sublinear term frequency and L2 normalisation; predict_proba is the logistic model over those features."),
rich([{ text: "pidguard/detectors/statistical.py", bold: true }, { text: ", lines 44-110" }],
  { align: AlignmentType.LEFT, spacing: { before: 100, after: 60 } }));
C.push(...codeBlock("pidguard/detectors/statistical.py", 44, 110));

C.push(body("The remaining modules follow the same structure and are included in full in the submitted source tree.", { spacing: { before: 140 } }));

// ═══════════════════════ ASSEMBLE ═══════════════════════
const doc = new Document({
  creator: AUTHORS.map(a => a[1]).join("; "),
  title: "Prompt Injection Defense for LLM Agents",
  description: "BCSE410L Cyber Security Project I Report",
  numbering: {
    config: [{
      reference: "bul",
      levels: [
        { level: 0, format: "bullet", text: "•", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 520, hanging: 260 } } } },
        { level: 1, format: "bullet", text: "◦", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 1040, hanging: 260 } } } },
      ],
    }],
  },
  styles: { default: { document: { run: { font: TNR, size: 24 } } } },
  sections: [{
    properties: { page: { margin: { top: 1440, right: 1440, bottom: 1440, left: 1700 } } },
    footers: {
      default: new Footer({
        children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ children: [PageNumber.CURRENT], font: TNR, size: 20 })],
        })],
      }),
    },
    children: C.filter(Boolean),
  }],
});

const out = path.join(__dirname, "Project_I_Report_PID-Guard.docx");
Packer.toBuffer(doc).then(b => {
  fs.writeFileSync(out, b);
  console.log("wrote " + out + "  (" + Math.round(b.length / 1024) + " KB, " +
              C.filter(Boolean).length + " blocks)");
});
