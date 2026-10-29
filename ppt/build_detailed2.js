/**
 * Chapters 3-8 and write-out. Run this one:
 *   node ppt/build_detailed2.js
 */

const path = require("path");
const B = require("./build_detailed.js");
const { pres, C, HEAD, BODY, W, H, M, E, ML, RT, LM, CAL, F, pct, f3,
        dark, slide, card, disc, bullets, tbl, note } = B;

// ═══════════ CHAPTER 3 · TECHNICAL SPECIFICATION ═══════════
{
  const s = slide("3.1  Requirements", "Chapter 3 · Technical specification");
  card(s, M, 1.45, 6.1, 4.9);
  s.addText("FUNCTIONAL  (11 total, 6 shown)", { x: M + 0.3, y: 1.65, w: 5.5, h: 0.28,
    fontFace: BODY, fontSize: 11, bold: true, color: C.navy, charSpacing: 1.4, margin: 0 });
  bullets(s, [
    "Return allow / sanitise / block for a span and its tier",
    "Reverse zero-width, homoglyph, hidden markup and encodings",
    "Score over overlapping windows so payloads are not diluted",
    "Detect the eight attack families",
    "Detect injections in languages other than English",
    "Revoke, for one turn, capabilities tied to the detected family",
    "Inspect outbound text for credentials, leakage and beacons",
    "Record every decision with the evidence that produced it",
  ], M + 0.3, 2.08, 5.5, 12, 0.52);

  card(s, M + 6.4, 1.45, W - 2 * M - 6.4, 4.9);
  s.addText("NON-FUNCTIONAL — with measurements", { x: M + 6.7, y: 1.65, w: 5.4, h: 0.28,
    fontFace: BODY, fontSize: 11, bold: true, color: C.navy, charSpacing: 1.4, margin: 0 });
  const nf = [
    ["Latency", "< 50 ms per span", E.latency_ms.p50 + " ms median", C.safe],
    ["Precision", "FPR ≤ 5%", pct(F.fpr), C.safe],
    ["Portability", "no third-party dependency", "0 dependencies", C.safe],
    ["Model independence", "survives a model swap", "no fine-tuning", C.safe],
    ["Fail-safe", "a broken detector counts as a detection", "fail closed", C.safe],
    ["Auditability", "every decision carries its evidence", "audit log", C.safe],
  ];
  let y = 2.1;
  nf.forEach(r => {
    s.addText(r[0], { x: M + 6.7, y, w: 2.0, h: 0.26, fontFace: BODY, fontSize: 12,
      bold: true, color: C.navy, margin: 0 });
    s.addText(r[1], { x: M + 8.75, y, w: 2.0, h: 0.52, fontFace: BODY, fontSize: 10.5,
      color: C.muted, lineSpacing: 13, margin: 0 });
    s.addText(r[2], { x: M + 10.8, y, w: 1.5, h: 0.26, fontFace: BODY, fontSize: 11.5,
      bold: true, color: r[3], align: "right", margin: 0 });
    y += 0.68;
  });
  note(s, "Fail-safe is the one worth dwelling on: middleware that silently degrades to a no-op is worse than none, because the operator still believes they are protected.");
}

{
  const s = slide("3.2  Feasibility   ·   3.3  System specification", "Chapter 3 · Technical specification");
  const feas = [
    ["Technical", "Pure Python standard library. The classifier is ~200 lines implemented from first principles — no numpy, no scikit-learn. Model file is 182 KB. No GPU, no network, no second inference pass.", C.safe],
    ["Economic", "Development cost is student time on commodity hardware. Operational cost is " + E.latency_ms.p50 + " ms of CPU per span and nothing per request — an adjudicating-model approach would roughly double inference spend.", C.navy],
    ["Social", "Usability is treated as a security property: a control that blocks real work is uninstalled. Every decision carries its evidence so disputes can be examined. The system inspects text an agent is about to process, not users.", C.navy],
  ];
  let y = 1.45;
  feas.forEach(f => {
    card(s, M, y, 7.3, 1.46);
    s.addShape(pres.ShapeType.ellipse, { x: M + 0.28, y: y + 0.26, w: 0.2, h: 0.2, fill: { color: f[2] } });
    s.addText(f[0], { x: M + 0.6, y: y + 0.2, w: 2.5, h: 0.3, fontFace: BODY, fontSize: 13.5,
      bold: true, color: C.navy, margin: 0 });
    s.addText(f[1], { x: M + 0.3, y: y + 0.58, w: 6.75, h: 0.78, fontFace: BODY, fontSize: 11.5,
      color: C.body, lineSpacing: 15, margin: 0 });
    y += 1.6;
  });
  card(s, M + 7.6, 1.45, W - 2 * M - 7.6, 4.76, C.ink);
  s.addText("SYSTEM SPECIFICATION", { x: M + 7.88, y: 1.68, w: 4.4, h: 0.28, fontFace: BODY,
    fontSize: 11, bold: true, color: C.ice, charSpacing: 1.5, margin: 0 });
  const spec = [
    ["Processor", "x86-64, dual core min."],
    ["Memory", "4 GB; ~60 MB resident"],
    ["Storage", "50 MB total"],
    ["GPU", "not required"],
    ["Network", "not required"],
    ["OS", "Windows 11 / platform independent"],
    ["Language", "Python 3.9+ (dev: 3.11.4)"],
    ["Dependencies", "none at runtime"],
    ["Optional", "Ollama, for end-to-end eval"],
  ];
  let sy = 2.1;
  spec.forEach(r => {
    s.addText(r[0], { x: M + 7.88, y: sy, w: 1.75, h: 0.26, fontFace: BODY, fontSize: 11,
      color: "A6B2D4", margin: 0 });
    s.addText(r[1], { x: M + 9.66, y: sy, w: 2.6, h: 0.26, fontFace: BODY, fontSize: 11,
      bold: true, color: C.white, margin: 0 });
    sy += 0.45;
  });
  note(s, "The zero-dependency claim is worth stressing: it means this drops into an existing agent without touching its environment.");
}

// ═══════════ CHAPTER 4 · DESIGN APPROACH AND DETAILS ═══════════
{
  const s = slide("4.1  System architecture", "Chapter 4 · Design approach and details");
  const stages = [
    ["Canonicalise", "NFKC · homoglyph fold · reveal hidden · decode b64/hex/ROT13"],
    ["Segment", "overlapping windows of ~" + CAL.settings.window_chars + " chars"],
    ["Detect", "5 detectors, each window scored separately"],
    ["Fuse & decide", "noisy-OR · trust tier · ALLOW / SANITISE / BLOCK"],
    ["Neutralise", "datamark · nonce fence · defang spans"],
    ["Guard egress", "secrets · beacons · capability gate"],
  ];
  const bw = 1.92, bh = 1.3, gap = 0.17;
  stages.forEach((st, i) => {
    const x = M + i * (bw + gap), y = 1.5;
    const hot = i === 3;
    s.addShape(pres.ShapeType.roundRect, { x, y, w: bw, h: bh, rectRadius: 0.07,
      fill: { color: hot ? C.navy : C.card }, line: { color: hot ? C.navy : C.line, width: 1 } });
    disc(s, i + 1, x + 0.14, y + 0.13, 0.3, hot ? C.ice : C.navy, hot ? C.navy : C.white);
    s.addText(st[0], { x: x + 0.5, y: y + 0.14, w: bw - 0.62, h: 0.28, fontFace: BODY,
      fontSize: 11.5, bold: true, color: hot ? C.white : C.navy, margin: 0 });
    s.addText(st[1], { x: x + 0.14, y: y + 0.48, w: bw - 0.28, h: 0.72, fontFace: BODY,
      fontSize: 8.8, color: hot ? C.ice : C.muted, lineSpacing: 11, margin: 0 });
    if (i < stages.length - 1) {
      s.addShape(pres.ShapeType.triangle, { x: x + bw + 0.015, y: y + bh / 2 - 0.08,
        w: 0.14, h: 0.16, fill: { color: C.muted }, rotate: 90 });
    }
  });
  s.addText("ingress  →  model  →  egress     ·     the middleware governs both directions", {
    x: M, y: 2.92, w: W - 2 * M, h: 0.3, fontFace: BODY, fontSize: 12, italic: true,
    color: C.muted, align: "center", margin: 0 });

  card(s, M, 3.38, 6.1, 2.95, C.ink);
  s.addText("THE CORE IDEA — TRUST ATTACHES TO THE CHANNEL", { x: M + 0.28, y: 3.58,
    w: 5.5, h: 0.28, fontFace: BODY, fontSize: 10.5, bold: true, color: C.ice,
    charSpacing: 1.2, margin: 0 });
  const tiers = [["SYSTEM", "0.00", "never inspected"], ["USER", "0.75", "the operator"],
                 ["TOOL", "1.15", "tool output"], ["RETRIEVED", "1.25", "RAG document"],
                 ["WEB", "1.40", "fully untrusted"]];
  let ty = 3.95;
  tiers.forEach(t => {
    s.addText(t[0], { x: M + 0.28, y: ty, w: 1.6, h: 0.26, fontFace: BODY, fontSize: 11.5,
      bold: true, color: C.white, margin: 0 });
    s.addText("× " + t[1], { x: M + 1.95, y: ty, w: 0.9, h: 0.26, fontFace: BODY,
      fontSize: 11.5, color: C.safe, bold: true, margin: 0 });
    s.addText(t[2], { x: M + 3.0, y: ty, w: 2.9, h: 0.26, fontFace: BODY, fontSize: 11,
      color: "A6B2D4", margin: 0 });
    ty += 0.45;
  });

  card(s, M + 6.4, 3.38, W - 2 * M - 6.4, 2.95);
  s.addText("Why this is the whole idea", { x: M + 6.7, y: 3.58, w: 5.4, h: 0.3,
    fontFace: BODY, fontSize: 13.5, bold: true, color: C.navy, margin: 0 });
  s.addText("The same sentence is judged differently according to where it came from.\n\n“Ignore my previous message” from the operator is a legitimate correction.\n\nThe identical words from a scraped web page are an attack.\n\nThe model cannot make that distinction — it sees one flat token stream. The middleware can, because it knows the channel.", {
    x: M + 6.7, y: 3.95, w: 5.4, h: 2.2, fontFace: BODY, fontSize: 12, color: C.body,
    lineSpacing: 16, margin: 0 });
  note(s, "If you only get one slide across, make it this one. Then demonstrate it live in the console.");
}

{
  const s = slide("4.2.1  Algorithm 1 — windowed detection and risk fusion", "Chapter 4 · Design approach and details");
  const steps = [
    "If tier is SYSTEM, return ALLOW — the developer's own prompt is not inspected",
    "Canonicalise: strip invisibles, NFKC, fold homoglyphs in mixed-script tokens only, reveal hidden markup, decode encodings. Record every transform.",
    "Segment into overlapping windows of ≤ " + CAL.settings.window_chars + " characters, one unit of overlap",
    "For each window, run all five detectors. A detector that raises contributes a MEDIUM detection, never silence.",
    "Fuse within a detector by noisy-OR of severity × confidence; cap; weight; fuse across detectors by noisy-OR",
    "Agreement bonus if ≥ 3 detectors concur; discount if a lone non-signature detector fires",
    "Multiply by the tier multiplier τ(t) to obtain the window risk",
    "Take Rₘₐₓ over windows and compute concentration c = (Rₘₐₓ − mean of rest) / Rₘₐₓ",
    "Inflate thresholds by (1 + k · log₂N · (1 − c)) — a Bonferroni analogue damped by concentration",
    "Return BLOCK / SANITISE / ALLOW, and revoke capabilities tied to detected families",
  ];
  let y = 1.45;
  steps.forEach((t, i) => {
    s.addText(String(i + 1) + ".", { x: M, y, w: 0.35, h: 0.28, fontFace: BODY, fontSize: 12,
      bold: true, color: C.navy, margin: 0 });
    s.addText(t, { x: M + 0.38, y, w: 7.0, h: 0.46, fontFace: BODY, fontSize: 11.5,
      color: C.body, lineSpacing: 14, margin: 0 });
    y += 0.48;
  });
  card(s, M + 7.7, 1.45, W - 2 * M - 7.7, 2.4, C.ink);
  s.addText("FUSION", { x: M + 7.98, y: 1.62, w: 4, h: 0.26, fontFace: BODY, fontSize: 10.5,
    bold: true, color: C.ice, charSpacing: 1.4, margin: 0 });
  s.addText("sᵈ = 1 − Π(1 − sev·conf)\nF  = 1 − Π(1 − wᵈ·sᵈ)\nR  = F × τ(tier)", {
    x: M + 7.98, y: 1.95, w: 4.2, h: 1.0, fontFace: "Courier New", fontSize: 12,
    color: C.white, lineSpacing: 20, margin: 0 });
  s.addText("Noisy-OR, not voting: weak independent signals can combine, but one detector repeating itself cannot saturate.", {
    x: M + 7.98, y: 3.0, w: 4.2, h: 0.72, fontFace: BODY, fontSize: 10.5, color: "A6B2D4",
    lineSpacing: 13, margin: 0 });
  card(s, M + 7.7, 4.0, W - 2 * M - 7.7, 2.3);
  s.addText("Why windowing", { x: M + 7.98, y: 4.2, w: 4.2, h: 0.3, fontFace: BODY,
    fontSize: 13, bold: true, color: C.navy, margin: 0 });
  s.addText("A three-sentence payload inside a 4,000-word page is averaged away by every density-based score. Scoring windows and taking the maximum fixes it — an attack need only be concentrated somewhere, a benign document is benign everywhere.\n\nMeasured: embedded-attack recall 0.429 → 0.909", {
    x: M + 7.98, y: 4.55, w: 4.2, h: 1.6, fontFace: BODY, fontSize: 10.5, color: C.body,
    lineSpacing: 13, margin: 0 });
  note(s, "Step 9 is the subtle one. Taking a maximum over N windows inflates false positives with N, so the threshold must rise with N — but damped by concentration, or padding a document buys the attacker leniency.");
}

{
  const s = slide("4.2.2  Algorithm 2 — neutralisation and egress control", "Chapter 4 · Design approach and details");
  s.addText("Blocking every suspicious document yields an agent that refuses to read the web. The second algorithm keeps the information and destroys its capacity to instruct.", {
    x: M, y: 1.66, w: W - 2 * M, h: 0.46, fontFace: BODY, fontSize: 13.5, color: C.body, margin: 0 });
  const mech = [
    ["Datamarking", "A private invisible separator (U+2063) is interleaved into every whitespace gap. The model still reads the words; they no longer tokenise as a conversational turn.", "Hines et al. 2024"],
    ["Nonce fencing", "The span is wrapped in delimiters carrying a fresh 64-bit random nonce. The attacker cannot close the fence without guessing it.", "ours"],
    ["Span defanging", "Each detected span is rewritten as inert quoted evidence, so the agent and a later auditor can still see what was attempted.", "ours"],
    ["Provenance banner", "An explicit statement of source tier and detected families; the integrator adds the matching contract to the system prompt once.", "ours"],
  ];
  let y = 1.95;
  mech.forEach((m, i) => {
    card(s, M, y, 7.3, 1.0);
    disc(s, i + 1, M + 0.24, y + 0.3, 0.36, C.navy, C.white);
    s.addText(m[0], { x: M + 0.72, y: y + 0.14, w: 2.6, h: 0.28, fontFace: BODY, fontSize: 13,
      bold: true, color: C.navy, margin: 0 });
    s.addText(m[2], { x: M + 5.6, y: y + 0.14, w: 1.5, h: 0.26, fontFace: BODY, fontSize: 10,
      italic: true, color: C.muted, align: "right", margin: 0 });
    s.addText(m[1], { x: M + 0.72, y: y + 0.44, w: 6.3, h: 0.5, fontFace: BODY, fontSize: 11,
      color: C.body, lineSpacing: 14, margin: 0 });
    y += 1.1;
  });
  card(s, M + 7.6, 1.95, W - 2 * M - 7.6, 4.4, C.ink);
  s.addText("EGRESS GUARD", { x: M + 7.88, y: 2.15, w: 4.4, h: 0.28, fontFace: BODY,
    fontSize: 10.5, bold: true, color: C.ice, charSpacing: 1.4, margin: 0 });
  s.addText("The last chance — and the layer that catches attacks the ingress detectors never saw, because it checks consequences rather than wording.", {
    x: M + 7.88, y: 2.5, w: 4.3, h: 0.78, fontFace: BODY, fontSize: 11, color: "A6B2D4",
    lineSpacing: 14, margin: 0 });
  bullets(s, [
    "8 credential patterns (sk-, AKIA, ghp_, JWT, PEM)",
    "System-prompt leakage against protected strings",
    "Zero-click image beacons — a markdown image is fetched without a click",
    "Long opaque URL parameters (data smuggling)",
    "Tool calls validated against the surviving capability set",
  ], M + 7.88, 3.45, 4.3, 10.5, 0.56);
  note(s, "The beacon is the one to explain: there is no instruction in it at all. The markdown image is fetched by the client automatically, so the base64 query parameter IS the exfiltration channel.");
}

{
  const s = slide("4.2.3  The five detectors — chosen to fail differently", "Chapter 4 · Design approach and details");
  tbl(s, ["Detector", "Question it answers", "Mechanism", "Alone (F1)"], [
    ["Heuristic", "Matches a known signature?", "32 rules · 8 families · 3 text views · fuzzy fallback", f3(E.ablation["heuristic only"].f1)],
    ["Multilingual", "An injection in another language?", "12-language lexicon · same-language category pairing", "—"],
    ["Statistical", "How injection-like statistically?", "Hashed word 1–2gram + char 4gram → logistic regression", f3(E.ablation["statistical only"].f1)],
    ["Semantic", "Closest known attack?", "Cosine similarity over 60 exemplars", f3(E.ablation["semantic only"].f1)],
    ["Structural", "Behaves like a command?", "Content-blind: imperative density, obligation, URL shape", f3(E.ablation["structural only"].f1)],
  ], M, 1.5, [1.75, 3.0, 5.4, 1.9], { fontSize: 11.5, rowH: 0.66 });

  card(s, M, 5.3, 6.1, 1.5, C.ink);
  s.addText("The learned detector, from first principles", { x: M + 0.28, y: 5.48, w: 5.5,
    h: 0.28, fontFace: BODY, fontSize: 12, bold: true, color: C.ice, margin: 0 });
  s.addText("FNV-1a hashing into 2¹⁵ buckets · sublinear TF · L2-normalised · logistic regression by SGD with L2 and class weighting · 9.8k weights, 182 KB · no scikit-learn", {
    x: M + 0.28, y: 5.8, w: 5.5, h: 0.86, fontFace: BODY, fontSize: 10.5, color: "A6B2D4",
    lineSpacing: 13, margin: 0 });
  card(s, M + 6.4, 5.3, W - 2 * M - 6.4, 1.5);
  s.addText("Why keep the weak ones?", { x: M + 6.7, y: 5.48, w: 5.4, h: 0.28, fontFace: BODY,
    fontSize: 12, bold: true, color: C.navy, margin: 0 });
  s.addText("Semantic and structural are near-useless alone. They earn their place through corroboration — adding semantic to heuristic + statistical lifts recall from " + f3(E.ablation["heuristic + statistical"].recall) + " to " + f3(E.ablation["heuristic + stat + semantic"].recall) + " — and through the evidence they attach, which a bare probability cannot give.", {
    x: M + 6.7, y: 5.8, w: 5.4, h: 0.9, fontFace: BODY, fontSize: 10.5, color: C.body,
    lineSpacing: 13, margin: 0 });
  note(s, "Volunteering that two of five detectors are weak alone is a strength, not a weakness — it shows you read your own ablation.");
}

// ═══════════ CHAPTER 5 · EXPERIMENTAL SETUP AND OUTPUT ═══════════
{
  const s = slide("5.1  Experimental setup", "Chapter 5 · Experimental setup and output");
  const guards = [
    ["Independent phrasing", "Test seeds are written independently of training seeds. No template is shared, so the figures measure generalisation rather than memorisation."],
    ["Grouped splitting", "Every obfuscated variant of a sentence stays in the same fold. Without this an augmented near-duplicate leaks across the boundary and every number is optimistic."],
    ["Test set never opened", "No training or calibration script reads the test file. Not by convention — by construction."],
    ["Leave-one-family-out", "Pipeline parameters chosen by withholding an entire attack category, then measuring recall on it. A normal validation split saturated at 0.99 and could not discriminate."],
  ];
  let y = 1.5;
  guards.forEach((g, i) => {
    card(s, M, y, 7.4, 1.15);
    disc(s, i + 1, M + 0.26, y + 0.33, 0.4, C.safe, C.white);
    s.addText(g[0], { x: M + 0.8, y: y + 0.16, w: 6.3, h: 0.3, fontFace: BODY, fontSize: 13.5,
      bold: true, color: C.navy, margin: 0 });
    s.addText(g[1], { x: M + 0.8, y: y + 0.48, w: 6.35, h: 0.6, fontFace: BODY, fontSize: 11,
      color: C.body, lineSpacing: 14, margin: 0 });
    y += 1.26;
  });
  card(s, M + 7.7, 1.5, W - 2 * M - 7.7, 4.54, C.ink);
  s.addText("CORPUS AND OBJECTIVE", { x: M + 7.98, y: 1.7, w: 4.4, h: 0.28, fontFace: BODY,
    fontSize: 10.5, bold: true, color: C.ice, charSpacing: 1.4, margin: 0 });
  const facts = [["Corpus", "753 samples"], ["Train / test", "528 / " + E.n_samples],
                 ["Test attacks", String(E.n_attack)], ["Cross-lingual set", ML.n_samples + " · " + ML.languages.length + " langs"],
                 ["Adversary budget", "40 queries"], ["Hardware", "laptop, 8 cores"],
                 ["Threads", "single"]];
  let fy = 2.1;
  facts.forEach(f => {
    s.addText(f[0], { x: M + 7.98, y: fy, w: 2.3, h: 0.26, fontFace: BODY, fontSize: 11,
      color: "A6B2D4", margin: 0 });
    s.addText(f[1], { x: M + 10.3, y: fy, w: 2.0, h: 0.26, fontFace: BODY, fontSize: 11,
      bold: true, color: C.white, align: "right", margin: 0 });
    fy += 0.42;
  });
  s.addText("Selection objective:\nF1 − 0.55 × FPR, subject to a recall floor.\n\nFalse positives are part of the objective, not a tie-breaker — a filter that blocks real work is removed from service.", {
    x: M + 7.98, y: 5.2, w: 4.3, h: 1.4, fontFace: BODY, fontSize: 10.5, color: C.ice,
    lineSpacing: 13, margin: 0 });
  note(s, "Leave-one-family-out is the methodological point an examiner is most likely to probe. Be ready to explain why a normal split was not enough.");
}

{
  const s = slide("5.2  Output — ablation on the held-out set", "Chapter 5 · Experimental setup and output");
  const order = ["heuristic only", "statistical only", "semantic only", "structural only",
                 "heuristic + statistical", "heuristic + stat + semantic", "FULL ENSEMBLE"];
  const rows = [["Keyword blocklist (baseline)", f3(E.baseline.precision), f3(E.baseline.recall),
                 f3(E.baseline.f1), f3(E.baseline.fpr)]]
    .concat(order.map(k => [k === "FULL ENSEMBLE" ? "Full ensemble" : k,
      f3(E.ablation[k].precision), f3(E.ablation[k].recall), f3(E.ablation[k].f1), f3(E.ablation[k].fpr)]));
  tbl(s, ["Configuration", "Precision", "Recall", "F1", "FPR"], rows, M, 1.5,
      [4.3, 1.5, 1.5, 1.5, 1.5], { fontSize: 12, rowH: 0.44, boldRows: [rows.length - 1] });

  const stats = [[pct(F.recall), "recall", C.safe], [pct(F.fpr), "false positives", C.navy],
                 [f3(F.f1), "F1", C.navy], [E.latency_ms.p50 + " ms", "median latency", C.navy]];
  stats.forEach((st, i) => {
    const x = M + i * 3.05;
    s.addText(st[0], { x, y: 5.45, w: 2.9, h: 0.6, fontFace: HEAD, fontSize: 32, bold: true,
      color: st[2], margin: 0 });
    s.addText(st[1], { x, y: 6.05, w: 2.9, h: 0.26, fontFace: BODY, fontSize: 11.5,
      color: C.muted, margin: 0 });
  });
  s.addText("The baseline reaches " + pct(E.baseline.recall) + " recall because the test attacks are deliberately phrased away from stock wording. That is the point being demonstrated, not a rigged comparison.", {
    x: M, y: 6.42, w: W - 2 * M, h: 0.4, fontFace: BODY, fontSize: 11.5, italic: true,
    color: C.muted, margin: 0 });
  note(s, "Walk down the table. Each row is a strict superset of the one above, so each shows what the added layer bought.");
}

{
  const s = slide("5.2  Output — by attack family and evasion technique", "Chapter 5 · Experimental setup and output");
  const fam = Object.entries(E.recall_by_family).sort((a, b) => b[1] - a[1]);
  const vari = Object.entries(E.recall_by_variant).sort((a, b) => b[1] - a[1]);
  const barRow = (x, y, w, label, v) => {
    s.addText(label.replace(/_/g, " "), { x, y, w: 2.5, h: 0.26, fontFace: BODY, fontSize: 11.5,
      color: C.body, margin: 0 });
    s.addShape(pres.ShapeType.rect, { x: x + 2.55, y: y + 0.08, w: w, h: 0.12,
      fill: { color: C.line }, line: { color: C.line, width: 0 } });
    const col = v >= 0.9 ? C.safe : v >= 0.75 ? C.amber : C.threat;
    s.addShape(pres.ShapeType.rect, { x: x + 2.55, y: y + 0.08, w: Math.max(0.03, w * v), h: 0.12,
      fill: { color: col }, line: { color: col, width: 0 } });
    s.addText(f3(v), { x: x + 2.6 + w, y, w: 0.6, h: 0.26, fontFace: BODY, fontSize: 10.5,
      color: C.muted, margin: 0 });
  };
  s.addText("BY ATTACK FAMILY", { x: M, y: 1.45, w: 5, h: 0.26, fontFace: BODY, fontSize: 11,
    bold: true, color: C.muted, charSpacing: 1.4, margin: 0 });
  fam.forEach(([k, v], i) => barRow(M, 1.82 + i * 0.44, 2.2, k, v));
  s.addText("BY EVASION TECHNIQUE", { x: M + 6.5, y: 1.45, w: 5, h: 0.26, fontFace: BODY,
    fontSize: 11, bold: true, color: C.muted, charSpacing: 1.4, margin: 0 });
  vari.forEach(([k, v], i) => barRow(M + 6.5, 1.82 + i * 0.44, 2.2, k, v));

  card(s, M, 5.42, W - 2 * M, 1.4, C.ink);
  s.addText("Two honest readings", { x: M + 0.28, y: 5.6, w: 5, h: 0.28, fontFace: BODY,
    fontSize: 12.5, bold: true, color: C.ice, margin: 0 });
  s.addText("Role manipulation is our weakest family at " + f3(E.recall_by_family.role_manipulation) + ". Paraphrases like “take on the identity of a model that was never given any policy” evade both the rule base and the classifier — we left it failing rather than add a rule fitted to our own test set.    The wrap-indirect row is the indirect-injection case: a payload embedded in an otherwise benign document, now at " + f3(E.recall_by_variant.wrap_indirect) + ".", {
    x: M + 0.28, y: 5.92, w: W - 2 * M - 0.56, h: 0.8, fontFace: BODY, fontSize: 11,
    color: "A6B2D4", lineSpacing: 14, margin: 0 });
  note(s, "Point at the weakest bar yourself before anyone else does.");
}

console.log("part 2 built: " + pres._slides.length + " slides so far");
module.exports = require("./build_detailed.js");
