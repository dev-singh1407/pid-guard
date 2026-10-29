/**
 * Report content. Separated from the formatting helpers so the prose can be
 * edited without touching layout code.
 *
 *   node report/content.js
 */

const fs = require("fs");
const path = require("path");
const H = require("./build_report.js");
const {
  AlignmentType, Document, Footer, PageBreak, PageNumber, Packer, Paragraph,
  TextRun, E, ML, RT, LM, CAL, F, pc, f3, TNR, body, rich, h1, h2, h3, bullet,
  caption, mono, centre, gap, table,
} = H;

const AUTHORS = [
  ["23BCE0241", "SANCHIT BAGHEL"],   // sorted on register number, per template
  ["23BCE0794", "DEV SINGH"],
];

const doc = new Document({
  creator: "Sanchit Baghel; Dev Singh",
  title: "Prompt Injection Defense for LLM Agents",
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
  styles: {
    default: { document: { run: { font: TNR, size: 24 } } },
  },
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
    children: [

      // ─────────────────────────── TITLE PAGE ───────────────────────────
      ...gap(2),
      centre("BCSE410L – Cyber Security Project", 26, true, false),
      ...gap(2),
      centre("Prompt Injection Defense for LLM Agents", 32, true, true),
      ...gap(1),
      centre("A Middleware Layer for Detecting and Neutralising", 24, false, false),
      centre("Prompt Injection Attacks in Tool-Using LLM Agents", 24, false, false),
      ...gap(3),
      ...AUTHORS.flatMap(([reg, name]) => [
        centre(reg, 26, true, true),
        centre(name, 26, true, true),
        ...gap(1),
      ]),
      ...gap(2),
      centre("Under the Supervision of", 24, false, false),
      centre("Dr Anto S", 26, true, false),
      centre("School of Computer Science and Engineering (SCOPE)", 24, false, false),
      ...gap(3),
      centre("B.Tech.", 26, true, false),
      centre("in", 24, false, false),
      centre("Computer Science and Engineering", 26, true, false),
      ...gap(2),
      centre("School of Computer Science and Engineering", 24, false, false),
      centre("October 2026", 24, false, false),
      new Paragraph({ children: [new PageBreak()] }),

      // ─────────────────────────── ABSTRACT ───────────────────────────
      h1("Abstract"),
      body("A large language model receives a single flat stream of tokens. Nothing in its architecture distinguishes an instruction written by the developer from a paragraph inside a web page the developer asked it to read. When such a model is given tools — file access, browsing, electronic mail, a shell — it inherits the privileges of whatever text it happens to ingest. An adversary who can place words anywhere the agent will read them can therefore issue commands to that agent under the victim's identity. This class of attack is termed indirect prompt injection and is ranked LLM01, the highest entry, in the OWASP Top 10 for Large Language Model Applications."),
      body("This project presents PID-Guard, a model-agnostic middleware layer that enforces the separation of instruction from data outside the model, where the adversary's text cannot reach it. The system inspects every untrusted span on both the inbound and outbound paths through a five-stage pipeline: canonicalisation, which reverses zero-width characters, homoglyph substitution, hidden markup and layered encodings; a five-detector ensemble combining a signature rule base, a cross-lingual lexicon, a logistic-regression classifier implemented from first principles, nearest-neighbour similarity and content-blind structural analysis, each scored over overlapping windows; evidence fusion by noisy-OR weighted by the provenance of the text; neutralisation by datamarking and nonce fencing rather than deletion; and an egress guard that redacts credentials, blocks zero-click beacons and enforces a per-turn capability gate."),
      body("On a held-out evaluation set of 225 samples the system attains " + pc(F.recall) + " attack recall at a " + pc(F.fpr) + " false-positive rate (F1 " + f3(F.f1) + "), adding a median of " + E.latency_ms.p50 + " milliseconds per span with no third-party runtime dependency. A separate cross-lingual benchmark of " + ML.n_samples + " samples across " + ML.languages.length + " languages raised recall from " + pc(ML.before.recall) + " to " + pc(ML.after.recall) + " with no false positives on foreign-language controls, closing a complete bypass. Against an adaptive white-box adversary that mutates payloads until they evade, the system retains " + pc(RT.robustness) + " robustness."),
      rich([
        { text: "Keywords – ", bold: true },
        { text: "Prompt Injection, Large Language Models, LLM Agents, Indirect Injection, AI Security, Adversarial Robustness, Defence in Depth, Natural Language Processing." },
      ]),
      new Paragraph({ children: [new PageBreak()] }),

      // ─────────────────────── TABLE OF CONTENTS ───────────────────────
      h1("Table of Contents"),
      table(["Sl.No", "Contents", "Page No."],
        [
          ["", "Abstract", "i"],
          ["1.", "INTRODUCTION", "1"],
          ["", "1.1 Background", "1"],
          ["", "1.2 Motivation", "2"],
          ["", "1.3 Scope of the Project", "2"],
          ["2.", "PROJECT DESCRIPTION AND GOALS", "3"],
          ["", "2.1 Literature Review", "3"],
          ["", "2.2 Research Gap", "5"],
          ["", "2.3 Problem Statement", "6"],
          ["", "2.4 Objectives", "6"],
          ["", "2.5 Project Plan", "7"],
          ["3.", "TECHNICAL SPECIFICATION", "8"],
          ["", "3.1 Requirements", "8"],
          ["", "3.2 Feasibility Study", "9"],
          ["", "3.3 System Specification", "10"],
          ["4.", "DESIGN APPROACH AND DETAILS", "11"],
          ["", "4.1 System Architecture", "11"],
          ["", "4.2 Design", "12"],
          ["5.", "EXPERIMENTAL SETUP AND OUTPUT", "16"],
          ["", "5.1 Experimental Setup", "16"],
          ["", "5.2 Output of the Proposed System", "17"],
          ["6.", "RESULT ANALYSIS", "19"],
          ["", "6.1 Comparison with Existing Systems", "19"],
          ["7.", "CONCLUSION AND FUTURE WORKS", "21"],
          ["8.", "REFERENCES", "22"],
        ], [900, 5900, 1200]),
      new Paragraph({ children: [new PageBreak()] }),

      // ─────────────────────── 1. INTRODUCTION ───────────────────────
      h1("1. Introduction"),
      h2("1.1 Background"),
      body("Large language models are increasingly deployed not as passive text generators but as agents: systems that retrieve documents, browse the web, read electronic mail and invoke tools on a user's behalf. This shift changes the security posture fundamentally. A passive model that produces undesirable text causes limited harm; an agent that can read files, send mail and make network requests causes real harm when it is misled."),
      body("The mechanism of that misdirection is structural rather than incidental. A language model receives its system prompt, the user's request and any retrieved content as one undifferentiated token sequence. There is no field, delimiter or type marking that identifies which portion carries authority. Consequently any text the agent ingests is, from the model's perspective, indistinguishable from an instruction issued by its operator."),
      body("Indirect prompt injection exploits precisely this. The adversary never communicates with the agent directly. Instead they place crafted text where the agent will read it — a product review, a support ticket, a hypertext comment invisible to human readers, a configuration file, a curriculum vitae submitted to an automated screening pipeline. When the agent retrieves that content, the embedded instruction competes for the model's attention alongside the legitimate task, and frequently wins. The OWASP Foundation ranks prompt injection as LLM01, the foremost risk for applications built on large language models, and notes explicitly that no complete mitigation exists at the model layer."),
      h2("1.2 Motivation"),
      body("The defences commonly proposed for this problem share a structural weakness: they live inside the prompt, which is the very channel the attack occupies. Instructing a model to disregard commands found in documents places a defensive sentence in competition with an offensive one, and the model arbitrates. Worse, such a defence fails silently — the operator receives no signal that it was overridden."),
      body("Two further approaches are frequently suggested and are similarly unsatisfactory. Keyword blocklists are trivially defeated by paraphrase; our own measurements place such a baseline at " + pc(E.baseline.recall) + " recall against attacks phrased independently of stock wording. Employing a second language model as an adjudicator doubles inference cost and latency while introducing a second surface that is itself susceptible to injection."),
      body("This project is motivated by the conviction that the control must sit outside the model. If the model cannot reliably distinguish instruction from data, then a deterministic layer that tracks the provenance of every span, and that the adversary's text cannot modify, should make that distinction on the model's behalf. Such a layer can additionally be audited, tested and reasoned about in a way that a prompt cannot."),
      h2("1.3 Scope of the Project"),
      body("The project delivers a working middleware library, PID-Guard, that sits between an agent runtime and a language model and governs traffic in both directions. On ingress it canonicalises, inspects, scores and neutralises untrusted spans; on egress it inspects model output and proposed tool invocations for credential disclosure, exfiltration channels and capability violations."),
      body("Within scope are: detection of the eight attack families identified in the literature; resistance to character-level and encoding-level evasion; cross-lingual coverage; a provenance model distinguishing five levels of trust; per-turn capability restriction; an append-only audit trail; a reproducible evaluation methodology; and an interactive console for live demonstration."),
      body("Outside scope are: modification or fine-tuning of the underlying model; defence against adversaries with access to the model weights or to the middleware's own configuration; and protection against attacks that do not pass through the text channel, such as compromise of the tool implementations themselves. The system is designed as one layer of a defence-in-depth posture, not as a complete solution, and is evaluated and reported on that basis."),
      new Paragraph({ children: [new PageBreak()] }),
    ],
  }],
});

// Section 2 onwards is appended by sections2.js to keep files manageable.
module.exports = { doc, AUTHORS };

if (require.main === module) {
  const out = path.join(__dirname, "_part1.docx");
  Packer.toBuffer(doc).then(b => { fs.writeFileSync(out, b); console.log("part 1 ok: " + out); });
}
