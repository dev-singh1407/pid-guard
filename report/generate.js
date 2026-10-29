/**
 * Generates "Project I Report" for PID-Guard, following the VIT template.
 * Every figure is read from the benchmark JSON at build time.
 *
 *   node report/generate.js
 */

const fs = require("fs");
const path = require("path");
const H = require("./build_report.js");
const {
  AlignmentType, Document, Footer, PageBreak, PageNumber, Packer, Paragraph,
  TextRun, E, ML, RT, LM, CAL, F, pc, f3, TNR, body, rich, h1, h2, h3, bullet,
  caption, mono, centre, gap, table, figImage,
} = H;

const AUTHORS = [
  ["23BCE0241", "SANCHIT BAGHEL"],   // sorted on register number, per template
  ["23BCE0794", "DEV SINGH"],
];

const C = [];   // the document children, pushed section by section

// ═══════════════════════════ TITLE PAGE ═══════════════════════════
C.push(...gap(2),
  centre("BCSE410L – Cyber Security Project", 26, true, false),
  ...gap(2),
  centre("Prompt Injection Defense for LLM Agents", 32, true, true),
  ...gap(1),
  centre("A Middleware Layer for Detecting and Neutralising Prompt", 24, false, false),
  centre("Injection Attacks in Tool-Using LLM Agents", 24, false, false),
  ...gap(3));
AUTHORS.forEach(([reg, name]) => C.push(
  centre(reg, 26, true, true), centre(name, 26, true, true), ...gap(1)));
C.push(...gap(2),
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
  new Paragraph({ children: [new PageBreak()] }));

// ═══════════════════════════ ABSTRACT ═══════════════════════════
C.push(h1("Abstract"),
body("A large language model reads everything as one flat stream of tokens. Nothing in the architecture marks which part the developer wrote and which part came out of a web page the developer asked it to fetch. Once that model is given tools such as file access, browsing, mail and a shell, it will act on whatever text it happens to read. Anyone who can get words in front of the agent can therefore issue commands under the victim's own identity. The OWASP Top 10 for Large Language Model Applications ranks this class of attack, indirect prompt injection, at LLM01."),
body("This project presents PID-Guard, a model-agnostic middleware layer that separates instruction from data outside the model, in a place the attacker's text cannot reach. Untrusted text passes through five stages. Canonicalisation reverses zero-width characters, homoglyph substitution, hidden markup and layered encodings. Five detectors then score the text over overlapping windows: signature rules, a cross-lingual lexicon, a logistic-regression classifier, nearest-neighbour similarity and structural analysis. Their evidence is fused by noisy-OR and weighted by the channel the text arrived on. Suspicious spans are datamarked and fenced instead of deleted, so the agent keeps the information it needs. An egress guard then checks the outbound path and enforces a capability gate that lasts one turn."),
body("On a held-out set of " + E.n_samples + " samples the system attains " + pc(F.recall) + " attack recall at a " + pc(F.fpr) + " false-positive rate (F1 " + f3(F.f1) + "), adding " + E.latency_ms.p50 + " milliseconds per span with no third-party dependency. A cross-lingual benchmark of " + ML.n_samples + " samples across " + ML.languages.length + " languages raised recall from " + pc(ML.before.recall) + " to " + pc(ML.after.recall) + " with no false positives on foreign-language controls, closing a complete bypass. Against an adaptive white-box adversary the system retains " + pc(RT.robustness) + " robustness."),
rich([{ text: "Keywords – ", bold: true },
  { text: "Prompt Injection, Large Language Models, LLM Agents, Indirect Injection, AI Security, Adversarial Robustness, Defence in Depth, Natural Language Processing." }]),
new Paragraph({ children: [new PageBreak()] }));

// ═══════════════════════ TABLE OF CONTENTS ═══════════════════════
C.push(h1("Table of Contents"),
table(["Sl.No", "Contents", "Page No."], [
  ["", "Abstract", "i"],
  ["1.", "INTRODUCTION", "1"],
  ["", "1.1 Background", "1"],
  ["", "1.2 Motivation", "1"],
  ["", "1.3 Scope of the Project", "1"],
  ["2.", "PROJECT DESCRIPTION AND GOALS", "3"],
  ["", "2.1 Literature Review", "3"],
  ["", "2.2 Research Gap", "4"],
  ["", "2.3 Problem Statement", "4"],
  ["", "2.4 Objectives", "5"],
  ["", "2.5 Project Plan", "5"],
  ["3.", "TECHNICAL SPECIFICATION", "7"],
  ["", "3.1 Requirements", "7"],
  ["", "3.2 Feasibility Study", "8"],
  ["", "3.3 System Specification", "9"],
  ["4.", "DESIGN APPROACH AND DETAILS", "11"],
  ["", "4.1 System Architecture", "11"],
  ["", "4.2 Design", "12"],
  ["5.", "EXPERIMENTAL SETUP AND OUTPUT", "16"],
  ["", "5.1 Experimental Setup", "16"],
  ["", "5.2 Output of the Proposed System", "16"],
  ["6.", "RESULT ANALYSIS", "19"],
  ["", "6.1 Comparison with Existing Systems", "19"],
  ["7.", "CONCLUSION AND FUTURE WORKS", "22"],
  ["8.", "REFERENCES", "23"],
  ["", "APPENDIX A. SOURCE CODE AND REPOSITORY", "25"],
  ["", "APPENDIX B. CORE IMPLEMENTATION", "27"],
], [986, 6465, 1315], { borderless: true }),
new Paragraph({ children: [new PageBreak()] }));

// ═══════════════════════ 1. INTRODUCTION ═══════════════════════
C.push(h1("1. Introduction"),
h2("1.1 Background"),
body("Large language models are no longer used only to generate text. They are increasingly deployed as agents that retrieve documents, browse the web, read mail and call tools on a user's behalf. That changes the security picture. A passive model that writes something undesirable does limited harm. An agent that can read files, send mail and make network requests does real harm when misled."),
body("The problem is structural, not a bug in any one product. A model receives its system prompt, the user's request and any retrieved content as one undifferentiated token sequence, with no field or delimiter marking which portion carries authority. To the model, text pulled out of a document looks exactly like an instruction from its operator."),
body("Indirect prompt injection exploits exactly this. The attacker never contacts the agent at all. They put crafted text where the agent will later read it: a support ticket, an HTML comment no human will see, a CV in an automated screening pipeline. The planted instruction then competes with the legitimate task, and it often wins. OWASP ranks prompt injection as LLM01, the top risk for these applications, and notes that no complete fix exists at the model layer."),
h2("1.2 Motivation"),
body("Most proposed defences share one weakness. They live inside the prompt, which is the same channel the attack uses. Telling a model to ignore commands it finds in documents puts a defensive sentence up against an offensive one and leaves the model to referee. It also fails silently. When the defence is overridden, the operator gets no signal at all, arguably worse than no defence."),
body("Two other approaches are no better. Keyword blocklists are easy to get around by rewording: we measured one, and it caught only " + pc(E.baseline.recall) + " of attacks written without the stock phrasing. Using a second language model as a judge doubles the cost and delay of every request, and the judge is itself a model reading attacker-controlled text, so it can be injected too."),
body("We started from a simple position: the control has to sit outside the model. If the model cannot reliably tell an instruction from data, something else should make that call for it. That something should be deterministic, should track where every span came from, and should be out of reach of the attacker's text. Such a layer can be unit-tested and audited, which a paragraph of English in a system prompt cannot."),
h2("1.3 Scope of the Project"),
body("The project delivers a working middleware library that sits between an agent runtime and a language model and controls traffic in both directions. On the way in it canonicalises, inspects, scores and neutralises untrusted text. On the way out it checks the model's output and any tool call it proposes for leaked credentials, exfiltration channels and capability violations."),
body("In scope: the eight attack families named in the literature, resistance to character-level and encoding-level evasion, cross-lingual coverage across twelve languages, a trust model with five levels, per-turn capability restriction, an append-only audit trail, a reproducible evaluation that includes an adaptive adversary, and an interactive console for demonstrating the system against a local model."),
body("Out of scope: changing or fine-tuning the model itself, defending against an attacker who can reach the model weights or our own configuration file, and attacks that never travel through the text channel, such as a compromised tool implementation. We designed this as one layer of a defence-in-depth setup, not as a complete answer, and we report it on that basis."),
new Paragraph({ children: [new PageBreak()] }));

// ═══════════ 2. PROJECT DESCRIPTION AND GOALS ═══════════
C.push(h1("2. Project Description and Goals"),
h2("2.1 Literature Review"),
body("Perez and Ribeiro (2022) gave the first systematic account of the problem. They named the two primitives that are still the standard taxonomy: goal hijacking, where the attacker pulls the model off the operator's task, and prompt leaking, where the attacker extracts the confidential system prompt. They also showed that handcrafted adversarial prompts work across different model families, so the weakness is not an artefact of one training run."),
body("Greshake et al. (2023) introduced the indirect variant that this project is about. Their key point is that the attacker never has to interact with the agent at all. It is enough to poison a document the agent will later retrieve. They catalogue delivery routes including web pages, mail and code repositories, and they demonstrate working compromises of deployed retrieval-augmented systems. What they contribute is a threat model, not a defence."),
body("Liu et al. (2024) gave the field its first shared formalisation and benchmark, so attacks and defences could finally be compared on equal terms. Their main empirical finding matters directly to us. Prompt-level defences fall off sharply when the attack is paraphrased, because defence and attack sit in the same channel and the model has to choose between them."),
body("Hines et al. (2024) proposed spotlighting, a set of techniques that mark untrusted content so the model can tell it apart from instructions. The most effective variant was datamarking, which threads a private marker character through the untrusted span. We implement datamarking directly. It has one weakness we want to be explicit about: it depends on the model choosing to respect the convention. A model that ignores the marker is simply unprotected, and nothing tells the operator that this has happened."),
body("Willison (2023) described the dual LLM pattern. A quarantined model handles the untrusted content and holds no privileges, while a privileged model never sees that content directly. The isolation is architecturally sound, but it is expensive. It needs two inference passes and a tightly constrained interface between them, which puts it out of reach for most deployments."),
body("Zou et al. (2023) showed that adversarial suffixes found by gradient search transfer across model families. Two things follow. Susceptibility is a property of the architecture, not of one training run, and any defence built on a fixed blocklist will not hold. Carlini et al. (2023) reached a matching conclusion from the alignment side, showing that models aligned against harmful output are still exploitable by an adversary. Between them, these two results are why we put our control outside the model instead of trying to harden the model."),
body("Yi et al. (2023) built a benchmark specifically for indirect injection and tested several defences on it. They found that detectors trained on one attack distribution generalise poorly to another. That finding is what led us to calibrate by leave-one-family-out, withholding a whole attack category and then measuring recall on it. Debenedetti et al. (2024) introduced AgentDojo, where attacks and defences are evaluated against an agent doing realistic tasks instead of against static strings. Their insistence on measuring usefulness alongside security is why we report the false-positive rate and task completion next to every detection figure."),
body("Abdelnabi et al. (2023) catalogued delivery vectors and showed that retrieval pipelines, mail and code repositories all work as carriers. That survey is where our five trust tiers come from. On the evasion side, Li et al. (2019) showed with TextBugger that small character-level changes defeat text classifiers while a human still reads the text normally. That result drives two of our design choices: the canonicalisation stage, and the use of character n-grams alongside word n-grams in the learned detector. The Unicode Consortium (2023) security-mechanisms specification supplies the confusable mappings behind our homoglyph table."),
body("The OWASP Foundation (2023) supplies the risk framing and the LLM01 classification we use throughout this report. The wider literature on canary tokens and exfiltration through rendered markup informs our egress stage, and in particular the zero-click image beacon, where a markdown image reference makes the client issue a network request with no user interaction at all."),
h2("2.2 Research Gap"),
body("The surveyed work falls into three groups, and none of them gives you something you can actually deploy. The first group (Perez and Ribeiro, Greshake et al.) characterises the attacks and establishes how serious they are, but proposes no defence. The second (Liu et al.) supplies evaluation infrastructure and shows that existing defences are fragile, without building a stronger one. The third (Hines et al., Willison) proposes mitigations that either rely on the model choosing to comply, and so fail silently when it does not, or cost so much architecturally that most deployments cannot adopt them."),
body("Three specific gaps follow. First, no defence we surveyed works outside the model while staying model-agnostic, so that swapping the model out does not invalidate it. Second, defences are tested against fixed payload sets, not against an attacker who adapts, so every published robustness figure is an upper bound of unknown tightness. Third, and most concretely, the literature is written and evaluated almost entirely in English. Not one surveyed defence reports cross-lingual coverage, even though most web content is not in English. We measured what that costs: an English-only detector ensemble caught " + pc(ML.before.recall) + " of non-English versions of payloads it catches easily in English."),
h2("2.3 Problem Statement"),
body("An agent reads text from channels of differing trustworthiness and holds tools that can act in the world. Build a control that decides, for each span of text, whether that span is allowed to influence the agent's behaviour. It must do this without a second inference pass in the request path. It must stay valid when the underlying model is swapped out. And when it is uncertain, or when one of its own components breaks, it must fail safe instead of failing silently."),
body("The control also has to be usable. A filter that blocks legitimate work gets uninstalled, so we treat the false-positive rate on benign content as a first-class constraint and build it into the optimisation objective rather than checking it at the end."));

C.push(h2("2.4 Objectives"));
[
  ["Canonicalise hostile text.", "Reverse zero-width and bidirectional control characters, Unicode compatibility variants, homoglyph substitution, concealed markup and layered encodings, and treat the quantity of reversal required as evidence in its own right, since benign documents require none."],
  ["Detect by multiple independent means.", "Construct an ensemble whose members fail in uncorrelated ways, so that no single evasion technique defeats all of them simultaneously."],
  ["Extend detection beyond English.", "Provide cross-lingual coverage such that an adversary cannot bypass the system merely by changing language."],
  ["Fuse evidence under provenance.", "Combine detections probabilistically and weight the result by the trustworthiness of the channel on which the text arrived."],
  ["Neutralise without discarding.", "Preserve the informational content of suspicious text while destroying its capacity to act as an instruction, so that the agent remains useful."],
  ["Constrain capability per turn.", "Revoke precisely those tools that the detected attack family would require, applying least privilege for the duration of a single turn."],
  ["Guard the outbound path.", "Detect credential disclosure, system-prompt leakage and zero-click exfiltration channels in model output and in proposed tool invocations."],
  ["Evaluate honestly.", "Measure against held-out data, against an adaptive adversary and against a real language model, and report what is measured including results that do not favour the system."],
].forEach(([t, d]) => C.push(rich([{ text: t + " ", bold: true }, { text: d }],
  { spacing: { after: 100 } })));

C.push(h2("2.5 Project Plan"),
body("The work was divided into seven phases over one semester: literature survey and threat modelling, corpus construction and pipeline design, detector implementation and calibration, held-out evaluation and ablation, cross-lingual extension, adaptive adversary and hardening, and finally the console, the live-model evaluation and this report. All seven are complete. Fig. 1 shows the schedule as a Gantt chart and the months are indicative. The plan below is the schedule as worked rather than as first drafted: phases 5 and 6 were added partway through in response to findings, and that is recorded here because the order of events is itself part of the result."),
figImage("fig_gantt.png", 980 / 412),
caption("Fig. 1. Gantt chart"),
table(["Phase", "Activity", "Weeks", "Outcome"], [
  ["1", "Literature survey and threat modelling", "1–2", "Eight attack families identified"],
  ["2", "Corpus construction and pipeline design", "3–4", "753-sample corpus; five-stage architecture"],
  ["3", "Detector implementation and calibration", "5–7", "Four detectors; leave-one-family-out calibration"],
  ["4", "Held-out evaluation and ablation", "8–9", "F1 " + f3(F.f1) + "; benign-class defect identified"],
  ["5", "Cross-lingual extension", "10–11", "Fifth detector; " + ML.languages.length + " languages"],
  ["6", "Adaptive adversary and hardening", "12–13", "Robustness " + pc(RT.robustness) + "; two defects closed"],
  ["7", "Console, live-model evaluation, report", "14–15", "Web console; end-to-end LLM benchmark"],
], [877, 4383, 1205, 2301]),
caption("Table 1. Project plan as executed."),
new Paragraph({ children: [new PageBreak()] }));

// ═══════════════ 3. TECHNICAL SPECIFICATION ═══════════════
C.push(h1("3. Technical Specification"),
h2("3.1 Requirements"),
h3("3.1.1 Functional"));
[
  "The system shall accept a span of text together with a declared provenance tier and return a decision of allow, sanitise or block.",
  "The system shall reverse zero-width characters, Unicode compatibility variants, homoglyph substitutions, concealed markup and base64, hexadecimal, percent and ROT13 encodings prior to inspection.",
  "The system shall score text over overlapping windows so that a short payload embedded in a long document is not diluted.",
  "The system shall detect the eight attack families: instruction override, role manipulation, prompt leaking, exfiltration, tool abuse, delimiter escape, social engineering and obfuscation.",
  "The system shall detect injections expressed in languages other than English.",
  "The system shall weight its risk assessment by provenance, distinguishing system, user, tool, retrieved and web channels.",
  "The system shall neutralise suspicious spans by datamarking and nonce fencing while preserving their informational content.",
  "The system shall revoke, for the duration of one turn, those capabilities associated with the detected attack family.",
  "The system shall inspect outbound model output for credential material, system-prompt disclosure and zero-click exfiltration channels.",
  "The system shall validate proposed tool invocations against the capability set remaining for that turn.",
  "The system shall record every decision, including permissive ones, together with the evidence that produced it.",
].forEach(t => C.push(bullet(t)));

C.push(h3("3.1.2 Non-Functional"));
[
  "Performance: inspection shall add no more than fifty milliseconds per span at the median on commodity hardware. Measured: " + E.latency_ms.p50 + " ms median, " + E.latency_ms.p95 + " ms at the ninety-fifth percentile.",
  "Precision: the false-positive rate on benign traffic shall not exceed five per cent. Measured: " + pc(F.fpr) + ".",
  "Portability: the system shall carry no third-party runtime dependency and shall require neither network access nor a graphics processor.",
  "Model independence: the system shall remain valid when the underlying language model is replaced, requiring no fine-tuning and no provider-specific interface.",
  "Fail-safe behaviour: a malfunctioning detector shall be treated as a detection rather than ignored, since middleware that silently degrades to inaction is worse than none, the operator continuing to believe themselves protected.",
  "Auditability: every decision shall carry human-readable justification sufficient to reconstruct it.",
  "Maintainability: adding an attack signature, an exemplar or a language shall require a data change rather than a code change.",
].forEach(t => C.push(bullet(t)));

C.push(h2("3.2 Feasibility Study"),
h3("3.2.1 Technical Feasibility"));
[
  ["Technology Availability.", "The system is written entirely against the Python standard library. Every mechanism it needs, Unicode normalisation, regular expressions, hashing and JSON, is already in the runtime."],
  ["Technical Expertise.", "The project needs knowledge of applied NLP and of the attack literature. The classifier is a logistic regression over hashed n-grams, implemented from first principles in about two hundred lines, so no machine-learning framework has to be learned or maintained."],
  ["Infrastructure.", "No graphics processor, no network access and no second inference pass. The trained model occupies " + Math.round(fs.statSync(path.join(H.ROOT, "pidguard/models/lr_model.json")).size / 1024) + " kilobytes and loads in milliseconds, so deployment adds nothing to the infrastructure an agent already needs."],
  ["Integration.", "The layers are loosely coupled. The middleware is imported as a package and called at two points, before text reaches the model and before output leaves, so it can be fitted to an existing agent without changing the model or the provider."],
].forEach(([t, d]) => C.push(rich([{ text: t + " ", bold: true }, { text: d }],
  { spacing: { after: 90 } })));
C.push(
h3("3.2.2 Economic Feasibility"));
[
  ["Software Cost.", "None. There is no third-party runtime dependency and therefore no licence fee."],
  ["Hardware Cost.", "None beyond the development laptop. The middleware needs no accelerator and no additional server."],
  ["Cost per Request.", "The middleware adds " + E.latency_ms.p50 + " milliseconds of processor time per span and no monetary cost. An adjudicating-model defence would roughly double the inference bill of every request instead."],
  ["Return on Investment.", "One successful exfiltration of credentials from a production agent is expensive in itself and in disclosure, so the trade is favourable under any realistic estimate of how often an incident occurs."],
  ["Scaling Cost.", "A larger deployment needs only processor time proportional to the text inspected. Nothing in the design requires shared state between requests."],
].forEach(([t, d]) => C.push(rich([{ text: t + " ", bold: true }, { text: d }],
  { spacing: { after: 90 } })));
C.push(
h3("3.2.3 Social Feasibility"));
[
  ["User Acceptance.", "A control that blocks legitimate work gets uninstalled in its first week. The false-positive rate is therefore part of the optimisation objective rather than a figure checked afterwards, and it is reported beside every detection result."],
  ["Transparency.", "Every decision carries the evidence that produced it, including the permissive ones, so a disputed outcome can be examined and explained instead of merely overridden."],
  ["Privacy.", "The system inspects text an agent is about to process on its operator's behalf and performs no monitoring of users. The audit trail records decisions and their evidence and is intended for the operator of the agent."],
  ["Ethical Considerations.", "Detection is reported with its uncertainty and never presented as proof of intent. Results that do not favour the system, including a null result in the end-to-end evaluation, are reported as measured."],
  ["Error Impact.", "A false positive hides legitimate content and a false negative exposes the agent, so the output is decision support within a defence-in-depth posture and not a sole control."],
].forEach(([t, d]) => C.push(rich([{ text: t + " ", bold: true }, { text: d }],
  { spacing: { after: 90 } })));
C.push(
h2("3.3 System Specification"),
h3("3.3.1 Hardware Specification"),
table(["Component", "Specification"], [
  ["Processor", "x86-64, dual core minimum (development: Intel, 8 logical cores)"],
  ["Memory", "4 GB minimum; approximately 60 MB resident for the library"],
  ["Storage", "50 MB for the library, trained model, corpus and benchmark artefacts"],
  ["Graphics processor", "Not required"],
  ["Network", "Not required by the middleware; optional for the live-model evaluation"],
  ["Monitor", "Any display; the console is a browser page and the demonstrations are text"],
], [2650, 6116]),
caption("Table 2. Hardware specification."),
h3("3.3.2 Software Specification"),
table(["Component", "Specification"], [
  ["Operating system", "Windows 11; platform independent (Linux and macOS supported)"],
  ["Programming language", "Python 3.9 or later (developed on 3.11.4)"],
  ["Runtime dependencies", "None — Python standard library only"],
  ["Development environment", "Visual Studio Code; Git"],
  ["Evaluation tooling", "Bundled scripts; Node.js with docx and pptxgenjs for document generation"],
  ["Optional components", "Ollama with a local instruct model, for end-to-end evaluation"],
  ["Libraries and frameworks", "None at runtime. Node.js with docx and pptxgenjs at build time only, for generating this report and the slides"],
  ["Database", "None. Trained weights and calibration are JSON; the corpora are JSONL; the audit trail is held in memory for the session"],
  ["Security tools", "Input size limits, loopback-only binding, no-store response headers, X-Content-Type-Options, and the project's own egress guard and capability gate"],
  ["Interface", "Python API; command-line demonstrations; local web console"],
], [2650, 6116]),
caption("Table 3. Software specification."),
new Paragraph({ children: [new PageBreak()] }));

module.exports = { C, AUTHORS };
