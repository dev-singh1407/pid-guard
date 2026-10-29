/**
 * Builds "Project I Report" for PID-Guard, following the VIT template exactly:
 *
 *   section heading   Times New Roman 14, bold, UPPER CASE, line spacing 1.5
 *   subsection        Times New Roman 13, bold, Title Case, line spacing 1.5
 *   sub-subsection    Times New Roman 12, bold italic, Title Case, 1.5
 *   body              Times New Roman 12, line spacing 1.15
 *   title page        Times New Roman 16 bold upper; names 13 bold upper, 1.5
 *
 * Every figure quoted is read from the benchmark JSON at build time, so the
 * report cannot drift from what the code measures.
 *
 *   node report/build_report.js
 */

const fs = require("fs");
const path = require("path");
const D = require("docx");
const {
  AlignmentType, BorderStyle, Document, Footer, HeadingLevel, ImageRun, PageBreak,
  PageNumber, Packer, Paragraph, ShadingType, Table, TableCell, TableRow,
  TextRun, WidthType,
} = D;

const ROOT = path.join(__dirname, "..");
const J = (p, d) => { try { return JSON.parse(fs.readFileSync(path.join(ROOT, p), "utf8")); } catch (e) { return d; } };

const E  = J("benchmark/results_test.json", null);
const ML = J("benchmark/results_multilingual.json", null);
const RT = J("benchmark/results_redteam.json", null);
const LM = J("benchmark/results_llm.json", null);
const CAL= J("pidguard/models/calibration.json", null);
if (!E) { console.error("run benchmark/evaluate.py --json first"); process.exit(1); }
const F = E.ablation["FULL ENSEMBLE"];

const pc = (x, d = 1) => (x * 100).toFixed(d) + "%";
const f3 = (x) => Number(x).toFixed(3);

// ───────────────────────────── helpers ─────────────────────────────
const TNR = "Times New Roman";
const SP15 = { line: 360 };      // 1.5  (240 = single)
const SP115 = { line: 276 };     // 1.15

const body = (text, opts = {}) => new Paragraph({
  spacing: { ...SP115, after: 120, ...(opts.spacing || {}) },
  alignment: opts.align || AlignmentType.JUSTIFIED,
  indent: opts.indent,
  children: [new TextRun({ text, font: TNR, size: 24, ...(opts.run || {}) })],
});

const rich = (runs, opts = {}) => new Paragraph({
  spacing: { ...SP115, after: 120, ...(opts.spacing || {}) },
  alignment: opts.align || AlignmentType.JUSTIFIED,
  children: runs.map(r => new TextRun({ font: TNR, size: 24, ...r })),
});

const h1 = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_1,
  spacing: { ...SP15, before: 360, after: 200 },
  children: [new TextRun({ text: text.toUpperCase(), font: TNR, size: 28, bold: true, color: "000000" })],
});

const h2 = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_2,
  spacing: { ...SP15, before: 280, after: 140 },
  children: [new TextRun({ text, font: TNR, size: 26, bold: true, color: "000000" })],
});

const h3 = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_3,
  spacing: { ...SP15, before: 200, after: 120 },
  children: [new TextRun({ text, font: TNR, size: 24, bold: true, italics: true, color: "000000" })],
});

const bullet = (text, lvl = 0) => new Paragraph({
  numbering: { reference: "bul", level: lvl },
  spacing: { ...SP115, after: 80 },
  alignment: AlignmentType.JUSTIFIED,
  children: [new TextRun({ text, font: TNR, size: 24 })],
});

const caption = (text) => new Paragraph({
  alignment: AlignmentType.CENTER,
  spacing: { before: 100, after: 240 },
  children: [new TextRun({ text, font: TNR, size: 22, italics: true })],
});

const mono = (text) => new Paragraph({
  spacing: { line: 240, after: 60 },
  children: [new TextRun({ text, font: "Consolas", size: 19 })],
});

const centre = (text, size, bold, caps) => new Paragraph({
  alignment: AlignmentType.CENTER,
  spacing: { ...SP15, after: 120 },
  children: [new TextRun({ text: caps ? text.toUpperCase() : text, font: TNR, size, bold })],
});

const gap = (n = 1) => Array.from({ length: n }, () =>
  new Paragraph({ spacing: { after: 0 }, children: [new TextRun({ text: "", font: TNR, size: 24 })] }));

// table: header row + body rows, all widths in DXA summing to the table width
function table(headers, rows, widths, opts = {}) {
  const total = widths.reduce((a, b) => a + b, 0);
  // The template requires the table of contents to carry no borders.
  const NONE = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
  const borderless = opts.borderless
    ? { top: NONE, bottom: NONE, left: NONE, right: NONE,
        insideHorizontal: NONE, insideVertical: NONE }
    : undefined;
  const cell = (t, w, o = {}) => new TableCell({
    width: { size: w, type: WidthType.DXA },
    shading: (o.head && !opts.borderless)
      ? { type: ShadingType.CLEAR, fill: "E8EDF6" } : undefined,
    margins: { top: 60, bottom: 60, left: 90, right: 90 },
    children: [new Paragraph({
      alignment: o.num ? AlignmentType.RIGHT : AlignmentType.LEFT,
      spacing: { line: 240, after: 0 },
      children: [new TextRun({ text: String(t), font: TNR, size: 21, bold: !!o.head })],
    })],
  });
  return new Table({
    columnWidths: widths,
    borders: borderless,
    width: { size: total, type: WidthType.DXA },
    rows: [
      new TableRow({ tableHeader: true, children: headers.map((h, i) => cell(h, widths[i], { head: true })) }),
      ...rows.map(r => new TableRow({
        children: r.map((c, i) => cell(c, widths[i], { num: i > 0 })),
      })),
    ],
  });
}

const W = [2650, 1529, 1529, 1529, 1529];   // 5-col default (8600 dxa ≈ 6")

// ─────────────────── block diagram (Fig. 1) ───────────────────
// Drawn with Word tables so the boxes align exactly at any zoom and in any
// font, which ASCII art does not.
const FIGW = 8766;

const figLine = (t, o = {}) => new Paragraph({
  alignment: o.align || AlignmentType.LEFT,
  spacing: { line: 240, before: o.before || 0, after: o.after || 0 },
  children: [new TextRun({ text: t, font: TNR, size: o.size || 21,
    bold: !!o.bold, italics: !!o.italics, color: o.color || "000000" })],
});

// one labelled stage: number in a shaded cell, text beside it
function figStage(n, title, detail, opts = {}) {
  const numW = 620, txtW = FIGW - numW;
  const bd = { style: BorderStyle.SINGLE, size: 6, color: "000000" };
  const cell = (w, kids, fill) => new TableCell({
    width: { size: w, type: WidthType.DXA },
    shading: fill ? { type: ShadingType.CLEAR, fill } : undefined,
    margins: { top: 70, bottom: 70, left: 110, right: 110 },
    verticalAlign: "center",
    children: kids,
  });
  return new Table({
    columnWidths: [numW, txtW],
    width: { size: FIGW, type: WidthType.DXA },
    borders: { top: bd, bottom: bd, left: bd, right: bd,
               insideHorizontal: bd, insideVertical: bd },
    rows: [new TableRow({ children: [
      cell(numW, [figLine(String(n), { align: AlignmentType.CENTER, bold: true, size: 22 })],
           opts.fill || "E8EDF6"),
      cell(txtW, [figLine(title, { bold: true, size: 22 }),
                  figLine(detail, { size: 20, color: "333333" })]),
    ] })],
  });
}

// a plain full-width band (used for the endpoints of the figure)
function figBand(title, detail, fill) {
  const bd = { style: BorderStyle.SINGLE, size: 6, color: "000000" };
  return new Table({
    columnWidths: [FIGW],
    width: { size: FIGW, type: WidthType.DXA },
    borders: { top: bd, bottom: bd, left: bd, right: bd,
               insideHorizontal: bd, insideVertical: bd },
    rows: [new TableRow({ children: [new TableCell({
      width: { size: FIGW, type: WidthType.DXA },
      shading: { type: ShadingType.CLEAR, fill: fill || "FFFFFF" },
      margins: { top: 70, bottom: 70, left: 110, right: 110 },
      children: [figLine(title, { align: AlignmentType.CENTER, bold: true, size: 22 }),
                 figLine(detail, { align: AlignmentType.CENTER, size: 20, color: "333333" })],
    })] })],
  });
}

// A drawn figure embedded from a PNG, sized to the exact text column.
// docx-js takes the transformation in CSS pixels at 96 dpi, so the text
// width of 8766 dxa (6.088 in, 438 pt) is 584 px.
function figImage(file, aspect) {
  const wPt = 584;
  return new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 120, after: 0 },
    children: [new ImageRun({
      type: "png",
      data: fs.readFileSync(path.join(__dirname, file)),
      transformation: { width: wPt, height: Math.round(wPt / aspect) },
    })],
  });
}

// A verbatim source listing, read from the repository at build time so the
// appendix cannot drift from the code it quotes. Line numbers are the real
// ones from the file.
function codeBlock(relPath, from, to) {
  const src = fs.readFileSync(path.join(ROOT, relPath), "utf8");
  const lines = src.split(String.fromCharCode(10))
    .map(function (ln) { return ln.replace(String.fromCharCode(13), ""); });
  const slice = lines.slice(from - 1, to);
  const width = String(to).length;
  return slice.map((ln, i) => new Paragraph({
    spacing: { line: 200, after: 0 },
    indent: { left: 120 },
    children: [
      new TextRun({ text: String(from + i).padStart(width, " ") + "  ",
                    font: "Consolas", size: 15, color: "808080" }),
      new TextRun({ text: ln || " ", font: "Consolas", size: 15 }),
    ],
  }));
}

const figArrow = (label) => new Paragraph({
  alignment: AlignmentType.CENTER,
  spacing: { line: 240, before: 40, after: 40 },
  children: [new TextRun({ text: label ? "↓   " + label : "↓",
    font: TNR, size: 20, bold: true })],
});

module.exports = { D, AlignmentType, BorderStyle, Document, Footer, HeadingLevel,
  PageBreak, PageNumber, Packer, Paragraph, Table, TableCell, TableRow, TextRun,
  WidthType, ROOT, E, ML, RT, LM, CAL, F, pc, f3, TNR, SP15, SP115, body, rich,
  h1, h2, h3, bullet, caption, mono, centre, gap, table, W,
  figStage, figBand, figArrow, figLine, figImage, codeBlock };
