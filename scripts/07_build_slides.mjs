import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Presentation, PresentationFile } from "@oai/artifact-tool";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const here = path.resolve(scriptDir, "..", ".codex-build", "pptx");
const workspaceDir = path.resolve(here, "..", "..");
const outDir = path.join(here, "render");
const candidatePath = path.join(here, "candidate.pptx");
const finalPath = path.join(workspaceDir, "docs", "slides.pptx");
const SKILL_DIR = "C:\\Users\\sumit\\.codex\\plugins\\cache\\openai-primary-runtime\\presentations\\26.1117.12345\\skills\\presentations";

const W = 1280, H = 720;
const C = {
  bg: "#F8F7F3", navy: "#19344F", teal: "#177E78", orange: "#CF8741",
  red: "#B85B4B", text: "#28343E", muted: "#65727D", line: "#CDD5DB",
  pale: "#E9EFEE", white: "#FFFFFF", blue: "#537FA8", green: "#638B72",
};
const FONT = "Arial";

async function writeBlob(file, blob) {
  await fs.writeFile(file, new Uint8Array(await blob.arrayBuffer()));
}

function addText(slide, text, x, y, w, h, style = {}, name = undefined) {
  const shape = slide.shapes.add({
    geometry: "textbox", name,
    position: { left: x, top: y, width: w, height: h },
    fill: "none", line: { style: "solid", fill: "none", width: 0 },
  });
  shape.text = text;
  shape.text.style = {
    typeface: FONT, fontSize: "20pt", color: C.text,
    verticalAlignment: "top", alignment: "left", insets: 0,
    autoFit: "shrinkText", ...style,
  };
  return shape;
}

function addRect(slide, x, y, w, h, fill, line = "none", name = undefined) {
  return slide.shapes.add({
    geometry: "rect", name,
    position: { left: x, top: y, width: w, height: h },
    fill, line: { style: "solid", fill: line, width: line === "none" ? 0 : 1 },
  });
}

function startSlide(presentation, number, stage, title) {
  const slide = presentation.slides.add();
  slide.background.fill = C.bg;
  addText(slide, stage.toUpperCase(), 72, 42, 420, 24,
    { fontSize: "11pt", bold: true, color: C.teal }, `stage-${number}`);
  addText(slide, title, 72, 78, 1136, 60,
    { fontSize: "32pt", bold: true, color: C.navy }, `title-${number}`);
  addRect(slide, 72, 151, 68, 4, C.teal, "none", `title-rule-${number}`);
  addText(slide, "Beyond CVSS  |  Advanced Data Science", 72, 684, 600, 20,
    { fontSize: "9pt", color: C.muted, verticalAlignment: "middle" }, `footer-${number}`);
  addText(slide, String(number).padStart(2, "0"), 1158, 684, 50, 20,
    { fontSize: "9pt", color: C.muted, alignment: "right", verticalAlignment: "middle" }, `page-${number}`);
  return slide;
}

function addChart(slide, kind, config) {
  return slide.charts.add(kind, {
    chartFill: C.bg,
    chartLine: { style: "solid", fill: "none", width: 0 },
    plotAreaFill: C.bg,
    plotAreaLine: { style: "solid", fill: "none", width: 0 },
    titleTextStyle: { typeface: FONT, fontSize: 17, fill: C.navy, bold: true },
    xAxis: { textStyle: { typeface: FONT, fontSize: 12, fill: C.muted }, line: { style: "solid", fill: C.line, width: 1 }, majorGridlines: null },
    yAxis: { textStyle: { typeface: FONT, fontSize: 12, fill: C.muted }, line: { style: "solid", fill: C.line, width: 1 }, majorGridlines: { style: "solid", fill: C.line, width: 1 } },
    ...config,
  });
}

function notes(slide, text) {
  slide.speakerNotes.text = text;
}

const presentation = Presentation.create({ slideSize: { width: W, height: H } });

// 1. Title
{
  const slide = presentation.slides.add();
  slide.background.fill = C.bg;
  addRect(slide, 72, 84, 8, 470, C.teal, "none", "cover-accent");
  addText(slide, "BEYOND CVSS", 112, 115, 1010, 64,
    { fontSize: "44pt", bold: true, color: C.navy }, "cover-title");
  addText(slide, "Evaluating EPSS for vulnerability patch prioritization", 112, 204, 1000, 74,
    { fontSize: "27pt", color: C.text }, "cover-subtitle");
  addText(slide, "Does an exploitation-probability signal help a security team spend a limited patching budget?",
    112, 325, 810, 82, { fontSize: "21pt", color: C.muted }, "cover-question");
  addRect(slide, 112, 448, 115, 4, C.orange, "none", "cover-rule");
  addText(slide, "Sumit Sharma  |  Ayansh Pandey\nAdvanced Data Science  |  BML Munjal University\n19 November 2026",
    112, 480, 780, 105, { fontSize: "15pt", color: C.text, lineSpacing: 1.1 }, "cover-team");
  notes(slide, "Project report and analysis prepared from the local repository. AI assistance was used for code and document drafting and is disclosed in the project materials.");
}

// 2. Decision problem
{
  const slide = startSlide(presentation, 2, "Stage 1  |  Define the problem", "Patch budgets are fixed");
  addText(slide, "Security teams must choose which vulnerabilities to patch first when open work exceeds available capacity.",
    72, 190, 650, 108, { fontSize: "24pt", color: C.text }, "decision-statement");
  addText(slide, "Research question", 72, 340, 300, 28, { fontSize: "13pt", bold: true, color: C.teal }, "question-label");
  addText(slide, "At the same patching budget, does EPSS or a CVSS + EPSS ranking capture more CVEs later added to CISA KEV than CVSS alone?",
    72, 375, 700, 102, { fontSize: "20pt", color: C.text }, "research-question");
  addRect(slide, 846, 208, 1, 346, C.line, "none", "decision-divider");
  addText(slide, "30 days", 900, 255, 270, 58, { fontSize: "36pt", bold: true, color: C.navy }, "outcome-window");
  addText(slide, "KEV additions after each decision date form the outcome label.",
    900, 327, 260, 105, { fontSize: "18pt", color: C.muted }, "outcome-definition");
  addText(slide, "Primary KPI  Recall@K\nSupporting metrics  Precision@K and Average Precision",
    900, 465, 270, 70, { fontSize: "13pt", color: C.text }, "metrics");
  notes(slide, "The project measures catalogue additions within 30 days. This is a decision-support backtest, not a causal study and not a live patching system. Source: CISA KEV catalogue, https://www.cisa.gov/known-exploited-vulnerabilities-catalog.");
}

// 3. Sources and scope
{
  const slide = startSlide(presentation, 3, "Stage 1  |  Define the problem", "Three sources, ten dated snapshots");
  const sourceCols = [
    { x: 72, name: "NVD", detail: "CVE records\nPublication dates\nCVSS and CWE\nCPE and references", color: C.blue },
    { x: 456, name: "FIRST EPSS", detail: "Dated exploitation\nprobability\nPercentile\nModel version", color: C.teal },
    { x: 840, name: "CISA KEV", detail: "Known exploited\nvulnerabilities\nCatalogue-added date\nOutcome label", color: C.orange },
  ];
  for (const item of sourceCols) {
    addRect(slide, item.x, 200, 320, 5, item.color, "none");
    addText(slide, item.name, item.x, 228, 320, 40, { fontSize: "22pt", bold: true, color: C.navy });
    addText(slide, item.detail, item.x, 284, 320, 128, { fontSize: "17pt", color: C.text, lineSpacing: 1.08 });
  }
  addRect(slide, 72, 455, 1136, 1, C.line, "none");
  addText(slide, "10", 72, 483, 160, 54, { fontSize: "34pt", bold: true, color: C.teal });
  addText(slide, "fixed decision dates", 72, 539, 270, 30, { fontSize: "14pt", color: C.muted });
  addText(slide, "934,180", 444, 483, 260, 54, { fontSize: "34pt", bold: true, color: C.teal });
  addText(slide, "CVE-date rows", 444, 539, 260, 30, { fontSize: "14pt", color: C.muted });
  addText(slide, "109", 840, 483, 200, 54, { fontSize: "34pt", bold: true, color: C.orange });
  addText(slide, "future KEV labels", 840, 539, 260, 30, { fontSize: "14pt", color: C.muted });
  notes(slide, "Data sources: NVD CVE 2.0 feeds, https://nvd.nist.gov/vuln/data-feeds; FIRST EPSS, https://www.first.org/epss/; CISA KEV catalogue, https://www.cisa.gov/known-exploited-vulnerabilities-catalog. Decision dates are February 19 and August 19, 2022-2026.");
}

// 4. Panel construction
{
  const slide = startSlide(presentation, 4, "Stage 2  |  Validate the evidence", "Build one date-aware panel");
  const boxes = [
    { x: 72, y: 225, w: 245, h: 126, title: "NVD base", detail: "Published before date\nHistorical CVSS from change log" },
    { x: 380, y: 225, w: 245, h: 126, title: "Eligibility", detail: "Remove prior KEVs\nNormalize CVE ID" },
    { x: 688, y: 225, w: 245, h: 126, title: "Dated EPSS", detail: "Snapshot for date\nKeep model version" },
    { x: 996, y: 225, w: 212, h: 126, title: "Panel row", detail: "Age + scores\n30-day label" },
  ];
  for (const b of boxes) {
    addRect(slide, b.x, b.y, b.w, b.h, C.white, C.line);
    addText(slide, b.title, b.x + 16, b.y + 14, b.w - 32, 30, { fontSize: "17pt", bold: true, color: C.navy });
    addText(slide, b.detail, b.x + 16, b.y + 54, b.w - 32, 58, { fontSize: "13pt", color: C.muted });
  }
  for (const x of [328, 636, 944]) addText(slide, ">", x, 266, 34, 40, { fontSize: "30pt", bold: true, color: C.orange, alignment: "center" });
  addText(slide, "For each date: keep CVEs published before it, remove KEVs already listed, then label additions in the next 30 days.",
    72, 408, 1120, 60, { fontSize: "17pt", color: C.text }, "panel-rule");
  addText(slide, "No score is filled with zero. CVSS 4.0 is analyzed separately from the main CVSS 3.x comparison.",
    72, 496, 1100, 62, { fontSize: "15pt", color: C.muted }, "quality-rules");
  notes(slide, "The build checks normalized IDs, duplicate IDs, score ranges, publication-date leakage, prior-KEV exclusion, and 30-day labels. CVSS 3.x is reconstructed from timestamped NVD history strictly before 00:00 UTC on the decision date. Other NVD enrichment fields are current. Sources: NVD, FIRST EPSS, and CISA KEV.");
}

// 5. Methods
{
  const slide = startSlide(presentation, 5, "Stage 2  |  Validate the evidence", "Compare rankings and model scores");
  const labels = ["CVSS-only", "EPSS-only", "Combined"];
  const formulas = ["CVSS v3.0 / v3.1 score as of date", "EPSS score from that decision date", "0.5 x (CVSS / 10) + 0.5 x EPSS"];
  labels.forEach((label, i) => {
    const y = 195 + i * 93;
    addText(slide, label, 72, y, 220, 35, { fontSize: "19pt", bold: true, color: i === 1 ? C.teal : C.navy });
    addText(slide, formulas[i], 320, y + 2, 520, 42, { fontSize: "17pt", color: C.text });
    addRect(slide, 72, y + 60, 742, 1, C.line, "none");
  });
  addRect(slide, 876, 192, 1, 365, C.line, "none");
  addText(slide, "Budgets", 920, 202, 250, 28, { fontSize: "13pt", bold: true, color: C.teal });
  addText(slide, "K = 50, 100, 500, 1,000", 920, 238, 280, 56, { fontSize: "18pt", color: C.text });
  addText(slide, "Models", 920, 328, 250, 28, { fontSize: "13pt", bold: true, color: C.teal });
  addText(slide, "Logistic Regression\nRandom Forest\nXGBoost", 920, 364, 280, 92, { fontSize: "16pt", color: C.text });
  addText(slide, "Time split", 920, 488, 250, 28, { fontSize: "13pt", bold: true, color: C.teal });
  addText(slide, "Train through Aug 2025\nValidate Feb 2026\nTest Aug 2026", 920, 524, 280, 90, { fontSize: "13pt", color: C.text });
  notes(slide, "The combined score is a transparent baseline rather than a tuned optimum. The model sets include historical CVSS, age, and CVSS vector fields; the with-EPSS set adds the dated score and percentile. Current NVD enrichment fields are excluded. Class weighting addresses imbalance.");
}

// 6. Outcome scarcity
{
  const slide = startSlide(presentation, 6, "Stage 2  |  Validate the evidence", "The positive class is very small");
  addText(slide, "109", 72, 218, 260, 100, { fontSize: "58pt", bold: true, color: C.orange });
  addText(slide, "positive CVE-date rows", 72, 322, 380, 40, { fontSize: "19pt", color: C.text });
  addText(slide, "0.012%", 472, 218, 320, 100, { fontSize: "58pt", bold: true, color: C.teal });
  addText(slide, "of 934,180 panel rows", 472, 322, 380, 40, { fontSize: "19pt", color: C.text });
  addRect(slide, 854, 209, 1, 220, C.line, "none");
  addText(slide, "4 positives", 900, 242, 300, 50, { fontSize: "25pt", bold: true, color: C.navy });
  addText(slide, "in February 2024\nRecall changes by 25 points per captured CVE", 900, 310, 280, 90, { fontSize: "15pt", color: C.muted });
  addText(slide, "Bootstrap intervals are wide, and pooled rows include CVEs repeated at different dates.",
    72, 480, 1080, 60, { fontSize: "17pt", color: C.text });
  notes(slide, "Across the ten dates there are 109 positives. Some dates have only four to six positives, so date-level Recall@K moves in large steps. Bootstrap intervals resample CVE-date rows within each date; repeated-CVE dependence remains a limitation.");
}

// 7. Pooled top K
{
  const slide = startSlide(presentation, 7, "Stage 2  |  Validate the evidence", "Pooled top 1,000 captures 0, 5, or 5 positives");
  addChart(slide, "bar", {
    position: { left: 80, top: 196, width: 650, height: 420 },
    title: "Future KEV additions captured at K = 1,000",
    categories: ["CVSS-only", "EPSS-only", "Combined"],
    series: [{ name: "Captured KEVs", values: [0, 5, 5], fill: C.teal }],
    barOptions: { direction: "column", grouping: "clustered", gapWidth: 75 },
    hasLegend: false,
    dataLabels: { showValue: true, position: "outEnd", textStyle: { typeface: FONT, fontSize: 15, fill: C.navy, bold: true } },
    yAxis: { min: 0, max: 6, majorUnit: 1, title: { text: "Positive rows captured", textStyle: { typeface: FONT, fontSize: 13, fill: C.muted } }, textStyle: { typeface: FONT, fontSize: 12, fill: C.muted }, majorGridlines: { style: "solid", fill: C.line, width: 1 } },
  });
  addText(slide, "Out of 99 common-cohort positives", 790, 220, 380, 32, { fontSize: "14pt", bold: true, color: C.teal });
  addText(slide, "CVSS-only\n0 / 99\n\nEPSS-only\n5 / 99\n\nCombined\n5 / 99",
    790, 268, 360, 290, { fontSize: "21pt", color: C.navy, lineSpacing: 1.0 });
  addText(slide, "Pooled common cohort: 859,971 CVE-date rows. Recall@1,000 is 0.0%, 5.1%, and 5.1%, respectively.",
    72, 620, 1115, 36, { fontSize: "13pt", color: C.muted });
  notes(slide, "The pooled top-1,000 ranking contains 0 CVSS-only, 5 EPSS-only, and 5 combined positives in the common historical CVSS 3.x/EPSS cohort. This is a stacked historical panel, not a real-time joint patch queue. See outputs/tables/ranking_results.csv. Data sources: NVD, FIRST EPSS, CISA KEV.");
}

// 8. Per-date stability
{
  const slide = startSlide(presentation, 8, "Stage 2  |  Validate the evidence", "The leading ranking changes by period");
  addChart(slide, "line", {
    position: { left: 72, top: 185, width: 1136, height: 440 },
    title: "Recall@1,000 by decision date",
    categories: ["22 Feb", "22 Aug", "23 Feb", "23 Aug", "24 Feb", "24 Aug", "25 Feb", "25 Aug", "26 Feb", "26 Aug"],
    series: [
      { name: "CVSS-only", values: [0, 0, 0, 0, 0, 0, 0, 0, 0.105263, 0.166667], line: { style: "solid", fill: C.blue, width: 3 }, marker: { symbol: "circle", size: 7, fill: C.blue } },
      { name: "EPSS-only", values: [0, 0.5, 0.714286, 0.6, 0.25, 0.222222, 0.142857, 0, 0.157895, 0.055556], line: { style: "solid", fill: C.teal, width: 3 }, marker: { symbol: "circle", size: 7, fill: C.teal } },
      { name: "Combined", values: [0.1, 0.5, 0.571429, 0.6, 0.25, 0.222222, 0.142857, 0, 0.210526, 0.166667], line: { style: "solid", fill: C.orange, width: 3 }, marker: { symbol: "circle", size: 7, fill: C.orange } },
    ],
    lineOptions: { smooth: false },
    legend: { position: "bottom", overlay: false, textStyle: { typeface: FONT, fontSize: 13, fill: C.text } },
    hasLegend: true,
    yAxis: { min: 0, max: 0.8, majorUnit: 0.2, numberFormatCode: "0%", title: { text: "Recall", textStyle: { typeface: FONT, fontSize: 13, fill: C.muted } }, textStyle: { typeface: FONT, fontSize: 12, fill: C.muted }, majorGridlines: { style: "solid", fill: C.line, width: 1 } },
    xAxis: { textStyle: { typeface: FONT, fontSize: 11, fill: C.muted }, line: { style: "solid", fill: C.line, width: 1 } },
  });
  notes(slide, "Each point is Recall@1,000 for one decision date on the common CVSS 3.x and EPSS cohort. The 2024 February period has four positives. The latest period favors CVSS; other periods often favor EPSS or Combined. See outputs/tables/ranking_results.csv and robustness_results.csv.");
}

// 9. Predictive models
{
  const slide = startSlide(presentation, 9, "Stage 2  |  Validate the evidence", "EPSS raised test Average Precision for all three models");
  addChart(slide, "bar", {
    position: { left: 72, top: 190, width: 760, height: 430 },
    title: "Average Precision on 2026-08-19 test panel",
    categories: ["Logistic Regression", "Random Forest", "XGBoost"],
    series: [
      { name: "Historical CVSS + age", values: [0.002086, 0.000253, 0.000269], fill: C.blue },
      { name: "With EPSS", values: [0.007346, 0.000483, 0.000991], fill: C.teal },
    ],
    barOptions: { direction: "column", grouping: "clustered", gapWidth: 70 },
    legend: { position: "bottom", overlay: false, textStyle: { typeface: FONT, fontSize: 12, fill: C.text } },
    hasLegend: true,
    yAxis: { min: 0, max: 0.01, majorUnit: 0.002, numberFormatCode: "0.000", title: { text: "Average Precision", textStyle: { typeface: FONT, fontSize: 12, fill: C.muted } }, textStyle: { typeface: FONT, fontSize: 11, fill: C.muted }, majorGridlines: { style: "solid", fill: C.line, width: 1 } },
    xAxis: { textStyle: { typeface: FONT, fontSize: 11, fill: C.muted }, line: { style: "solid", fill: C.line, width: 1 } },
  });
  addText(slide, "Test set", 884, 220, 280, 30, { fontSize: "14pt", bold: true, color: C.teal });
  addText(slide, "206,587 rows\n19 positives\nAug 2026", 884, 260, 285, 120, { fontSize: "23pt", color: C.navy });
  addText(slide, "The gain is promising but provisional: one small held-out period cannot establish stable generalization.",
    884, 430, 290, 112, { fontSize: "16pt", color: C.muted });
  notes(slide, "Time-forward split: train through Aug 2025, validate Feb 2026, test Aug 2026. AP without/with EPSS: Logistic Regression .002086/.007346; Random Forest .000253/.000483; XGBoost .000269/.000991. The final test has 19 positives. Models use reconstructed CVSS, not current enrichment fields. See outputs/tables/model_results.csv.");
}

// 10. Hypotheses
{
  const slide = startSlide(presentation, 10, "Stage 3  |  Inform the decision", "Hypothesis assessment");
  const rows = [
    ["H1", "Supported, period caveat", "Pooled EPSS is higher for positives; date-level evidence varies."],
    ["H2", "Inconclusive", "EPSS captured more pooled positives, but adjusted tests did not confirm a stable gain."],
    ["H3", "Inconclusive", "Combined tied EPSS for pooled Recall@1,000; adjusted evidence does not establish a gain."],
    ["H4", "Supported provisionally", "EPSS improved AP on the held-out Aug 2026 period (19 positives)."],
    ["H5", "Inconclusive", "The leading ranking changes by date; newest EPSS version has one period."],
  ];
  const y0 = 190;
  rows.forEach(([id, status, summary], i) => {
    const y = y0 + i * 90;
    addText(slide, id, 72, y, 72, 32, { fontSize: "20pt", bold: true, color: C.teal });
    addText(slide, status, 164, y, 285, 42, { fontSize: "17pt", bold: true, color: C.navy });
    addText(slide, summary, 470, y, 708, 56, { fontSize: "15pt", color: C.text });
    if (i < rows.length - 1) addRect(slide, 72, y + 66, 1110, 1, C.line, "none");
  });
  notes(slide, "Statuses follow docs/hypothesis_assessment.md. H2/H3 p-values are adjusted with Holm's method across dates and K values. Pooled rows repeat some CVEs, so the H1 pooled rank test remains exploratory.");
}

// 11. Recommendation
{
  const slide = startSlide(presentation, 11, "Stage 3  |  Inform the decision", "Use EPSS in a shadow-mode pilot");
  addText(slide, "Keep CVSS visible. Add EPSS as an advisory signal while analysts consider asset criticality, exposure, controls, and patch feasibility.",
    72, 186, 1090, 96, { fontSize: "22pt", color: C.navy }, "recommendation");
  const phases = [
    ["1  Data review", "Join CVEs to assets; report freshness and missingness."],
    ["2  Shadow evaluation", "Compare lists without changing patch decisions; record overrides."],
    ["3  Controlled pilot", "Use analyst approval; track KEV coverage, time-to-patch, and workload."],
  ];
  phases.forEach(([title, detail], i) => {
    const y = 326 + i * 76;
    addText(slide, title, 72, y, 230, 34, { fontSize: "16pt", bold: true, color: i === 2 ? C.orange : C.teal });
    addText(slide, detail, 312, y, 780, 50, { fontSize: "15pt", color: C.text });
  });
  addRect(slide, 72, 571, 1136, 1, C.line, "none");
  addText(slide, "Limits: 109 positives; CVSS history is incomplete and other NVD enrichment is current; KEV date is not attack time; results are not causal. AI assistance was used and is disclosed in the project documents.",
    72, 592, 1110, 50, { fontSize: "12pt", color: C.muted });
  notes(slide, "Recommendation and roadmap are in docs/recommendations.md. This analysis does not prove that EPSS causes improved security outcomes and does not support automatic patching. AI assistance was used; follow course and university disclosure requirements. Sources: https://nvd.nist.gov/vuln/data-feeds; https://www.first.org/epss/; https://www.cisa.gov/known-exploited-vulnerabilities-catalog.");
}

await fs.mkdir(outDir, { recursive: true });
for (const [index, slide] of presentation.slides.items.entries()) {
  const name = `slide-${String(index + 1).padStart(2, "0")}.png`;
  await writeBlob(path.join(outDir, name), await presentation.export({ slide, format: "png", scale: 1 }));
}
const montage = await presentation.export({ format: "webp", montage: true });
await writeBlob(path.join(outDir, "deck-montage.webp"), montage);
await (await PresentationFile.exportPptx(presentation)).save(candidatePath);

const { finalizePresentation } = await import(pathToFileURL(path.join(SKILL_DIR, "container_tools/artifact_tool_utils.mjs")).href);
const stagingDir = path.join(here, "finalizer");
await fs.mkdir(stagingDir, { recursive: true });
await fs.mkdir(path.dirname(finalPath), { recursive: true });
const result = await finalizePresentation({
  explicitTotalSlideCount: 11,
  requiredNativeChartOwnerSlides: [7, 8, 9],
  workspaceDir,
  candidatePath,
  finalPath,
  pythonExecutable: "C:\\Program Files\\WindowsApps\\OpenAI.CodexPrimaryRuntime.v26-1117-835-0_26.1117.835.0_x64__3k8sg7r9htsxt\\dependencies\\python\\python.exe",
  integrityValidatorPath: path.join(SKILL_DIR, "container_tools/inspect_presentation_package_integrity.py"),
  layoutValidatorPath: path.join(SKILL_DIR, "container_tools/inspect_presentation_layout_geometry.py"),
  layoutArgs: ["--expected-slide-size-emu", "12192000,6858000", "--validate-heading-fit"],
  fontPolicy: { basis: "design", families: [FONT] },
  verifyArtifactToolImport: true,
  materializeLiteralChartWorkbooks: true,
  receiptPath: path.join(stagingDir, "slides.validation.json"),
});
console.log(JSON.stringify({ finalPath, result }, null, 2));








