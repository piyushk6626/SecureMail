import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Presentation, PresentationFile } from "@oai/artifact-tool";

const workspaceDir = "/home/shivam/Projects/SecureMail/SecureMail";
const SKILL_DIR = "/home/shivam/.codex/plugins/cache/openai-primary-runtime/presentations/26.904.11930/skills/presentations";
const TMP_DIR = path.join(workspaceDir, ".codex-build/securemail-architecture");
const FINAL_PPTX = path.join(workspaceDir, "out/presentations/securemail_technical_approach_components.pptx");
const RUNTIME_PYTHON = "/home/shivam/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3";
process.env.RUNTIME_NODE_MODULES = "/home/shivam/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules";

const { finalizePresentation } = await import(
  pathToFileURL(path.join(SKILL_DIR, "container_tools/artifact_tool_utils.mjs")).href,
);

await fs.mkdir(TMP_DIR, { recursive: true });
await fs.mkdir(path.dirname(FINAL_PPTX), { recursive: true });

const presentation = Presentation.create({
  slideSize: { width: 1280, height: 720 },
});
const slide = presentation.slides.add();
slide.background.fill = "#F4F7FA";

const fontFamily = "IBM Plex Sans";
const palette = {
  ink: "#17324D",
  muted: "#5A6F82",
  line: "#687D90",
  canvas: "#F4F7FA",
  white: "#FFFFFF",
  entryFill: "#F8FAFC",
  entryLine: "#C9D5DF",
  coreFill: "#ECF8FC",
  coreLine: "#8FD2E7",
  coreAccent: "#138BB3",
  infraFill: "#F7F3FC",
  infraLine: "#CDBDEA",
  infraAccent: "#7758B7",
  green: "#2D8B72",
};

function addText(name, text, position, style = {}) {
  const shape = slide.shapes.add({
    geometry: "textbox",
    name,
    position,
    fill: "none",
    line: { style: "solid", fill: "none", width: 0 },
  });
  shape.text = text;
  shape.text.style = {
    typeface: fontFamily,
    fontSize: style.fontSize ?? 20,
    bold: style.bold ?? false,
    color: style.color ?? palette.ink,
    alignment: style.alignment ?? "left",
    verticalAlignment: style.verticalAlignment ?? "middle",
    autoFit: "shrinkText",
    wrap: "square",
    insets: style.insets ?? { top: 0, right: 0, bottom: 0, left: 0 },
  };
  return shape;
}

function addGroup(name, label, position, fill, line, accent) {
  const box = slide.shapes.add({
    geometry: "roundRect",
    name,
    position,
    fill,
    line: { style: "solid", fill: line, width: 1.5 },
    borderRadius: 18,
  });
  box.shadow = "shadow-none";
  const strip = slide.shapes.add({
    geometry: "rect",
    name: `${name}-accent`,
    position: { left: position.left + 18, top: position.top + 42, width: 42, height: 4 },
    fill: accent,
    line: { style: "solid", fill: accent, width: 0 },
    borderRadius: 2,
  });
  const title = addText(`${name}-label`, label, {
    left: position.left + 18,
    top: position.top + 10,
    width: position.width - 36,
    height: 28,
  }, { fontSize: 18, bold: true, color: accent });
  return { box, strip, title };
}

function addNode(name, title, description, position, accent, fill = palette.white, textSizes = {}) {
  const box = slide.shapes.add({
    geometry: "roundRect",
    name,
    position,
    fill,
    line: { style: "solid", fill: accent, width: 1.5 },
    borderRadius: 12,
    shadow: "shadow-sm",
  });
  const marker = slide.shapes.add({
    geometry: "roundRect",
    name: `${name}-marker`,
    position: { left: position.left + 12, top: position.top + 14, width: 6, height: position.height - 28 },
    fill: accent,
    line: { style: "solid", fill: accent, width: 0 },
    borderRadius: 3,
  });
  const titleShape = addText(`${name}-title`, title, {
    left: position.left + 28,
    top: position.top + 10,
    width: position.width - 40,
    height: 27,
  }, { fontSize: textSizes.title ?? 21, bold: true, color: palette.ink });
  const descShape = addText(`${name}-description`, description, {
    left: position.left + 28,
    top: position.top + 38,
    width: position.width - 40,
    height: position.height - 46,
  }, { fontSize: textSizes.description ?? 17, color: palette.muted, verticalAlignment: "top" });
  return { box, marker, titleShape, descShape };
}

function connect(source, target, options = {}) {
  const connector = slide.shapes.connect(source.box, target.box, {
    kind: options.kind ?? "elbow",
    fromSide: options.fromSide,
    toSide: options.toSide,
    line: {
      style: options.dashed ? "dashed" : "solid",
      fill: options.color ?? palette.line,
      width: options.width ?? 1.7,
    },
    head: { type: "none" },
    tail: options.noHead ? { type: "none" } : { type: "triangle", width: "sm", length: "sm" },
  });
  connector.bringToFront();
  return connector;
}

function label(name, text, position, color = palette.muted) {
  const bg = slide.shapes.add({
    geometry: "roundRect",
    name: `${name}-bg`,
    position,
    fill: palette.canvas,
    line: { style: "solid", fill: palette.canvas, width: 0 },
    borderRadius: 4,
  });
  const t = addText(name, text, position, {
    fontSize: 14,
    bold: true,
    color,
    alignment: "center",
  });
  bg.bringToFront();
  t.bringToFront();
}

addText("title", "SecureMail component architecture", { left: 52, top: 28, width: 1176, height: 48 }, {
  fontSize: 42,
  bold: true,
  color: palette.ink,
});
addText("subtitle", "Current packages, runtime components and dependency boundaries", { left: 54, top: 77, width: 1172, height: 26 }, {
  fontSize: 20,
  color: palette.muted,
});
slide.shapes.add({
  geometry: "rect",
  name: "title-rule",
  position: { left: 54, top: 112, width: 1172, height: 3 },
  fill: palette.coreAccent,
  line: { style: "solid", fill: palette.coreAccent, width: 0 },
});

const system = slide.shapes.add({
  geometry: "roundRect",
  name: "securemail-workstation",
  position: { left: 48, top: 132, width: 1184, height: 532 },
  fill: palette.white,
  line: { style: "solid", fill: "#A9B8C5", width: 1.8 },
  borderRadius: 20,
  shadow: "shadow-sm",
});
addText("system-label", "SECUREMAIL WORKSTATION", { left: 70, top: 141, width: 260, height: 24 }, {
  fontSize: 14,
  bold: true,
  color: palette.muted,
});

const entryGroup = addGroup(
  "entry-group",
  "ENTRY POINTS",
  { left: 70, top: 174, width: 258, height: 462 },
  palette.entryFill,
  palette.entryLine,
  "#59758C",
);
const coreGroup = addGroup(
  "core-group",
  "CORE LOGIC AND CONTRACTS",
  { left: 348, top: 174, width: 482, height: 462 },
  palette.coreFill,
  palette.coreLine,
  palette.coreAccent,
);
const infraGroup = addGroup(
  "infra-group",
  "ADAPTERS AND LOCAL RUNTIME",
  { left: 850, top: 174, width: 360, height: 462 },
  palette.infraFill,
  palette.infraLine,
  palette.infraAccent,
);

const frontend = addNode(
  "frontend-node",
  "frontend/",
  "React dashboard",
  { left: 91, top: 229, width: 216, height: 76 },
  "#59758C",
);
const api = addNode(
  "api-node",
  "api/",
  "Typer CLI and FastAPI routers",
  { left: 91, top: 346, width: 216, height: 92 },
  "#59758C",
);
const worker = addNode(
  "worker-node",
  "worker.py",
  "Local job processor",
  { left: 91, top: 507, width: 216, height: 76 },
  "#59758C",
);

const bootstrap = addNode(
  "bootstrap-node",
  "bootstrap.py",
  "Composition root",
  { left: 372, top: 226, width: 434, height: 70 },
  palette.green,
);
const application = addNode(
  "application-node",
  "application/",
  "Use cases and normalization",
  { left: 372, top: 354, width: 184, height: 96 },
  palette.coreAccent,
);
const domain = addNode(
  "domain-node",
  "domain/",
  "Evidence models, policy, scoring, report schemas, jobs and ML",
  { left: 604, top: 342, width: 202, height: 126 },
  palette.coreAccent,
);
const ports = addNode(
  "ports-node",
  "ports/",
  "Analyzer, storage, report and ML contracts",
  { left: 604, top: 521, width: 202, height: 82 },
  palette.coreAccent,
);

const adapters = addNode(
  "adapters-node",
  "adapters/",
  "Analyzer runners, filesystem persistence, reporting, PKI and reference data, advisory ML",
  { left: 875, top: 226, width: 310, height: 142 },
  palette.infraAccent,
);
const analyzers = addNode(
  "analyzers-node",
  "Zeek + TShark",
  "Offline Docker analyzers",
  { left: 875, top: 450, width: 145, height: 112 },
  palette.infraAccent,
  palette.white,
  { title: 18, description: 16 },
);
const filesystem = addNode(
  "filesystem-node",
  "Local filesystem",
  "Jobs, catalog, artifacts and ML history",
  { left: 1040, top: 450, width: 145, height: 112 },
  palette.infraAccent,
  palette.white,
  { title: 17, description: 16 },
);

connect(frontend, api, { kind: "straight", fromSide: "bottom", toSide: "top" });
connect(api, worker, { kind: "straight", fromSide: "bottom", toSide: "top", dashed: true, color: "#7F91A2" });
connect(api, application, { kind: "elbow", fromSide: "right", toSide: "left" });
connect(worker, application, { kind: "elbow", fromSide: "right", toSide: "left" });
connect(application, domain, { kind: "straight", fromSide: "right", toSide: "left" });
connect(application, ports, { kind: "elbow", fromSide: "bottom", toSide: "left" });
connect(adapters, ports, { kind: "elbow", fromSide: "left", toSide: "right", color: palette.infraAccent });
connect(bootstrap, api, { kind: "elbow", fromSide: "left", toSide: "right", dashed: true, color: palette.green });
connect(bootstrap, application, { kind: "straight", fromSide: "bottom", toSide: "top", dashed: true, color: palette.green });
connect(bootstrap, adapters, { kind: "straight", fromSide: "right", toSide: "left", dashed: true, color: palette.green });
connect(adapters, analyzers, { kind: "elbow", fromSide: "bottom", toSide: "top", color: palette.infraAccent });
connect(adapters, filesystem, { kind: "elbow", fromSide: "bottom", toSide: "top", color: palette.infraAccent });

label("label-http", "HTTP API", { left: 177, top: 310, width: 72, height: 19 });
label("label-spawns", "spawns", { left: 176, top: 461, width: 66, height: 19 });
label("label-api-calls", "calls", { left: 319, top: 371, width: 52, height: 19 });
label("label-worker-calls", "calls", { left: 319, top: 523, width: 52, height: 19 });
label("label-uses", "uses", { left: 558, top: 382, width: 42, height: 19 });
label("label-depends", "depends on", { left: 508, top: 512, width: 85, height: 19 });
label("label-implements", "implements", { left: 790, top: 477, width: 84, height: 19 }, palette.infraAccent);
label("label-wires", "wires", { left: 559, top: 306, width: 48, height: 19 }, palette.green);
label("label-launches", "launches", { left: 895, top: 407, width: 70, height: 19 }, palette.infraAccent);
label("label-storage", "reads and writes", { left: 1031, top: 407, width: 108, height: 19 }, palette.infraAccent);

system.sendToBack();

for (const node of [frontend, api, worker, bootstrap, application, domain, ports, adapters, analyzers, filesystem]) {
  node.box.bringToFront();
  node.marker.bringToFront();
  node.titleShape.bringToFront();
  node.descShape.bringToFront();
}

slide.speakerNotes.textFrame.setText(
  [
    "Purpose: component and package view. Arrows show calls, dependencies, implementation, composition, or runtime lifecycle. They do not represent the capture-processing sequence.",
    "Sources: docs/development/repository-map.md; docs/architecture/clean-architecture.md; docs/architecture/runtime-topology.md; docs/architecture/frontend-data-flow.md; src/securemail/bootstrap.py; src/securemail/worker.py.",
    "Verified against the repository on 2026-09-07.",
  ].join("\n"),
);

const preview = await presentation.export({ slide, format: "png", scale: 1.5 });
await fs.writeFile(path.join(TMP_DIR, "slide-1-draft.png"), new Uint8Array(await preview.arrayBuffer()));
const layout = await slide.export({ format: "layout" });
await fs.writeFile(path.join(TMP_DIR, "slide-1.layout.json"), await layout.text());

const stagingDir = path.join(TMP_DIR, "finalizer");
await fs.mkdir(stagingDir, { recursive: true });
const candidatePath = path.join(stagingDir, "candidate.pptx");
await (await PresentationFile.exportPptx(presentation)).save(candidatePath);

const requirements = {
  explicitTotalSlideCount: 1,
  requiredNativeTableOwnerSlides: [],
  requiredNativeChartOwnerSlides: [],
};
const result = await finalizePresentation({
  ...requirements,
  workspaceDir,
  candidatePath,
  finalPath: FINAL_PPTX,
  pythonExecutable: RUNTIME_PYTHON,
  integrityValidatorPath: path.join(SKILL_DIR, "container_tools/inspect_presentation_package_integrity.py"),
  layoutValidatorPath: path.join(SKILL_DIR, "container_tools/inspect_presentation_layout_geometry.py"),
  layoutArgs: [
    "--expected-slide-size-emu", "12192000,6858000",
    "--validate-bullet-geometry",
    "--validate-heading-fit",
  ],
  fontPolicy: { basis: "design", families: [fontFamily] },
  verifyArtifactToolImport: true,
  receiptPath: path.join(stagingDir, "securemail_technical_approach_components_delivered_v2.validation.json"),
});

const finalPreview = await presentation.export({ slide, format: "png", scale: 2 });
await fs.writeFile(path.join(TMP_DIR, "slide-1-final.png"), new Uint8Array(await finalPreview.arrayBuffer()));
console.log(JSON.stringify({ finalPath: FINAL_PPTX, result }, null, 2));
