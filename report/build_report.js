// Builds the OmniGuard midterm report as a .docx. Figures live in ./figures.
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  ImageRun, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
  PageBreak, Footer, PageNumber, LevelFormat, TableOfContents,
} = require("docx");

const FIG = (f) => fs.readFileSync(path.join(__dirname, "figures", f));
const ACCENT = "6E56CF";
const INK = "1F2328";
const MUTE = "57606A";

// ---- small helpers -------------------------------------------------------
const h1 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 280, after: 120 }, children: [new TextRun({ text, color: INK })] });
const h2 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 80 }, children: [new TextRun({ text, color: INK })] });
const p = (text, opts = {}) => new Paragraph({ spacing: { after: 120, line: 276 }, alignment: AlignmentType.JUSTIFIED, children: [new TextRun({ text, ...opts })] });
const bullet = (text) => new Paragraph({ numbering: { reference: "bl", level: 0 }, spacing: { after: 60, line: 276 }, children: [new TextRun(text)] });

function figure(file, num, caption, dims) {
  const { w = 580, h = 435 } = dims || {};
  return [
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 120, after: 40 },
      children: [new ImageRun({ type: "jpg", data: FIG(file), transformation: { width: w, height: h } })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 180 },
      children: [
        new TextRun({ text: `Figure ${num}. `, bold: true, size: 20, color: ACCENT }),
        new TextRun({ text: caption, italics: true, size: 20, color: MUTE }),
      ],
    }),
  ];
}

// ---- team + status tables ------------------------------------------------
function cell(text, { bold = false, head = false, w } = {}) {
  return new TableCell({
    width: { size: w, type: WidthType.DXA },
    shading: head ? { type: ShadingType.CLEAR, fill: "F3F0FF", color: "auto" } : undefined,
    margins: { top: 60, bottom: 60, left: 110, right: 110 },
    children: [new Paragraph({ children: [new TextRun({ text, bold: bold || head, size: 20, color: head ? ACCENT : INK })] })],
  });
}
function table(rows, widths) {
  return new Table({
    columnWidths: widths,
    width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    borders: {
      top: { style: BorderStyle.SINGLE, size: 2, color: "D8D5E0" },
      bottom: { style: BorderStyle.SINGLE, size: 2, color: "D8D5E0" },
      left: { style: BorderStyle.SINGLE, size: 2, color: "D8D5E0" },
      right: { style: BorderStyle.SINGLE, size: 2, color: "D8D5E0" },
      insideHorizontal: { style: BorderStyle.SINGLE, size: 2, color: "E6E4EC" },
      insideVertical: { style: BorderStyle.SINGLE, size: 2, color: "E6E4EC" },
    },
    rows: rows.map((r, i) =>
      new TableRow({ tableHeader: i === 0, children: r.map((c) => cell(c.t, { head: i === 0, bold: c.b, w: c.w })) })
    ),
  });
}

const teamRows = [
  [{ t: "Member", w: 1800 }, { t: "Subsystem", w: 2400 }, { t: "Responsibility", w: 5400 }],
  [{ t: "Aayush Maharjan", b: true, w: 1800 }, { t: "Unified Dashboard & Platform Integration", w: 2400 }, { t: "React SOC dashboard, the FastAPI core and shared alert contract, live WebSocket feed, data stores, and the AI analyst integration — the seams that make every engine connect.", w: 5400 }],
  [{ t: "Khoi", b: true, w: 1800 }, { t: "SpectraC2", w: 2400 }, { t: "Encrypted command-and-control beacon detection using FFT and LSTM over Zeek/Suricata network telemetry.", w: 5400 }],
  [{ t: "Rahim", b: true, w: 1800 }, { t: "VerifyEye", w: 2400 }, { t: "Real-time phishing detection: DOM analysis, brand/logo recognition, and the browser-side interception layer.", w: 5400 }],
  [{ t: "Abu (Siddik)", b: true, w: 1800 }, { t: "Graph & Triage", w: 2400 }, { t: "Neo4j entity-graph schema and traversal for incident correlation, and the local LLM triage design.", w: 5400 }],
];

const statusRows = [
  [{ t: "Capability", w: 4200 }, { t: "Status", w: 1800 }, { t: "Notes", w: 3600 }],
  [{ t: "Core API, alert contract, storage", w: 4200 }, { t: "Complete", w: 1800 }, { t: "FastAPI, MongoDB + Neo4j, end-to-end", w: 3600 }],
  [{ t: "React dashboard + live WebSocket feed", w: 4200 }, { t: "Complete", w: 1800 }, { t: "Alerts, stats, attack graph, status", w: 3600 }],
  [{ t: "VerifyEye phishing detection (MVP)", w: 4200 }, { t: "Complete", w: 1800 }, { t: "Detect, freeze, OAuth-popup + network block", w: 3600 }],
  [{ t: "AI triage (local LLM)", w: 4200 }, { t: "Complete", w: 1800 }, { t: "Summary + next steps on the dashboard", w: 3600 }],
  [{ t: "Live system-status health checks", w: 4200 }, { t: "Complete", w: 1800 }, { t: "Pings Mongo, Neo4j, Ollama every 10s", w: 3600 }],
  [{ t: "SpectraC2 beacon engine", w: 4200 }, { t: "In progress", w: 1800 }, { t: "Connects to the alert contract", w: 3600 }],
  [{ t: "Confidence scoring + visual detection tier", w: 4200 }, { t: "Planned", w: 1800 }, { t: "Phase-two hardening", w: 3600 }],
  [{ t: "Analyst chatbot over alerts", w: 4200 }, { t: "Planned", w: 1800 }, { t: "Natural-language Q&A, reuses the AI layer", w: 3600 }],
];

// ---- document ------------------------------------------------------------
const doc = new Document({
  creator: "OmniGuard Team",
  title: "OmniGuard SOC — Midterm Report",
  numbering: {
    config: [{
      reference: "bl",
      levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 420, hanging: 220 } } } }],
    }],
  },
  styles: {
    default: { document: { run: { font: "Calibri", size: 22, color: INK } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 30, bold: true, color: INK }, paragraph: { spacing: { before: 280, after: 120 } } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 25, bold: true, color: ACCENT }, paragraph: { spacing: { before: 200, after: 80 } } },
    ],
  },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } } },
    footers: {
      default: new Footer({
        children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: "OmniGuard SOC — Midterm Report          ", size: 16, color: MUTE }),
            new TextRun({ children: ["Page ", PageNumber.CURRENT], size: 16, color: MUTE })],
        })],
      }),
    },
    children: [
      // ===== COVER =====
      new Paragraph({ spacing: { before: 2600 }, children: [] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [new TextRun({ text: "OmniGuard", bold: true, size: 72, color: ACCENT })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 }, children: [new TextRun({ text: "A Unified Security Operations Center", size: 32, color: INK })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 600 }, children: [new TextRun({ text: "Phishing detection · C2 beacon analytics · graph correlation · local AI triage", size: 20, italics: true, color: MUTE })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 }, children: [new TextRun({ text: "Senior Capstone — Midterm Report", bold: true, size: 26, color: INK })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 600 }, children: [new TextRun({ text: "San Francisco Bay University", size: 22, color: MUTE })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 20 }, children: [new TextRun({ text: "Team: Aayush Maharjan · Khoi · Rahim · Abu (Siddik)", size: 20, color: INK })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 20 }, children: [new TextRun({ text: "Report author: Aayush Maharjan — Unified Dashboard & Platform Integration", size: 20, color: MUTE })] }),
      new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Target completion: December 2026", size: 20, color: MUTE })] }),
      new Paragraph({ children: [new PageBreak()] }),

      // ===== TOC =====
      h1("Contents"),
      new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }),
      new Paragraph({ children: [new PageBreak()] }),

      // ===== 1. INTRODUCTION =====
      h1("1. Introduction"),
      p("OmniGuard is a unified Security Operations Center (SOC) platform built as our senior capstone project. A modern organization is attacked on several fronts at once — employees are lured to fake login pages, compromised machines beacon quietly to command-and-control servers, and the evidence of a single intrusion is scattered across unrelated tools. Analysts are left stitching that story together by hand while alerts pile up."),
      p("OmniGuard addresses this by bringing three detection capabilities and a correlation layer under one dashboard: real-time phishing detection (VerifyEye), encrypted command-and-control beacon analytics (SpectraC2), and a graph that links the entities those engines report. On top of that sits a local AI analyst that reads the alerts and briefs the human operator. A defining constraint of the project is that the entire system runs on-premises — no security data leaves the machine — which is both a privacy guarantee and a practical requirement for a live demonstration."),
      p("This midterm report describes the problem, the team, the system architecture, and the progress made so far. The platform core, the dashboard, the VerifyEye phishing subsystem, and the AI triage layer are working end-to-end; the remaining engines and hardening are in progress. The report focuses on our own implementation rather than on the underlying frameworks."),

      // ===== 2. OBJECTIVES =====
      h1("2. Project Objectives and Scope"),
      p("The project has four objectives:"),
      bullet("Detect credential-phishing pages in the browser in real time and stop the user before credentials are submitted."),
      bullet("Detect encrypted command-and-control beacons from network telemetry using signal-analysis and machine-learning techniques."),
      bullet("Correlate the entities these engines report — hosts, users, domains, URLs, processes — into a graph so a multi-stage incident can be seen as one picture."),
      bullet("Present everything through a single live dashboard, and add a local AI layer that summarizes the situation and recommends next steps."),
      p("The scope is deliberately on-premises and self-contained. No component depends on a cloud service: the databases, the model, and the dashboard all run locally. This keeps security telemetry inside the organization and makes the system demonstrable without network access."),

      // ===== 3. TEAM =====
      h1("3. Team and Responsibilities"),
      p("The team of four divides the work by subsystem, with one member owning the integration seams that join them together."),
      table(teamRows, [1800, 2400, 5400]),
      new Paragraph({ spacing: { after: 120 }, children: [] }),
      p("This report is authored by Aayush Maharjan, who owns the unified dashboard and platform integration. Because integration touches every subsystem, the work described here spans the shared alert contract, the dashboard, the data layer, and the AI integration that other engines feed into."),

      // ===== 4. ARCHITECTURE =====
      h1("4. System Architecture"),
      p("OmniGuard follows a producer–core–consumer design. Detection engines are producers: each one independently analyzes its own data source and emits a structured alert. The core is a single FastAPI service that defines the alert contract, stores every alert, and fans it out. The dashboard and the AI layer are consumers that read from the core. Figure 1 shows the overall shape."),
      ...figure("05-architecture.jpg", 1, "OmniGuard system architecture — detection engines produce alerts to the core API, which persists them to MongoDB and Neo4j and streams them live to the React dashboard; the local Ollama model provides triage."),
      h2("4.1 The alert contract"),
      p("Every engine speaks to the core through one agreed schema, the Alert contract, defined once as a pair of Pydantic models. Fixing this contract before any engine emitted data is what let a new engine connect on its first attempt with no changes on either side. New optional fields can be added freely; renames and removals are not allowed, so producers never break the core."),
      h2("4.2 Two databases, two jobs"),
      p("The core writes each alert to both MongoDB and Neo4j, which play different roles. MongoDB is the durable log — the full alert exactly as received, plus large payloads such as screenshots and raw flow data. Neo4j holds only entities and the relationships between them. The split is deliberate: large property blobs on graph nodes slow traversal, and fast traversal is the entire point of the graph. Keeping heavy data in Mongo and relationships in Neo4j lets each database do what it is good at."),
      h2("4.3 Everything local"),
      p("The team chose local installations of MongoDB, Neo4j, and the Ollama language model over hosted alternatives. The project's headline claim is zero cloud egress and on-premises data sovereignty, so storing security alerts in a cloud database would undercut that thesis. It also removes any network dependency from the live demonstration."),

      // ===== 5. IMPLEMENTATION =====
      h1("5. Implementation and Progress"),
      p("This section describes what has been built, organized by subsystem, with the integration and dashboard work — the author's own contribution — covered in the most depth."),

      h2("5.1 The unified dashboard"),
      p("The dashboard is a React single-page application that consumes the core API. It fetches the existing alerts on load and then subscribes to a WebSocket feed, so new alerts appear instantly without a refresh. Figure 2 shows the alerts view: a live, severity-tagged list of every detection, filterable by severity and by the engine that produced it."),
      ...figure("01-alerts-page.jpg", 2, "The live alerts view. Each phishing detection from VerifyEye arrives over the WebSocket feed and is listed newest-first with its severity, affected host, and domain."),
      p("The overview page (Figure 3) summarizes the current state: totals by severity with short trend sparklines, a threat-activity chart, and the two panels discussed below — the AI analyst and a live system-status readout. The left sidebar's status panel is not hard-coded; it polls a dedicated health endpoint every ten seconds that pings MongoDB, Neo4j, and the Ollama model, so each row reflects the real state of that service."),
      ...figure("02-dashboard-overview.jpg", 3, "The dashboard overview — severity totals with trends, the AI analyst panel, and the live system-status panel in the sidebar (all services reporting healthy)."),

      h2("5.2 VerifyEye — real-time phishing detection"),
      p("VerifyEye is delivered as a Chrome extension so that detection happens in the browser, at the moment a user lands on a page, rather than after the fact. Its logic is two-part. First it looks for credential fields — password and email or username inputs. Finding those alone is not enough, because every legitimate login page has them; the decisive test is brand impersonation. The extension keeps a locally cached list of protected brands (each with keywords and its genuine domains, served by the core and refreshed in the background). A page is treated as phishing when it presents credential fields, its text matches a known brand, and the page is not actually on that brand's real domain."),
      p("When that condition is met the extension freezes the page: it disables the credential fields, blocks form submission at the earliest point in the browser's event handling, and injects a warning banner. Detection also survives modern evasion: a mutation observer re-runs the check when a login form is injected late by JavaScript (as single-page apps do), and the extension re-arms itself when a single-page app changes the URL without reloading."),
      p("Figure 4 shows the extension in action on a page impersonating Claude: the credential fields are outlined in red and disabled, and a warning banner appears across the top. The freeze is deliberately surgical — it locks the credential fields and the submit action but leaves the page's other controls live, for the reason given next."),
      ...figure("06-verifyeye-claude-frozen.jpg", 4, "VerifyEye freezing a phishing page that impersonates Claude. The email and password fields are outlined and disabled and a warning banner is shown; the OAuth buttons are intentionally left active so a follow-on popup attack can also be caught.", { w: 610, h: 299 }),
      p("Two further techniques harden the response. The extension also catches the fake-OAuth-popup trick — where a page offers “Continue with Google” and opens a counterfeit provider login in a popup window. Because the surgical freeze keeps that button usable, the user can trigger the popup, and the popup is itself a brand-impersonating page on the wrong domain, so VerifyEye freezes it the instant it opens (Figures 5 and 6)."),
      ...figure("07-verifyeye-google-popup.jpg", 5, "The counterfeit “Continue with Google” popup, frozen as soon as it opens. Although it is a separate window on its own address, VerifyEye detects that it impersonates Google away from google.com and disables it.", { w: 610, h: 299 }),
      ...figure("08-verifyeye-apple-popup.jpg", 6, "The same defense against a counterfeit “Sign in with Apple” popup — the extension recognizes the Apple impersonation and freezes the window.", { w: 610, h: 299 }),
      p("Detection is driven by a configurable brand list served by the core, so coverage extends across many targets. Figure 7 shows the same protection on a page impersonating Netflix. As a final layer, when a phishing page is confirmed the extension installs a network-level block against the credential-harvesting host, so even a script that bypasses the form cannot exfiltrate. Every confirmed detection is reported to the core as an alert, which is how the entries in Figure 2 arrived."),
      ...figure("09-verifyeye-netflix.jpg", 7, "Brand coverage — a phishing page impersonating Netflix, detected and frozen. VerifyEye protects a configurable set of brands (Google, Apple, Netflix, Microsoft, GitHub, TikTok, Amazon and more) defined centrally by the core.", { w: 610, h: 299 }),

      h2("5.3 AI analyst — local triage"),
      p("The AI layer answers a practical question: with dozens of alerts on screen, what is actually going on and what should the analyst do first? A dedicated endpoint gathers the most recent alerts, compresses each to its essential fields, and asks a locally-run language model (Ollama, llama3.2:3b) for a short situation summary followed by a prioritized list of next steps. The result is rendered in the “AI analyst” panel on the dashboard. Figure 8 shows a generated briefing."),
      ...figure("03-ai-briefing.jpg", 8, "The AI analyst panel. The locally-run model has read the current alerts and produced a situation summary and prioritized next steps — entirely on-device, with no data leaving the machine."),
      p("Because the model runs locally, the feature upholds the project's zero-egress principle: the alert data is never sent to an external API. The same local layer is the foundation for a planned natural-language chatbot that will let analysts ask questions about the alerts directly."),

      h2("5.4 Graph correlation"),
      p("The core writes every alert's entities into Neo4j as nodes and relationships. The dashboard renders this as an interactive attack graph (Figure 9), color-coded by entity type — hosts, users, processes, IPs, domains, URLs, and MITRE ATT&CK techniques. The graph is designed as an investigation tool rather than a wall display: its default correlation view surfaces entities touched by more than one host or flagged by more than one engine, which is precisely the structure a flat list of alerts cannot show."),
      ...figure("04-attack-graph.jpg", 9, "The attack graph — entities reported by the detection engines, correlated in Neo4j and rendered as a force-directed graph with a type legend. The default view emphasizes entities that link multiple hosts or engines."),

      h2("5.5 SpectraC2 — beacon analytics"),
      p("SpectraC2 detects encrypted command-and-control beacons from network telemetry. Malware that beacons home does so at a characteristic, often periodic, interval; the engine applies frequency analysis and a learned model over Zeek/Suricata flow data to recover that signal and flag the beaconing host. Because it emits alerts through the same shared contract, its detections appear in the dashboard and graph alongside VerifyEye's. This subsystem is in active development."),

      // ===== 6. CHALLENGES =====
      h1("6. Challenges and Engineering Decisions"),
      p("Several problems shaped the implementation and are worth recording."),
      bullet("Dynamically-injected login forms. A one-time scan at page load misses forms that single-page applications inject later. The fix was continuous detection via a mutation observer that re-runs the check and then disconnects once it has acted, avoiding an infinite loop as the freeze itself modifies the page."),
      bullet("Avoiding false positives on legitimate single sign-on. Many real sites show a “Continue with Google” button, which naively matches a brand keyword on a non-brand domain. This is exactly why detection is not a single boolean: brand mention alone must not trigger a block. It motivated a planned confidence-scoring model in which several weighted signals, not one keyword, decide."),
      bullet("Surgical page freezing. Disabling every control on a flagged page also disabled the legitimate OAuth buttons, which prevented the extension from catching the fake popup those buttons open. The freeze was narrowed to lock only the credential fields and the submit action while leaving other controls live, so the popup attack is still caught."),
      bullet("Ownership of integration seams. Because integration spans everyone's work, a recurring challenge has been keeping subsystem boundaries clear so effort is not duplicated. The team now favors written ownership agreements and demonstrates cross-cutting changes on separate branches rather than pushing into a teammate's work."),

      // ===== 7. STATUS =====
      h1("7. Current Status and Next Steps"),
      p("The platform's core path works end-to-end: a detection engine produces an alert, the core ingests and stores it in both databases, and the dashboard shows it live with graph correlation and an AI briefing. Table 2 summarizes where each capability stands."),
      new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text: "Table 2. Capability status at the midterm.", italics: true, size: 20, color: MUTE })] }),
      table(statusRows, [4200, 1800, 3600]),
      new Paragraph({ spacing: { after: 120 }, children: [] }),
      p("The next steps, in priority order, are: complete and integrate the SpectraC2 beacon engine; add a confidence-scoring model and a visual (image-based) detection tier to VerifyEye to resist text-based evasion; build the natural-language analyst chatbot on the existing local-AI layer; and finish dashboard features such as authentication and graph filtering ahead of the final demonstration in December 2026."),

      // ===== 8. CONCLUSION =====
      h1("8. Conclusion"),
      p("At the midterm, OmniGuard is a working, integrated SOC rather than a set of disconnected prototypes. The hardest architectural work — a shared alert contract, a thin core, a two-database storage split, and a live dashboard — is complete and proven by a real feature flowing through it end-to-end. VerifyEye detects and neutralizes phishing pages, including modern popup and single-page-app variants; the attack graph correlates what the engines report; and a local AI analyst turns raw alerts into guidance, all without any data leaving the machine. The remaining work is additive: more detection engines, stronger detection, and polish. The foundation they plug into already exists and works."),

      // ===== REFERENCES =====
      new Paragraph({ children: [new PageBreak()] }),
      h1("References"),
      ...[
        "FastAPI. “FastAPI framework documentation.” https://fastapi.tiangolo.com/",
        "MongoDB, Inc. “MongoDB Manual.” https://www.mongodb.com/docs/manual/",
        "Neo4j, Inc. “Neo4j Graph Database — Developer Documentation.” https://neo4j.com/docs/",
        "Meta Open Source. “React — A JavaScript library for building user interfaces.” https://react.dev/",
        "Ollama. “Run large language models locally.” https://ollama.com/",
        "Google. “Chrome Extensions (Manifest V3) documentation.” https://developer.chrome.com/docs/extensions/",
        "The Zeek Project. “Zeek Network Security Monitor.” https://zeek.org/",
        "MITRE. “MITRE ATT&CK Knowledge Base.” https://attack.mitre.org/",
      ].map((r, i) => new Paragraph({ spacing: { after: 100, line: 264 }, children: [new TextRun({ text: `[${i + 1}] `, bold: true, color: ACCENT }), new TextRun({ text: r })] })),
    ],
  }],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(path.join(__dirname, "OmniGuard_Midterm_Report.docx"), buf);
  console.log("wrote OmniGuard_Midterm_Report.docx");
});
