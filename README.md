# OmniGuard SOC: Multi-Modal Threat Defense, Jitter-Invariant C2 Analytics & Graph-Based Incident Triage

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-macOS%20|%20Linux%20|%20Docker-orange.svg)](#)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-v15.0-red.svg)](https://attack.mitre.org/)

An end-to-end cybersecurity intelligence platform that closes the loop between
initial phishing ingress, encrypted command-and-control beaconing, and analyst
response — **detect → reason → respond → account**, all with a human in control
and no data leaving the network.

OmniGuard SOC combines:
1. **VerifyEye** — real-time DOM-level phishing interception in the browser, with brand impersonation detection and client input locking.
2. **SpectraC2** — non-decrypting temporal / Fast Fourier Transform (FFT) beaconing detection using Isolation Forest and LSTM models.
3. **SOC Graph + Local LLM** — Neo4j attack-path correlation and zero-cloud-egress triage powered by a local Ollama model, with real one-click host containment and a tamper-evident decision ledger.

> **Read this first — honest status.** This README describes both what the
> platform **does today** and where it's **headed**. The original scope (below,
> in [§1](#1-executive-summary--problem-formulation)) was deliberately
> ambitious; this document is clear about which of those pieces are live and
> which are still on the roadmap. See [§2 Current Status](#2-current-status) for
> the one-glance picture.

---

## Table of Contents
- [1. Executive Summary & Problem Formulation](#1-executive-summary--problem-formulation)
- [2. Current Status: Built vs. Roadmap](#2-current-status-built-vs-roadmap)
- [3. System Architecture](#3-system-architecture)
- [4. Subsystem Deep Dives](#4-subsystem-deep-dives)
  - [4.1 VerifyEye (Ingress & Phishing Interception)](#41-verifyeye-ingress--phishing-interception)
  - [4.2 SpectraC2 (Encrypted Beaconing Analytics)](#42-spectrac2-encrypted-beaconing-analytics)
  - [4.3 Graph, Local LLM Triage, Containment & Ledger](#43-graph-local-llm-triage-containment--ledger)
- [5. Technology Stack](#5-technology-stack)
- [6. Repository Structure](#6-repository-structure)
- [7. End-to-End Attack & Validation Methodology](#7-end-to-end-attack--validation-methodology)
- [8. Quickstart & Installation](#8-quickstart--installation)
- [9. Roadmap & Future Work](#9-roadmap--future-work)
- [10. Academic References & Literature](#10-academic-references--literature)

**Legend:** ✅ built & working · 🟡 partial / scaffolded · 🚧 roadmap (future work)

---

## 1. Executive Summary & Problem Formulation

Modern Security Operations Centers (SOCs) face an escalating crisis driven by three disconnected attack vectors:
* **The Zero-Hour Phishing Gap**: Active credential harvesting domains operate for only 4 to 8 hours. Conventional defenses (DNS blacklists and static keyword matching) experience a 12–48 hour discovery delay, enabling attackers to harvest credentials before blacklists update.
* **The Encrypted C2 Blind Spot**: Over 95% of enterprise web traffic is encrypted via TLS 1.3. Adversaries inject pseudo-random timing jitter (0%–50%) into beacon loops, allowing reverse shells and post-exploitation frameworks (e.g., Sliver, Cobalt Strike) to blend into standard HTTPS browsing without detection.
* **Alert Fatigue & Multi-Hop Siloing**: Tier-1 to Tier-3 analysts are overwhelmed by 10,000+ daily disconnected alerts. Relational databases fail to surface multi-hop lateral movement, leaving Advanced Persistent Threats (APTs) with an average enterprise dwell time exceeding 16 days.

**OmniGuard SOC** unifies browser-level visual defense, encrypted network
telemetry analysis, and multi-relational graph analytics into one platform aimed
at slashing Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) while
keeping all AI reasoning and telemetry processing local — **zero cloud egress,
with a person in control of every response action.**

---

## 2. Current Status: Built vs. Roadmap

This is the one-glance honest picture of the platform as it stands.

| Capability | Status | Notes |
|---|---|---|
| **VerifyEye** phishing interception (Chrome MV3 + headless Playwright) | ✅ Built | Catches credential forms that submit off-domain; names the impersonated brand; locks input. |
| VerifyEye brand identification | 🟡 Partial | **DOM/text heuristic** brand matching is what runs. A YOLOv8 visual-logo model + pHash is scaffolded (`visual/`) but not the production verdict path. |
| **SpectraC2** FFT / IAT beacon detection | ✅ Built | Isolation Forest + LSTM models trained and on disk; `/classify-flow` API; jitter-invariant periodicity features. |
| SpectraC2 on IBM LinuxONE (`s390x`) | 🚧 Roadmap | Runs on commodity hardware today; `linuxone/` holds deployment manifests only. |
| **Neo4j** attack-graph correlation & blast radius | ✅ Built | Entity/relationship ingestion, multi-hop traversal. |
| **Local LLM triage** (Ollama, zero egress) | ✅ Built | Runs `llama3.2:3b` locally. Incident summaries, MITRE mapping, analyst Q&A. |
| **Ask AI** conversational triage + page-aware chat | ✅ Built | Analyst can interrogate any alert; context-aware corner helper. |
| **One-click host containment** (real network cut) | ✅ Built | A cooperative agent on the host **actually cuts and restores its network** on analyst command — not just a generated firewall rule. |
| **Tamper-evident decision ledger** | ✅ Built | Every request, AI output, and containment action is appended to an auditable ledger. |
| **AI transparency** layer | ✅ Built | Surfaces what the model saw and why it said what it said. |
| **MCP server** | ✅ Built | Exposes OmniGuard data/actions to MCP-compatible clients. |
| **React SOC dashboard** + live WebSocket updates | ✅ Built | Graph canvas, alert feed, triage, containment panel. |
| FFT periodicity heatmaps in the UI | 🚧 Roadmap | Spectral features are computed; the heatmap visualization is not built yet. |
| Telemetry streaming (Kafka / Redis / Zeek / Suricata) | 🟡 Scaffolded | Consumer + Zeek parser exist as code; **not in the live path.** Alerts POST directly to `/alerts`. |
| Adversary simulation (Sliver / Cobalt Strike / Flipper Zero) | 🟡 Partial | Replaced by a safe in-repo beacon simulator (`demo/beacon_sim.py`) for the demo. |
| Live AI (auto-watch incoming alerts) | 🚧 Roadmap | Today the AI reasons on demand; real-time auto-triage is planned. |

---

## 3. System Architecture

The diagram below is the **full target architecture.** Boxes marked 🚧 / 🟡 are
roadmap or scaffolded (see [§2](#2-current-status-built-vs-roadmap)); everything
else runs today.

```text
  [ Physical Ingress / Drop ]            🚧 (demo uses a safe simulator)
       Flipper Zero BadUSB
               │
               ├────────────────────────────────────────┐
               ▼                                        ▼
    [ Victim Web Browser ]                  [ C2 Beacon ]
    Chrome MV3 Extension        ✅          Beacon simulator        ✅
               │                            (Sliver/Cobalt Strike   🚧)
    (DOM inspection)                        (Encrypted TLS beaconing)
               ▼                                        ▼
   ┌───────────────────────┐               ┌─────────────────────────┐
   │ VerifyEye Engine   ✅ │               │ Telemetry sensors    🟡 │
   │ - Headless Playwright │               │ - Zeek conn parser      │
   │ - Brand heuristic  ✅ │               │ - Kafka consumer        │
   │ - YOLOv8 logo model🟡 │               │   (scaffolded, offline) │
   │ - DOM action check ✅ │               └────────────┬────────────┘
   └───────────┬───────────┘                            │
               │                              (flow metadata)
               │                                        ▼
               │                           ┌─────────────────────────┐
               │                           │ SpectraC2 Engine     ✅ │
               │                           │ - Inter-Arrival (IAT)   │
               │                           │ - FFT & Power Spectrum  │
               │                           │ - LSTM & Isolation For. │
               │                           │ - IBM LinuxONE s390x 🚧 │
               │                           └────────────┬────────────┘
               │                                        │
               └───────────────────┬────────────────────┘
                                   │ (structured alerts → POST /alerts ✅)
                                   ▼
                   ┌───────────────────────────────┐
                   │ Neo4j Property Graph       ✅ │
                   │ - Shortest path / blast radius│
                   │ - Entity resolution           │
                   └───────────────┬───────────────┘
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │ Local LLM Triage (Ollama)  ✅ │
                   │ - llama3.2:3b, zero egress    │
                   │ - MITRE ATT&CK mapping        │
                   │ - Incident summary + Ask AI   │
                   └───────────────┬───────────────┘
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │ React SOC Dashboard        ✅ │
                   │ - Attack graph canvas         │
                   │ - 1-click REAL host isolation │
                   │ - Tamper-evident ledger       │
                   │ - FFT heatmaps             🚧 │
                   └───────────────────────────────┘
```

---

## 4. Subsystem Deep Dives

### 4.1 VerifyEye (Ingress & Phishing Interception) ✅

* **Client-Side Inline Protection** ✅: A lightweight Chrome Extension (Manifest V3) that monitors dynamic DOM changes, cross-origin `action` endpoints, and form input bindings, backed by a headless Playwright crawler (`dom/crawler.py`).
* **Brand Identification** 🟡: The production verdict uses **DOM/text heuristic** brand matching (`visual/detector.py`) against a curated brand list (Microsoft, Google, Okta, PayPal, …). A quantized **YOLOv8** object-detection model and perceptual hashing (**pHash**, `visual/phash.py`) are scaffolded for visual logo detection but are not yet the decision path.
* **Zero-Hour Interception** ✅: If a page shows a credential form that submits to **off-domain** infrastructure while impersonating a known brand, VerifyEye flags it and can lock input before credentials are dispatched.

### 4.2 SpectraC2 (Encrypted Beaconing Analytics) ✅

* **Metadata-Only Processing** ✅: No TLS decryption or DPI — classification is driven by flow timing/metadata only.
* **Jitter-Invariant Signal Processing** ✅: Beacon loops — even with 10%–50% randomized jitter — exhibit underlying periodicities. SpectraC2 extracts Inter-Arrival Time deltas $\Delta t_i = t_i - t_{i-1}$ and computes the **Fast Fourier Transform** and **Power Spectral Density**:
  $$X(f) = \sum_{n=0}^{N-1} x[n] \cdot e^{-j 2\pi f n / N}$$
* **Inference** ✅: Trained **Isolation Forest** (`isolation_forest.joblib`) and **LSTM** (`spectrac2_lstm.pt`) models score flows. Runs on commodity hardware; **IBM LinuxONE (`s390x`) deployment is roadmap** 🚧 (`linuxone/` holds manifests).
* **Telemetry source** 🟡: In the live demo, flows are fed by `demo/beacon_sim.py`. A Zeek/Kafka streaming path is scaffolded (`telemetry-pipeline/`) but not wired into the running system.

### 4.3 Graph, Local LLM Triage, Containment & Ledger ✅

* **Property Graph Ingestion** ✅: Normalized entities (`Host`, `User`, `IP`, `Process`, `Domain`) and relationships into **Neo4j**, with host-name normalization so the extension, beacon, and agent always correlate onto one node.
* **Blast-Radius Propagation** ✅: Graph traversal to trace multi-hop paths and risk.
* **Air-Gapped Synthesis** ✅: An on-premise **Ollama** instance running **`llama3.2:3b`** produces incident summaries, maps MITRE techniques (`T1566`, `T1056`, `T1071`, `TA0008`), and answers analyst questions — **100% local, zero cloud egress.**
* **Real One-Click Containment** ✅: The analyst's "Isolate host" button hands a command to a **cooperative containment agent running on the host** (`demo/containment_agent.py`), which *actually cuts the machine off the network* (firewall default-block, keeping only the SOC control channel open) and restores it on release. Nothing happens without an analyst request, and the agent confirms back when the action is really applied.
* **Tamper-Evident Decision Ledger** ✅: Every isolation request, AI output, and agent confirmation is appended to an auditable ledger (`backend/ledger.py`) — the "account" in detect-reason-respond-account.
* **AI Transparency** ✅ (`backend/ai_transparency.py`) and an **MCP server** ✅ (`mcp_server/`) that exposes OmniGuard data and actions to MCP-compatible clients round out the triage layer.

---

## 5. Technology Stack

| Layer | Technologies | Status |
|---|---|---|
| **Adversary Simulation** | In-repo beacon simulator; Flipper Zero DuckyScript payloads | ✅ sim · 🟡 Flipper assets · 🚧 Sliver/Cobalt Strike |
| **Visual Ingress AI** | Playwright, Chrome MV3, DOM/text brand heuristics; (YOLOv8/ONNX/OpenCV scaffolded) | ✅ DOM path · 🟡 vision model |
| **Flow Inference Engine** | NumPy, SciPy (FFT), Scikit-Learn (Isolation Forest), PyTorch (LSTM), FastAPI | ✅ |
| **Telemetry & Streaming** | Zeek conn parser, Kafka consumer | 🟡 scaffolded, offline |
| **Graph Correlation Core** | Neo4j (Cypher), Python graph engine | ✅ |
| **Air-Gapped LLM Triage** | Ollama (`llama3.2:3b`), Pydantic | ✅ |
| **Analyst Dashboard** | React.js, Vite, WebSockets | ✅ |
| **Core API & Data** | FastAPI, MongoDB, MCP | ✅ |

> **On the local model.** OmniGuard runs `llama3.2:3b` locally by design — the
> goal is data sovereignty, not maximum model size. The architecture pushes
> multi-step work into the backend so a small local model stays sufficient.

---

## 6. Repository Structure

```text
omniguard/
├── backend/                      # ✅ FastAPI core: alerts, graph, AI triage,
│   │                             #    containment, ledger, conversations, MCP glue
│   ├── main.py                   #    REST + WebSocket endpoints
│   ├── ai.py / ai_transparency.py#    Local LLM triage + transparency
│   ├── containment.py            #    Host isolation state machine
│   ├── ledger.py                 #    Tamper-evident decision ledger
│   ├── graph.py                  #    Neo4j correlation & blast radius
│   └── ...                       #    ocsf, dedup, evidence, triage, turns, auth
├── verifyeye-ingress/            # ✅ Visual & DOM phishing defense
│   ├── extension/                #    Chrome Extension (Manifest V3)
│   ├── dom/crawler.py            #    Playwright headless DOM parser
│   ├── visual/                   #    🟡 brand heuristic (detector.py) + pHash
│   └── service.py                #    Verdict API
├── spectrac2-engine/             # ✅ Encrypted beaconing analytics
│   ├── feature_extraction/       #    IAT, FFT, spectral power density
│   ├── inference/                #    Isolation Forest + LSTM (trained models)
│   ├── linuxone/                 #    🚧 IBM LinuxONE (s390x) manifests
│   └── service/                  #    FastAPI flow-classification API
├── telemetry-pipeline/           # 🟡 scaffolded, not in live path
│   ├── zeek-scripts/             #    conn.log parser
│   └── kafka-consumers/          #    stream consumer
├── adversary-simulation/         # 🟡 flipper/ assets
├── demo/                         # ✅ Two-laptop live demo
│   ├── beacon_sim.py             #    Safe C2 beacon simulator
│   ├── containment_agent.py      #    Cooperative host-isolation agent
│   └── setup_demo_hosts.py       #    Fake-domain hosts-file helper
├── mcp_server/                   # ✅ MCP server exposing OmniGuard
├── frontend/                     # ✅ React/Vite SOC dashboard
├── fake_sites/                   #    Demo phishing pages
├── schemas/                      #    Shared alert contract
├── docs/                         #    Setup + demo runbooks
├── tests/
├── docker-compose.yml            #    mongo, neo4j, backend, verifyeye-agent, frontend
└── README.md
```

---

## 7. End-to-End Attack & Validation Methodology

The platform is exercised against a multi-stage intrusion scenario. Stages
marked 🚧 are target scope; the live two-laptop demo covers ingress → egress →
triage → **real response**.

```text
[ STAGE 1: INGRESS ] ──► [ STAGE 2: EGRESS ] ──► [ STAGE 3: TRIAGE ] ──► [ STAGE 4: RESPOND ]
   ✅                        ✅                       ✅                      ✅
- Fake login page         - Beacon simulator dials  - Both engines correlate  - Analyst isolates the
- VerifyEye flags the       the SOC (real timing)     onto one host in Neo4j    host → agent REALLY
  brand impersonation     - SpectraC2 FFT flags     - Local LLM summarizes      cuts its network
  & off-domain submit       the periodicity           & maps MITRE            - Every step written to
                                                    - Analyst asks "Ask AI"     the tamper-evident ledger

[ STAGE 3b: LATERAL MOVEMENT ]  🚧  — LSASS dump / pass-the-hash expansion is target scope, not yet simulated.
```

### Validation Benchmarks — *targets, not yet measured*
These were the project's **target** numbers. They are not independently measured
yet; an evaluation harness is roadmap ([§9](#9-roadmap--future-work)).
* **Detection Latency** 🚧: ingestion-to-graph correlation target `< 500 ms`.
* **Inference Precision** 🚧: `> 95%` precision target on encrypted C2 flow classification.
* **Zero Egress** ✅: 100% local LLM summarization and telemetry processing — no third-party API calls. (This one holds today by construction.)

---

## 8. Quickstart & Installation

> **What runs today.** The platform core — the alert API, the MongoDB alert
> store, the Neo4j attack graph, the local LLM triage, and the React dashboard —
> runs locally. SpectraC2 and VerifyEye are developed in their own folders and
> connect to the API over HTTP. For the full, always-current setup guide see
> [`docs/running-locally.md`](docs/running-locally.md), and for the live
> two-laptop demo see [`docs/lan-demo-setup.md`](docs/lan-demo-setup.md).

### The fast way — Docker

Needs **Docker Desktop** running. The compose stack brings up `mongo`, `neo4j`,
`backend`, `verifyeye-agent`, and `frontend`.

```bash
git clone <this-repo>
cd omniguard
docker compose up -d --build
```

| Service   | URL                          |
|-----------|------------------------------|
| Dashboard | http://localhost:8080        |
| API + Swagger | http://localhost:8000/docs |
| Neo4j browser | http://localhost:7474    |

Stop with `docker compose down` (data persists in named volumes). The backend
reaches the databases by service name (`mongo`, `neo4j`), not localhost.

### The manual way — for development

Separate processes, no rebuild on each change. Needs Python 3.11+, Node 18+,
MongoDB, Neo4j Desktop, and [Ollama](https://ollama.com). Full steps in
[`docs/running-locally.md`](docs/running-locally.md); in short:

```bash
# local LLM
ollama pull llama3.2:3b

# backend — terminal 1
cd backend && python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # then set NEO4J_PASSWORD
uvicorn main:app --reload       # API on :8000

# frontend — terminal 2
cd frontend && npm install && npm run dev   # dashboard on :5173
```

### Sending a test alert

Any engine — or you, from Swagger — posts to `POST /alerts`. One shape for every
engine, documented in
[`schemas/omniguard_data_schemas.json`](schemas/omniguard_data_schemas.json).

```bash
curl -X POST http://localhost:8000/alerts -H 'Content-Type: application/json' -d '{
  "source": "manual",
  "event_type": "suspicious_login",
  "severity": "high",
  "host": "WS-FINANCE-04"
}'
```

It appears on the dashboard live, and in the attack graph.

---

## 9. Roadmap & Future Work

Ordered roughly by priority. These are the pieces that are scaffolded or
designed but not yet live.

1. **Live AI** 🚧 — have the local model watch incoming alerts in real time and surface what needs attention, instead of only answering on demand.
2. **Polish the UI** 🚧 — refine the dashboard, visuals, and overall analyst UX.
3. **Train & tune the models** 🚧 — improve SpectraC2 detection accuracy and the local LLM's answers; stay on the local-only model.
4. **Evaluation harness** 🚧 — run the beacon simulator against benign traffic through SpectraC2 and report **real, measured** precision/latency to replace the target numbers in [§7](#7-end-to-end-attack--validation-methodology).
5. **FFT periodicity heatmaps** 🚧 in the dashboard (spectral features are already computed).
6. **Visual logo detection** 🚧 — promote the scaffolded YOLOv8 + pHash path into the VerifyEye verdict.
7. **Live telemetry streaming** 🚧 — wire the Zeek → Kafka pipeline into the running system instead of direct POSTs.
8. **Enterprise targets** 🚧 — IBM LinuxONE (`s390x`) deployment; lateral-movement (pass-the-hash) scenario; real C2 frameworks in the adversary-simulation lab.

---

## 10. Academic References & Literature

1. **MITRE Corporation**: *MITRE ATT&CK® Enterprise Matrix (v14/v15)*. Tactics & Techniques covering Phishing (`T1566`), Input Capture (`T1056`), Command and Control (`TA0011`, `T1071`), and Lateral Movement (`TA0008`), 2024–2025.
2. **Lin, D., et al. (IEEE S&P)**: *Phishpedia: A Deep Learning-Based Phishing Detection System with High Accuracy and Low False Positives*. Technical foundations for logo identification, visual layout verification, and coordinate mapping.
3. **Al-Eroud, A., & Alsmadi, I.**: *Identifying Malicious HTTPS Command and Control (C2) Traffic using Behavioral Flow Metrics*. Journal of Information Security and Applications, vol. 72, p. 103398, 2023.
4. **Noel, S., & Jajodia, S.**: *Managing Attack Graph Complexity Through Visual Hierarchies*. IEEE Transactions on Dependable and Secure Computing.
5. **DARPA Transparent Computing Program**: *Graph-based Provenance Tracking and APT Detection via Fine-Grained System Telemetry Datasets*, 2020.
6. **Anderson, B., & McGrew, D. (ACM CCS)**: *Machine Learning for Encrypted Malware Traffic Classification: Accounting for Metadata Inaccuracies and Concept Drift*. Proceedings of the ACM Conference on Computer and Communications Security.
7. **Oest, A., et al. (USENIX Security)**: *Sunrise to Sunset: Analyzing the End-to-End Life Cycle and Interventions of Phishing Attacks*. Comparative studies on DNS blacklist discovery latency versus inline rendering inspection.
8. **IEEE Security & Privacy Workshops**: *Cyber Threat Intelligence Extraction using Domain-Adapted Local LLMs without Privacy Leakage*, 2024.
9. **IBM Corporation**: *IBM LinuxONE III Technical Guide: High-Performance Enterprise Linux on s390x Architecture*, IBM Redbooks, 2024.
10. **Open Information Security Foundation (OISF) & Zeek Project**: *Suricata EVE JSON and Zeek Network Telemetry Protocol Parsing Standards*, 2024–2025.
