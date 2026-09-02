# OmniGuard SOC: Autonomous Multi-Modal Threat Defense, Jitter-Invariant C2 Analytics & Graph-Based Incident Triage

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20|%20IBM%20s390x%20|%20AWS-orange.svg)](#)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-v15.0-red.svg)](https://attack.mitre.org/)

An enterprise-grade, end-to-end cybersecurity intelligence platform designed to eliminate the gaps between initial ingress attacks, encrypted command-and-control beaconing, and distributed lateral movement. 

OmniGuard SOC combines:
1. **VerifyEye**: Real-time visual and DOM-level phishing interception with client input locking.
2. **SpectraC2**: Non-decrypting temporal and Fast Fourier Transform (FFT) beaconing detection on IBM LinuxONE (`s390x`).
3. **SOC Graph Visualizer & Local LLM**: Dynamic Neo4j attack path correlation with zero-cloud-egress triage powered by Ollama.

---

## Table of Contents
- [1. Executive Summary & Problem Formulation](#1-executive-summary--problem-formulation)
- [2. System Architecture](#2-system-architecture)
- [3. Subsystem Deep Dives](#3-subsystem-deep-dives)
  - [3.1 VerifyEye (Ingress & Phishing Interception)](#31-verifyeye-ingress--phishing-interception)
  - [3.2 SpectraC2 (Encrypted Beaconing Analytics)](#32-spectrac2-encrypted-beaconing-analytics)
  - [3.3 Autonomous Graph & Local LLM Triage](#33-autonomous-graph--local-llm-triage)
- [4. Technology Stack](#4-technology-stack)
- [5. Repository Structure](#5-repository-structure)
- [6. End-to-End Attack & Validation Methodology](#6-end-to-end-attack--validation-methodology)
- [7. Quickstart & Installation](#7-quickstart--installation)
- [8. Project Timeline & Milestones](#8-project-timeline--milestones)
- [9. Academic References & Literature](#9-academic-references--literature)

---

## 1. Executive Summary & Problem Formulation

Modern Security Operations Centers (SOCs) face an escalating crisis driven by three disconnected attack vectors:
* **The Zero-Hour Phishing Gap**: Active credential harvesting domains operate for only 4 to 8 hours. Conventional defenses (DNS blacklists and static keyword matching) experience a 12–48 hour discovery delay, enabling attackers to harvest credentials before blacklists update.
* **The Encrypted C2 Blind Spot**: Over 95% of enterprise web traffic is encrypted via TLS 1.3. Adversaries inject pseudo-random timing jitter (0%–50%) into beacon loops, allowing reverse shells and post-exploitation frameworks (e.g., Sliver, Cobalt Strike) to blend into standard HTTPS browsing without detection.
* **Alert Fatigue & Multi-Hop Siloing**: Tier-1 to Tier-3 analysts are overwhelmed by 10,000+ daily disconnected alerts. Relational databases fail to surface multi-hop lateral movement, leaving Advanced Persistent Threats (APTs) with an average enterprise dwell time exceeding 16 days.

**OmniGuard SOC** unifies browser-level visual defense, enterprise-grade encrypted network telemetry, and multi-relational graph analytics into an autonomous defense platform capable of slashing Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) from hours to seconds while maintaining zero-cloud-egress data sovereignty.

---

## 2. System Architecture

```text
  [ Physical Ingress / Drop ]
       Flipper Zero BadUSB
               │
               ├────────────────────────────────────────┐
               ▼                                        ▼
    [ Victim Web Browser ]                  [ In-Memory C2 Implant ]
    Chrome MV3 Extension                     Sliver Reverse Shell
               │                                        │
    (DOM & Perceptual Hash)                (Encrypted TLS 1.3 Beaconing)
               ▼                                        ▼
   ┌───────────────────────┐               ┌─────────────────────────┐
   │ VerifyEye AI Engine   │               │ Network Sensors         │
   │ - Headless Playwright │               │ - Zeek (conn/ssl.log)   │
   │ - YOLOv8 Logo Model   │               │ - Suricata (EVE JSON)   │
   │ - DOM Action Validator│               └────────────┬────────────┘
   └───────────┬───────────┘                            │
               │                              (Flow Metadata Streaming)
               │                                        ▼
               │                           ┌─────────────────────────┐
               │                           │ Apache Kafka / Redis    │
               │                           └────────────┬────────────┘
               │                                        │
               │                                        ▼
               │                           ┌─────────────────────────┐
               │                           │ SpectraC2 Engine        │
               │                           │ - IBM LinuxONE (s390x)  │
               │                           │ - Inter-Arrival (IAT)   │
               │                           │ - FFT & Power Spectrum  │
               │                           │ - LSTM & Isolation For. │
               │                           └────────────┬────────────┘
               │                                        │
               └───────────────────┬────────────────────┘
                                   │ (Structured Alert Payloads)
                                   ▼
                   ┌───────────────────────────────┐
                   │ Neo4j Property Graph          │
                   │ - Shortest Path & Dijkstra    │
                   │ - Blast Radius Calculations   │
                   │ - Dynamic Entity Resolution   │
                   └───────────────┬───────────────┘
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │ Local Air-Gapped LLM Triage   │
                   │ - Ollama (Llama-3-Cyber)      │
                   │ - MITRE ATT&CK Matrix Mapping │
                   │ - Executive Incident Summary  │
                   └───────────────┬───────────────┘
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │ Unified React SOC Dashboard   │
                   │ - React Flow Graph Canvas     │
                   │ - FFT Periodicity Heatmaps    │
                   │ - 1-Click Host Isolation      │
                   └───────────────────────────────┘
```

---

## 3. Subsystem Deep Dives

### 3.1 VerifyEye (Ingress & Phishing Interception)
* **Client-Side Inline Protection**: A lightweight Chrome Extension (Manifest V3) that continuously monitors dynamic DOM changes, cross-origin `action` endpoints, and form input bindings.
* **Perceptual Brand Identification**: Leverages a quantized **YOLOv8** object detection model and Perceptual Hashing (**pHash**) to classify corporate brand targets (e.g., Microsoft 365, Okta, Google Workspace) in <500ms.
* **Zero-Hour Interception**: If a rendered site visually matches an authentic portal but originates from unverified infrastructure, VerifyEye freezes input fields, injects visual threat bounding boxes, and prevents credential dispatch before exfiltration occurs.

### 3.2 SpectraC2 (Encrypted Beaconing Analytics)
* **Metadata-Only Processing**: Bypasses the need for TLS decryption or invasive Deep Packet Inspection (DPI) by ingesting flow telemetry via Zeek (`conn.log`, `ssl.log`) and Suricata.
* **Jitter-Invariant Signal Processing**: Programmatic beacon loops—even those with 10%–50% randomized jitter—exhibit distinct underlying periodicities. SpectraC2 extracts Inter-Arrival Time (IAT) deltas $\Delta t_i = t_i - t_{i-1}$ and computes the **Fast Fourier Transform (FFT)** and **Power Spectral Density (PSD)**:
  $$X(f) = \sum_{n=0}^{N-1} x[n] \cdot e^{-j 2\pi f n / N}$$
* **Enterprise Inference on IBM LinuxONE (`s390x`)**: Evaluates sequential packet order and spectral features using **Isolation Forest** and **LSTM** models, distinguishing automated reverse shells from noisy human browsing at scale.

### 3.3 Autonomous Graph & Local LLM Triage
* **Property Graph Ingestion**: Ingests normalized entities (`Host`, `User`, `IP`, `Process`, `Domain`) and relationships (`CONNECTED_TO`, `SPAWNED`, `AUTHENTICATED_AS`) into **Neo4j**.
* **Blast-Radius Propagation**: Uses NetworkX graph traversal algorithms to trace multi-hop pivot paths and quantify enterprise risk scores dynamically.
* **Air-Gapped Synthesis**: Uses an on-premise instance of **Ollama** running `Llama-3-Cyber` or `Mistral` via strict JSON schema prompting. The engine translates graph paths into incident summaries, maps MITRE techniques (`T1566`, `T1056`, `T1071`, `TA0008`), and generates actionable 1-click containment commands (e.g., firewall block rules, host quarantine).

---

## 4. Technology Stack

| Layer | Primary Technologies | Functional Responsibility |
|---|---|---|
| **Adversary Simulation** | Flipper Zero (DuckyScript / Sub-GHz), Sliver C2, Cobalt Strike | Emulating BadUSB keystrokes, captive portals, and randomized egress beacons. |
| **Visual Ingress AI** | PyTorch, YOLOv8, ONNX Runtime, OpenCV, Playwright, Chrome MV3 | Real-time DOM inspection, logo object detection, and credential submission freezing. |
| **Flow Inference Engine** | IBM LinuxONE (`s390x`), NumPy, SciPy (FFT), Scikit-Learn, PyTorch, FastAPI | High-throughput temporal flow feature calculation and beacon classification. |
| **Telemetry & Streaming** | Apache Kafka, Redis Queue, Zeek (Bro), Suricata (EVE JSON), Scapy | Scalable log streaming, protocol parsing, and backpressure management. |
| **Graph Correlation Core** | Neo4j (Cypher), NetworkX, Python Graph Engine | Entity correlation, multi-hop shortest-path discovery, and blast radius calculation. |
| **Air-Gapped LLM Triage** | Ollama, Llama-3-Cyber / Mistral, LangChain, Pydantic | Privacy-preserving incident summarization, MITRE tagging, and remediation generation. |
| **Analyst Dashboard** | React.js, React Flow, D3.js, Tailwind CSS, Recharts, WebSockets | Unified multi-pane interface for graph navigation, spectral heatmaps, and mitigation. |

---

## 5. Repository Structure

```text
omniguard-soc/
├── .github/                      # CI/CD pipelines and PR workflows
├── adversary-simulation/         # Offensive attack tooling & test suites
│   ├── flipper/                  # Flipper Zero DuckyScript payloads & Evil Portal configs
│   ├── sliver/                   # C2 server listener configs & profile manifests
│   └── pcap-replay/              # Synthetic and DARPA TC/Caldera evaluation PCAPs
├── verifyeye-ingress/            # Visual & DOM Phishing Defense Subsystem
│   ├── extension/                # Chrome Extension (Manifest V3) content/background scripts
│   ├── crawler/                  # Playwright headless DOM parsing service (AWS ECS/Lambda)
│   └── models/                   # YOLOv8 weights, ONNX export scripts, and pHash utilities
├── spectrac2-engine/             # Encrypted Network Behavioral Analytics Subsystem
│   ├── feature-extraction/       # IAT calculation, FFT, and spectral power density scripts
│   ├── inference/                # Isolation Forest and LSTM model definitions & checkpoints
│   ├── linuxone/                 # IBM LinuxONE (s390x) deployment manifests & Dockerfiles
│   └── service/                  # FastAPI microservice exposing flow classification APIs
├── telemetry-pipeline/           # Streaming Ingestion & Parsing
│   ├── zeek-scripts/             # Custom Zeek policy definitions & conn/ssl log extractors
│   ├── suricata/                 # Suricata rulesets & EVE.json parsers
│   └── kafka-consumers/          # Message serialization, Redis queue workers, & normalizers
├── graph-triage-core/            # Neo4j Entity Resolution & Local LLM Synthesis
│   ├── schema/                   # Neo4j Cypher constraints, indexes, and graph schemas
│   ├── traversal/                # NetworkX blast radius and shortest path implementations
│   ├── ollama-triage/            # Local LLM prompt templates, Pydantic schemas, and LangChain loops
│   └── api/                      # Core orchestration REST/WebSocket endpoints
├── frontend-dashboard/           # Unified SOC Analyst Dashboard
│   ├── src/
│   │   ├── components/graph/     # React Flow interactive attack topology canvas
│   │   ├── components/spectral/  # FFT periodicity heatmaps and beacon time series (D3/Recharts)
│   │   ├── components/verify/    # Visual diffs, logo matches, and credential capture inspect
│   │   └── components/triage/    # Natural language incident timeline & 1-click mitigation actions
│   └── package.json
├── docker-compose.yml            # Multi-service local orchestrator
└── README.md
```

---

## 6. End-to-End Attack & Validation Methodology

The platform is evaluated against a synchronized multi-stage enterprise intrusion simulation:

```text
[ STAGE 1: INGRESS ] ──► [ STAGE 2: EGRESS ] ──► [ STAGE 3: PIVOTING ] ──► [ STAGE 4: TRIAGE ]
Physical BadUSB Drop      Encrypted Beaconing      Internal Lateral Pivot     Air-Gapped LLM Remediation
- Flipper Zero injects    - Staged Sliver implant  - LSASS dump & Pass-the-   - Ollama maps ATT&CK matrix
  keystrokes                dials AWS listener       Hash across domain         (T1566, T1056, T1071)
- Launches fake login     - 30% jitter applied       controllers              - Generates executive narrative
- VerifyEye locks input   - SpectraC2 FFT flags    - Neo4j graph expands      - Pushes 1-click firewall
  & flags logo theft        harmonic spikes          blast radius in UI         quarantine rule
```

### Validation Benchmarks
* **Detection Latency**: Ingestion-to-graph correlation in $<500	ext{ ms}$.
* **Inference Precision**: $>95\%$ precision target on active encrypted C2 flow classifications across $200+$ test runs.
* **Zero Egress**: $100\%$ local execution of LLM summarization and network telemetry processing without third-party API exposure.

---

## 7. Quickstart & Installation

### Prerequisites
* Docker & Docker Compose (v2.20+)
* Python 3.11+
* Node.js 18+ & npm
* Ollama installed locally with the target model:
  ```bash
  ollama pull llama3
  ```

### 1. Clone Repository & Setup Environment
```bash
git clone https://github.com/your-org/omniguard-soc.git
cd omniguard-soc
cp .env.example .env
```

### 2. Boot Infrastructure Stack
Launch Kafka, Redis, Neo4j, and core microservices:
```bash
docker-compose up -d neo4j kafka redis
```
* Neo4j Browser will be available at `http://localhost:7474` (Default Auth: `neo4j/omniguard_secret`).

### 3. Launch Backend Microservices
```bash
# Setup Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r spectrac2-engine/requirements.txt
pip install -r graph-triage-core/requirements.txt

# Start SpectraC2 & Graph Triage APIs
uvicorn graph-triage-core.api.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Start the Unified React Dashboard
```bash
cd frontend-dashboard
npm install
npm run dev
```
Navigate to `http://localhost:3000` to view the active incident console.

---

## 8. Project Timeline & Milestones

| Phase | Duration | Focus Area | Deliverables |
|---|---|---|---|
| **Phase 1** | Weeks 1–3 | Architecture & Infrastructure | Provision IBM LinuxONE & AWS environments; configure Kafka/Redis queues; author Flipper Zero DuckyScripts and Sliver C2 listeners. |
| **Phase 2** | Weeks 4–6 | AI Models & Graph Schema | Train YOLOv8 brand detection model; implement FFT spectral feature pipeline; deploy Neo4j base schemas and entity resolution. |
| **Phase 3** | Weeks 7–9 | Graph Traversal & Local LLM | Implement NetworkX shortest-path algorithms; configure Ollama Llama-3 structured prompt templates; benchmark LinuxONE throughput. |
| **Phase 4** | Weeks 10–12 | Dashboard & Client Extension | Build Chrome MV3 Extension; deliver React Flow attack graph canvas and FFT spectral heatmaps; hook up WebSocket event streams. |
| **Phase 5** | Weeks 13–14 | Replay, Benchmarking & Showcase | Execute end-to-end multi-stage intrusion replay; achieve $>95\%$ precision benchmarks; compile technical whitepaper and demo. |

---

## 9. Academic References & Literature

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
