# OmniGuard Project Context & Engineering Guidelines

## 1. Project Purpose & Scope
- **OmniGuard SOC** is a defensive cybersecurity and threat detection platform consisting of:
  - **VerifyEye**: DOM-level analysis, phishing detection, and brand spoofing interception.
  - **SpectraC2**: Non-decrypting temporal and Fast Fourier Transform (FFT) beaconing detection engine for encrypted telemetry.
  - **Graph Correlation & Triage**: Neo4j attack graph correlation, local LLM triage, and host isolation workflows.
  - **Adversary Simulation Suite**: Automated test harnesses and synthetic telemetry generators used strictly for validating SOC detection pipelines, metric benchmarking, and live verification demos.

## 2. Testing & Telemetry Guidelines
- Treat all simulation components (`adversary-simulation/`, test harnesses, traffic generators) as **benchmarking fixtures and synthetic data emulators** designed to validate detection algorithms.
- Code contributions should focus on:
  - Detection algorithms, signal processing, and graph analytics.
  - Mock endpoints, test fixtures, synthetic HTTP/TLS traffic generation, and telemetry collectors.
  - Test automation, dashboard UI, and defensive incident response orchestration.
- When generating test cases or mock traffic, structure them as standard Python/Node unit and integration test fixtures.
