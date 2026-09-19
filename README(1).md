# VerifyEye

**VerifyEye** is the visual ingress defense component of the **OmniGuard SOC** capstone project.

Its purpose is to analyze web pages for signs of credential-phishing activity by combining:

- **Playwright** for browser automation and DOM analysis
- **YOLOv8** for visual object/logo detection
- **pHash** for perceptual image comparison
- **Chrome Manifest V3** for browser-side credential-form protection
- A structured result format that can later connect VerifyEye to the OmniGuard SOC graph, dashboard, and telemetry systems

> **Project status:** Early development / prototype  
> **Team member:** Rahim  
> **Project:** OmniGuard SOC  
> **Target completion:** December 2026

---

## 1. Role in OmniGuard SOC

VerifyEye represents the **visual ingress defense** portion of OmniGuard SOC.

The overall OmniGuard architecture combines ingress defense, encrypted C2 behavioral detection, graph correlation, local LLM triage, and a unified SOC dashboard.

Rahim's assigned responsibilities are:

1. Build the VerifyEye visual detection engine.
2. Use YOLOv8 and pHash for brand/logo analysis.
3. Build a Playwright-based DOM crawler.
4. Develop a Chrome MV3 extension that can protect credential forms.
5. Create controlled adversary-emulation scenarios for testing.

The VerifyEye component is intended to provide structured alerts that can later be consumed by the other OmniGuard components.

---

## 2. High-Level Architecture

```text
                         Web Page
                            |
                +-----------+-----------+
                |                       |
                v                       v
           Playwright               Screenshot
           DOM Scanner                   |
                |                        v
                |                    YOLOv8
                |                        |
                |                        v
                |                  Logo Detection
                |                        |
                |                        v
                |                      pHash
                |                        |
                +-----------+------------+
                            |
                            v
                       Risk Analysis
                            |
                            v
                     VerifyEye Alert
                            |
              +-------------+-------------+
              |                           |
              v                           v
       Chrome MV3 Extension       OmniGuard Backend
                                      |
                         +------------+------------+
                         |            |            |
                         v            v            v
                       Abu          Aayush        Khoi
                     Neo4j/LLM     Dashboard     Telemetry
```

---

## 3. Current Development Scope

### 3.1 Playwright DOM Scanner

The DOM scanner opens an authorized test webpage and examines its HTML structure.

It currently focuses on:

- Page URL
- Page title
- Number of forms
- Username/email fields
- Password fields
- Possible credential forms
- Form submission destinations

Example output:

```json
{
  "url": "http://localhost:3000",
  "title": "Test Login Page",
  "form_count": 1,
  "credential_form": true,
  "username_field": true,
  "password_field": true,
  "form_actions": [
    "/login"
  ]
}
```

### 3.2 YOLOv8

YOLOv8 is planned to provide visual detection of logos or other relevant webpage elements.

The initial implementation provides the detection framework. A dedicated, labeled brand-logo dataset/model is required for reliable brand-specific detection.

Expected future output:

```json
{
  "brand": "ExampleBank",
  "confidence": 0.94
}
```

### 3.3 pHash

pHash creates a perceptual fingerprint of an image.

VerifyEye can compare:

- A detected/cropped logo
- A known legitimate reference logo

A smaller pHash distance generally indicates greater visual similarity.

Example:

```text
Reference Logo
      |
     pHash
      |
      A
      |
      | compare
      |
      B
      |
Detected Logo
```

### 3.4 Chrome MV3 Extension

The browser extension is planned to:

1. Detect credential forms.
2. Send page information to VerifyEye.
3. Receive a risk result.
4. Warn the user about suspicious pages.
5. Lock or prevent credential submission when the page is considered unverified/high-risk.

### 3.5 Adversary Emulation

Testing will use controlled, authorized scenarios such as:

- Simulated phishing pages
- Rogue captive-portal scenarios
- Controlled credential-harvesting demonstrations
- Controlled C2/telemetry scenarios

These scenarios are intended to validate the defensive components and provide test telemetry for the wider OmniGuard SOC.

---

## 4. Project Structure

The planned project structure is:

```text
verifyeye/
│
├── main.py
│
├── dom/
│   ├── __init__.py
│   └── crawler.py
│
├── visual/
│   ├── __init__.py
│   ├── detector.py
│   ├── phash.py
│   └── logos/
│       ├── legitimate-logo-1.png
│       └── legitimate-logo-2.png
│
├── scoring/
│   └── risk_score.py
│
├── api/
│   └── server.py
│
├── chrome_extension/
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   ├── popup.js
│   └── style.css
│
├── adversary_emulation/
│   ├── scenarios/
│   │   ├── phishing_scenario.md
│   │   ├── captive_portal_scenario.md
│   │   └── c2_scenario.md
│   └── test_data/
│
├── tests/
│   ├── test_visual.py
│   ├── test_dom.py
│   └── test_scoring.py
│
└── README.md
```

Not every directory is required in the first prototype. Components can be added incrementally.

---

## 5. Technologies

| Technology | Purpose |
|---|---|
| Python | Main VerifyEye development language |
| Playwright | Browser automation and DOM inspection |
| Chromium | Browser used by Playwright |
| Ultralytics YOLOv8 | Visual/logo detection |
| OpenCV | Image processing |
| Pillow | Image loading and processing |
| imagehash | pHash generation and comparison |
| FastAPI | Planned VerifyEye API |
| Chrome MV3 | Planned browser extension |
| Git/GitHub | Version control and collaboration |

---

## 6. Installation

### Requirements

- Windows, Linux, or macOS
- Python 3.x
- pip
- Git
- Chromium-compatible environment

### Install Python packages

```bash
pip install playwright
pip install ultralytics
pip install opencv-python
pip install pillow
pip install imagehash
```

Or install them together:

```bash
pip install playwright ultralytics opencv-python pillow imagehash
```

### Install Playwright Chromium

Use Python's module execution method:

```bash
python -m playwright install chromium
```

If `python` is not available but the Windows Python launcher is installed:

```bash
py -m playwright install chromium
```

### Verify Playwright

```bash
python -m playwright --version
```

---

## 7. Running the Current Prototype

From the `verifyeye` directory:

```bash
python main.py
```

The program asks for a URL:

```text
Enter website URL:
```

Enter a webpage that you own or are authorized to test.

The prototype then prints:

```text
===== VerifyEye Result =====
URL: ...
Title: ...
Forms: ...
Credential Form: ...
Username Field: ...
Password Field: ...

Form Actions:
- ...
```

---

## 8. Example DOM Detection Flow

For a test page containing:

```html
<form action="/login" method="POST">
    <input type="email" name="email">
    <input type="password" name="password">
    <button type="submit">Login</button>
</form>
```

VerifyEye should identify:

```text
Forms: 1
Credential Form: True
Username Field: True
Password Field: True
Form Actions:
- /login
```

This demonstrates the first stage of VerifyEye's credential-phishing detection pipeline.

---

## 9. Visual Detection Flow

The planned visual pipeline is:

```text
Web Page
   |
   v
Screenshot
   |
   v
YOLOv8
   |
   v
Detected Logo
   |
   v
Crop / Normalize Image
   |
   v
pHash
   |
   v
Compare with Reference Logo
   |
   v
Similarity / Distance
```

### Important

The standard YOLOv8 model is not automatically a dedicated brand-logo classifier.

For brand-specific detection, VerifyEye will need:

1. A labeled logo dataset.
2. Training/validation data.
3. A trained YOLOv8 model.
4. Testing against legitimate and simulated phishing pages.
5. Performance evaluation.

---

## 10. Planned Risk Scoring

VerifyEye will eventually combine multiple signals.

Possible signals include:

```text
Credential form detected
        +
Password field detected
        +
External form destination
        +
Unknown/unverified domain
        +
Brand/logo similarity
        +
Other DOM indicators
        |
        v
    Risk Score
        |
        v
 Low / Medium / High
```

The final scoring method is still under development and should be documented when finalized.

---

## 11. Planned API

VerifyEye is expected to expose a simple API so that other OmniGuard components do not need to directly depend on internal Python files.

Planned endpoint:

```text
POST /analyze
```

Example request:

```json
{
  "url": "http://localhost:3000"
}
```

Example planned response:

```json
{
  "alert_type": "phishing",
  "risk_score": 0.91,
  "severity": "HIGH",
  "brand_detected": "ExampleBank",
  "credential_form": true,
  "external_submission": true
}
```

The exact schema should be agreed upon with the rest of the OmniGuard team before integration.

---

## 12. Team Integration

VerifyEye is not intended to operate as an isolated application.

### Rahim → Khoi

Khoi owns the encrypted C2 behavioral engine and telemetry pipeline.

Rahim's controlled adversary-emulation scenarios can generate test activity for Khoi's telemetry pipeline.

The teams should agree on:

- Timestamp format
- Scenario ID
- Source/destination information
- Required network telemetry
- Log format
- PCAP requirements, if needed
- Zeek/Suricata fields, if needed

---

### Rahim → Abu

Abu owns the Neo4j graph and air-gapped LLM triage.

VerifyEye should provide structured security alerts that can become graph entities or relationships.

Potential fields:

```json
{
  "alert_id": "...",
  "timestamp": "...",
  "url": "...",
  "domain": "...",
  "brand_detected": "...",
  "risk_score": 0.91,
  "severity": "HIGH",
  "credential_form": true
}
```

The final schema must be coordinated with Abu.

---

### Rahim → Aayush

Aayush owns the unified SOC dashboard and platform integration.

VerifyEye should provide an API response that can be displayed by the dashboard.

Potential dashboard information:

```text
Phishing Alert
Brand
URL
Risk Score
Severity
Credential Form
Timestamp
Evidence
```

The API contract should be agreed upon before final integration.

---

## 13. Development Roadmap

### Phase 1 — DOM Scanner

- [x] Set up Python
- [x] Install Playwright
- [x] Install Chromium
- [x] Create project structure
- [x] Create initial crawler
- [x] Detect HTML forms
- [x] Detect username/email fields
- [x] Detect password fields
- [x] Extract form actions

### Phase 2 — Visual Detection

- [ ] Capture webpage screenshots
- [ ] Set up YOLOv8
- [ ] Collect authorized test images
- [ ] Label logo dataset
- [ ] Train/test logo detector
- [ ] Return logo confidence

### Phase 3 — pHash

- [ ] Add reference-logo database
- [ ] Generate pHash values
- [ ] Compare detected logos
- [ ] Establish testing thresholds
- [ ] Record visual comparison results

### Phase 4 — VerifyEye Scoring

- [ ] Combine DOM results
- [ ] Combine YOLOv8 results
- [ ] Combine pHash results
- [ ] Create risk-scoring module
- [ ] Return structured alert

### Phase 5 — API

- [ ] Create FastAPI server
- [ ] Create `/analyze`
- [ ] Define request schema
- [ ] Define response schema
- [ ] Test API locally

### Phase 6 — Chrome MV3

- [ ] Create extension
- [ ] Detect credential forms
- [ ] Connect to VerifyEye API
- [ ] Display warning
- [ ] Lock high-risk credential forms
- [ ] Test authorized pages

### Phase 7 — OmniGuard Integration

- [ ] Coordinate telemetry with Khoi
- [ ] Coordinate graph schema with Abu
- [ ] Coordinate dashboard API with Aayush
- [ ] Perform end-to-end testing
- [ ] Document final integration

### Phase 8 — Final Demonstration

```text
Test User
   |
   v
Simulated Phishing Page
   |
   v
VerifyEye
   |
   +---- Playwright DOM Analysis
   |
   +---- YOLOv8 Logo Detection
   |
   +---- pHash Comparison
   |
   v
Risk Assessment
   |
   v
Chrome Credential Protection
   |
   v
OmniGuard Alert
   |
   +---- Neo4j / LLM Triage
   |
   +---- SOC Dashboard
```

---

## 14. Testing Strategy

All testing should use websites, machines, credentials, and network environments that the project team owns or has explicit permission to test.

### Test categories

#### Legitimate page

Expected:

```text
Credential form detected
+
Known/verified visual identity
+
Normal submission behavior
```

#### Simulated phishing page

Expected:

```text
Credential form detected
+
Suspicious or mismatched visual identity
+
Higher risk
+
Browser warning/blocking
```

#### Visual similarity test

Test:

```text
Legitimate logo vs. modified logo
```

and record the pHash distance.

#### DOM test

Test pages with:

- No forms
- Normal forms
- Login forms
- Password-only forms
- External form destinations

---

## 15. Security and Privacy Considerations

VerifyEye is a defensive security research project.

The system should:

- Use controlled test environments.
- Avoid collecting real user passwords.
- Avoid storing real credentials.
- Use simulated accounts for demonstrations.
- Avoid scanning systems without authorization.
- Keep test data separate from real credentials.
- Clearly label simulated attack scenarios.

The Chrome extension should focus on **detecting and preventing credential submission**, not collecting credentials.

---

## 16. GitHub Workflow

Recommended workflow:

```bash
git clone <repository-url>
cd verifyeye
```

Create a feature branch:

```bash
git checkout -b rahim-verifyeye
```

After making changes:

```bash
git status
git add .
git commit -m "Add VerifyEye DOM scanner"
git push origin rahim-verifyeye
```

For major features, use separate commits such as:

```text
Add Playwright DOM scanner
Add webpage screenshot capture
Add YOLOv8 detection framework
Add pHash comparison
Add VerifyEye risk scoring
Add VerifyEye API
Add Chrome MV3 extension
Add integration testing
```

Avoid committing:

```text
.env
passwords
API keys
private credentials
real user data
large unnecessary datasets
```

A `.gitignore` file should be added as the project grows.

---

## 17. Current Status

**Current working component:**

```text
Playwright DOM Scanner
```

**Currently being developed:**

```text
YOLOv8 + pHash Visual Detection
```

**Planned:**

```text
Risk Scoring
FastAPI
Chrome MV3
Adversary Emulation
OmniGuard Integration
```

---

## 18. Contributors

**OmniGuard SOC Team**

- Khoi — Encrypted C2 Behavioral Engine & Telemetry Pipeline
- Rahim — Visual Ingress Defense & Adversary Emulation
- Abu — Graph Correlation & Air-Gapped LLM Triage
- Aayush — Unified Dashboard & Platform Integration

---

## 19. License

This project is developed as a senior capstone project for educational and defensive cybersecurity research purposes.

If this repository is later made public, the team should add an appropriate license and review the repository for sensitive information before publication.
