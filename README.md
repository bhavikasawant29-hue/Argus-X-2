ARGUS-X
Evidence-Driven Security Telemetry Correlation & Attack Reconstruction

Connect the evidence. Reconstruct the attack.

ARGUS-X is a security investigation platform that transforms fragmented telemetry from authentication, endpoint, network, and application sources into a transparent, evidence-backed attack narrative.

Instead of asking only “Is this event suspicious?”, ARGUS-X asks:

What happened?
Which events belong to the same attack?
Why do we believe they are connected?
What evidence is missing?
What was affected?
What could have been prevented?
Problem

Modern cyberattacks leave evidence across multiple telemetry sources. Authentication logs may show suspicious access, endpoint logs may show execution or credential access, network logs may show lateral movement, and application logs may show access to critical assets.

Because these sources are fragmented, analysts must manually correlate events, reconstruct the attack sequence, determine the strength of evidence, and identify gaps.

ARGUS-X addresses this investigation problem by correlating heterogeneous telemetry and reconstructing a coherent attack narrative.

Target Users
Security Operations Center (SOC) Analysts
Incident Responders
Threat Hunters
Security Investigation Teams
Solution

ARGUS-X follows an evidence-centric investigation pipeline:

Raw Telemetry
      ↓
Ingestion
      ↓
Normalization
      ↓
Correlation
      ↓
Temporal Reasoning
      ↓
Attack Reconstruction
      ↓
Evidence Analysis
      ↓
Confidence + Completeness
      ↓
Evidence Gaps
      ↓
Impact Analysis
      ↓
Investigation & Recommendations

The system does not simply classify every suspicious-looking event as malicious. Events are evaluated based on entity relationships, temporal continuity, and attack-stage progression before becoming part of the reconstructed attack path.

Key Features
Core Reconstruction
Multi-source security telemetry ingestion
Common security-event normalization
Entity-based event correlation
Temporal reasoning
Multi-stage attack reconstruction
Attack timeline
Attack graph
Evidence Intelligence
Evidence-backed conclusions
Verified / Inferred / Unsupported evidence classification
Confidence scoring
Attack completeness scoring
Evidence-gap detection
Telemetry recommendations
Evidence traceability
Impact & Investigation
Attack infrastructure mapping
Blast-radius analysis
Counterfactual attack simulation
Attack replay
Evidence-grounded AI Investigator
Analyst investigation interface
What Makes ARGUS-X Different?
1. Evidence-Driven Reconstruction

ARGUS-X builds attack narratives from traceable telemetry evidence rather than presenting isolated alerts.

2. Confidence ≠ Completeness

ARGUS-X separates:

Confidence: How strongly is the reconstructed conclusion supported by available evidence?

Completeness: How much of the expected attack sequence is observable?

This allows the system to represent strong evidence even when parts of an attack remain unobservable.

3. Evidence-Gap Intelligence

When available telemetry cannot sufficiently support part of an investigation, ARGUS-X identifies the evidence gap and recommends additional telemetry that could reduce the uncertainty.

4. Explainable Correlation

The system provides the reasoning behind event relationships instead of treating correlation as a black box.

5. Grounded Investigation AI

The AI Investigator works from the reconstructed investigation context and supporting evidence. The AI layer assists analysts with investigation and explanation rather than acting as the primary detection engine.

6. Counterfactual Analysis

Analysts can ask what would happen if a particular attack stage had been blocked and examine downstream stages that could have been prevented according to the reconstructed dependency chain.

System Architecture
┌─────────────────────────────────────────────┐
│              SECURITY TELEMETRY             │
│ Authentication | Endpoint | Network | App   │
└──────────────────────┬──────────────────────┘
                       ↓
┌─────────────────────────────────────────────┐
│          INGESTION & NORMALIZATION          │
│        OCSF v1.1.0 Schema Normalizer        │
└──────────────────────┬──────────────────────┘
                       ↓
┌─────────────────────────────────────────────┐
│       ASSET INVENTORY & VULN ENRICHMENT     │
│       NVD CVE 2.0 | CISA KEV | FIRST EPSS   │
└──────────────────────┬──────────────────────┘
                       ↓
┌─────────────────────────────────────────────┐
│        CORRELATION & TEMPORAL REASONING     │
│      Entity Relationships + Time Context    │
└──────────────────────┬──────────────────────┘
                       ↓
┌─────────────────────────────────────────────┐
│          ATTACK RECONSTRUCTION ENGINE       │
│       Stage Mapping + Attack Path           │
└──────────────────────┬──────────────────────┘
                       ↓
┌─────────────────────────────────────────────┐
│            EVIDENCE & INTELLIGENCE          │
│ 4-Tier Evidence | Confidence | Gaps | Graph │
└──────────────────────┬──────────────────────┘
                       ↓
┌─────────────────────────────────────────────┐
│             IMPACT & INVESTIGATION          │
│ Blast Radius | Replay | What-If | AI / Det  │
└──────────────────────┬──────────────────────┘
                       ↓
┌─────────────────────────────────────────────┐
│             REACT INVESTIGATION UI          │
└─────────────────────────────────────────────┘

OCSF v1.1.0 Schema Alignment

ARGUS-X formally aligns its normalization engine with the Open Cybersecurity Schema Framework (OCSF) v1.1.0 specification:

Source Type        | OCSF Class UID | OCSF Class Name        | Category UID | Category Name
-------------------|----------------|------------------------|--------------|-----------------------------
Endpoint (Process) | 1007           | Process Activity       | 1            | System Activity
Endpoint (File)    | 1001           | File Activity          | 1            | System Activity
Authentication     | 3002           | Authentication         | 3            | Identity & Access Management
Network            | 4001           | Network Activity       | 4            | Network Activity
Application        | 6002           | Application Activity   | 6            | Application Activity

Standardized attributes:
- `category_uid` and `category_name`: Canonical OCSF domain categorization.
- `class_uid` and `class_name`: Standard event classification.
- `activity_id` and `type_uid`: Explicit activity IDs (Launch=1, Terminate=2, Logon=1, Logoff=2, Open=1, Close=2, Access=1, Other=99) and composite `type_uid` (`class_uid * 100 + activity_id`).
- `status_id`: 1=Success, 2=Failure, 0=Unknown based on action outcomes.
- `severity_id`: 0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical, 6=Fatal.
- `unmapped`: Preserves original event IDs, raw telemetry records, and normalization diagnostics for strict evidence auditability.

Vulnerability Intelligence & Asset Matching

ARGUS-X connects enterprise asset inventories with live vulnerability feeds:
- Sources: NVD CVE API 2.0, CISA Known Exploited Vulnerabilities (KEV), and FIRST EPSS API.
- Version-Aware Matching: Evaluates CPE criteria, inclusive/exclusive version boundaries (`version_start_including`, `version_end_excluding`), and pinned CPE releases using `packaging.version`.
- Match Status Taxonomy:
  - `version_affected`: Confirmed within affected version boundaries.
  - `version_not_affected`: Confirmed safe outside vulnerability boundaries.
  - `insufficient_data`: Vendor and product match, but version data is absent or inconclusive.
  - `product_mismatch` / `vendor_mismatch`: Non-matching software components.
- Threat Context: Enriched events include CVSS scores, KEV status, and EPSS scores as exploitation indicators (not proof of compromise).

Correlation Approach

ARGUS-X uses an explainable, deterministic correlation model:

Signal                                | Weight | Rationale
--------------------------------------|--------|-------------------------------------
Same Source Host                      | +3     | Co-located entity activity
Network Pivot Transition              | +3     | Lateral transition (prev. dest == next source)
Same Destination Host                 | +2     | Converging operations against target
Auth-to-Execution Sequence            | +2     | Immediate process launch following login
Same User Principal                   | +1     | Common identity attribution
Same Source IP                        | +1     | Common network ingress point
Within 60 Seconds                     | +1     | Strong temporal proximity

Events scoring 3 or higher are correlated, recording matched fields and natural-language transition rationales.

Evidence Model (4-Tier Taxonomy)

Status / Tier         | Definition
----------------------|---------------------------------------------------------------------------------
Corroborated          | Observed in primary log and corroborated across >=2 distinct telemetry sources
Directly Observed     | Directly recorded in telemetry with at least 1 supporting contextual signal
Inferred              | Supported by attack progression and temporal sequence; lacks supporting events
Insufficient Evidence | Lacks critical telemetry (e.g. missing user or host identification)


Demonstration Dataset

The working prototype uses a synthetic heterogeneous security telemetry dataset containing 809 events.

Source	Events
Authentication	232
Endpoint	223
Network	203
Application	151
Total	809

The dataset contains both attack-related activity and legitimate background noise.

ARGUS-X processes the complete telemetry set and reconstructs the coherent attack path rather than receiving only pre-selected attack events.

Demonstration Attack Path
PC-25
  ↓
SRV-02
  ↓
DB-01

The demonstrated reconstruction contains 8 coherent attack events, covering stages from initial access through database access.

Example Investigation

In the demonstration scenario, ARGUS-X reconstructs activity involving:

Authentication
      ↓
Process Execution
      ↓
Credential Access
      ↓
Lateral Movement
      ↓
Privilege Escalation
      ↓
Database Connection
      ↓
Database Access

The platform then provides:

Attack timeline
Attack graph
Evidence relationships
Confidence and completeness
Evidence gaps
Infrastructure map
Blast radius
Counterfactual analysis
Attack replay
AI-assisted investigation
Blast Radius

The Attack Graph answers:

How did the attack move?

The Blast Radius answers:

What was affected?

For the demonstration scenario:

PC-25 → SRV-02 → DB-01

ARGUS-X identifies:

Affected hosts
Compromised user
Critical asset
Attack origin
Compromised pivot
Final critical asset
Counterfactual Analysis

ARGUS-X supports hypothetical attack analysis.

Example:

What if lateral movement had been blocked?

The system evaluates the reconstructed dependency chain and identifies downstream stages that would have been prevented according to that hypothetical condition.

This helps analysts reason about potential prevention points rather than only explaining what already happened.

AI Investigator

The AI Investigator provides evidence-grounded answers to analyst questions.

Example:

Question:
How did the attacker reach DB-01?

Context:
Reconstructed attack timeline
Attack graph
Supporting evidence
Infrastructure relationships

The AI response is generated from the investigation evidence and is intended to distinguish supported conclusions from unsupported claims.

The core security analysis remains deterministic. The AI layer is used for investigation assistance and explanation.

Technology Stack
Frontend
React.js
Vite
Tailwind CSS
Backend
Python
FastAPI
Pydantic
Security Analytics
Pandas
NetworkX
Rule-Based Correlation
Temporal Reasoning
Threat Intelligence
MITRE ATT&CK
AI
OpenAI API
Evidence-Grounded Investigation AI
Data
CSV
JSON
Synthetic Security Telemetry
Deployment
Vercel
Render
Development
Git
GitHub
Project Structure
Argus-X/
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── context/
│   │   ├── services/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── index.css
│   ├── package.json
│   ├── vite.config.js
│   └── ...
│
├── backend/
│   ├── engine/
│   │   ├── correlation.py
│   │   ├── reconstruction.py
│   │   ├── evidence.py
│   │   ├── scoring.py
│   │   ├── gaps.py
│   │   ├── graph.py
│   │   ├── blast_radius.py
│   │   ├── infrastructure.py
│   │   ├── recommendations.py
│   │   ├── counterfactual.py
│   │   ├── investigator.py
│   │   └── replay.py
│   │
│   ├── ingestion/
│   │   └── loader.py
│   │
│   ├── models/
│   │   └── event.py
│   │
│   ├── main.py
│   ├── requirements.txt
│   └── tests/
│
├── data/
│   ├── raw/
│   │   ├── authentication_logs.csv
│   │   ├── endpoint_logs.csv
│   │   ├── network_logs.csv
│   │   └── application_logs.csv
│   └── README.md
│
├── docs/
│
├── screenshots/
│
├── README.md
└── .gitignore
Installation
Prerequisites
Python 3.10+
Node.js 18+
npm
Git
Clone Repository
git clone https://github.com/bhavikasawant29-hue/Argus-X.git
cd Argus-X
Backend Setup
cd backend
pip install -r requirements.txt

Create a .env file inside the backend directory:

```env
OPENAI_API_KEY=your_openai_api_key

# Optional Hugging Face configuration for log text classification:
HF_TOKEN=your_huggingface_user_access_token
HF_MODEL_ID=facebook/bart-large-mnli
```

Never commit the .env file or API tokens to Git.

Start the backend:

uvicorn backend.main:app --reload

The API will be available at:

http://localhost:8000

API documentation:

http://localhost:8000/docs
Frontend Setup

Open another terminal:

cd frontend
npm install
npm run dev

The frontend will be available at the local Vite development URL shown in the terminal.

The frontend communicates with the FastAPI backend through the configured API URL.

API Endpoints

Endpoint                  | Method | Purpose
--------------------------|--------|---------------------------------------------------------------
`/api/health`             | GET    | Backend service health check
`/api/demo`               | POST   | Execute full analysis on benchmark synthetic dataset (809 events)
`/api/analyze`            | POST   | Ingest and analyze uploaded multipart CSV telemetry files
`/api/inventory`          | GET    | Retrieve enterprise asset catalog and installed software profiles
`/api/ocsf/normalize`     | POST   | Normalize batch telemetry events to OCSF v1.1.0 with diagnostics
`/api/vulnerabilities`    | GET    | Retrieve ingested CVE records, KEV status, and EPSS scores
`/api/vulnerabilities/ingest` | POST | Trigger live feed ingestion (NVD CVE, CISA KEV, FIRST EPSS)
`/api/investigate`        | POST   | Evidence-grounded investigation (LLM + deterministic fallback)
`/api/counterfactual`     | POST   | Counterfactual simulation (simulate blocking specific stage)
`/api/ml/anomalies`       | POST   | Run Isolation Forest statistical anomaly detection on telemetry
`/api/ml/analyze-log`     | POST   | Zero-shot log message text classification via hosted Hugging Face
`/api/ml/train`           | POST   | Train and persist updated Isolation Forest baseline artifact
`/api/mitre/techniques`   | GET    | Query local MITRE ATT&CK Enterprise STIX techniques catalog
`/api/mitre/map`          | POST   | Evidence-based mapping of telemetry to candidate ATT&CK techniques

FastAPI interactive Swagger documentation is available at:
`/docs`

Testing & Verification

Execute the automated test suites from the `backend/` directory:

```bash
cd backend

# 1. OCSF v1.1.0 Compliance & Normalization Suite
python test_ocsf_compliance.py

# 2. Asset Inventory & Vulnerability Enrichment Suite
python test_asset_enrichment.py

# 3. Real CVE Version Boundaries & Matcher Suite
python test_vulnerability_matcher.py

# 4. Correlation, Reconstruction & 4-Tier Evidence Suite
python test_reconstruction_engine.py

# 5. AI Investigator Resilience & Deterministic Fallback Suite
python test_investigator_resilience.py

# 6. Core Evidence & Pipeline Integration Suite
python test_evidence.py

# 7. ML Isolation Forest Anomaly Detection Suite
python test_anomaly_detector.py

# 8. Hugging Face Log Classifier & Secret Hygiene Suite
python test_hf_log_analyzer.py

# 9. MITRE ATT&CK STIX Dataset & Evidence Mapping Suite
python test_mitre_mapper.py

# 10. FastAPI Endpoints & Integration Suite
python test_api.py
```

### Machine Learning & Threat Intelligence Architecture

#### 1. ML-Based Anomaly Detection (`backend/engine/anomaly_detector.py`)
- **Model**: Scikit-learn `IsolationForest` (unsupervised outlier detection, `n_estimators=100`, configurable `contamination=0.05`, `random_state=42`).
- **Feature Extraction**: 10 engineered features across all four telemetry sources:
  - Source type numeric encoding (Authentication, Endpoint, Network, Application)
  - Log-scaled user and host event frequencies
  - Failed authentication burst counts
  - Numerical severity mapping (Informational to Critical)
  - Inter-arrival time deltas between events
  - Distinct destination host count (lateral scanning indicator)
  - External or lateral pivot flags
  - Privileged/script action keyword indicators
  - Payload / context string length
- **Persistence**: Fitted pipeline saved using `joblib` into `backend/data/models/isolation_forest_baseline.joblib` (excluded from Git).
- **Semantics**: Anomaly scores quantify statistical divergence from baseline patterns. **An anomaly score is NOT an attack probability.**

#### 2. Pretrained Hugging Face Integration (`backend/engine/hf_log_analyzer.py`)
- **Model**: Hosted Hugging Face Inference API utilizing `facebook/bart-large-mnli` (or configured via `HF_MODEL_ID`).
- **Configuration**: `HF_TOKEN` read from backend environment. Zero credential exposure: tokens are never exposed in exceptions, responses, or client payloads.
- **Resilience**: 10-second timeout, input truncation to 512 characters, and graceful degradation returning status `"token_missing"` or `"provider_error"` without crashing the pipeline.
- **Semantics**: Text classification labels are candidate hypotheses requiring telemetry corroboration.

#### 3. MITRE ATT&CK Enterprise Mapping (`backend/engine/mitre_mapper.py`)
- **Dataset**: Machine-readable STIX 2.1 Enterprise ATT&CK matrix cached locally in `backend/data/mitre_attack/enterprise_techniques_cache.json` with dynamic update support from `attack-stix-data`.
- **Evidence-Based Rule Engine**: Evaluates reconstructed events against technical telemetry criteria (process command line, LSASS memory indicators, SMB/RDP ports, auth tokens).
- **Status Taxonomy**:
  - `evidence_supported_candidate`: Technical indicators and cross-source corroboration observed.
  - `candidate_requires_review`: Behavioral pattern detected but specific technical proofs are partial.
  - `unmapped`: Telemetry lacks necessary technical detail.

Deployment
Frontend

Deployed using Vercel.

Backend

Deployed using Render.

The production architecture separates the React frontend from the FastAPI analysis backend.

User
 ↓
Vercel
 ↓
React Frontend
 ↓
FastAPI API
 ↓
ARGUS-X Analysis Engine
 ↓
Telemetry + Evidence
AI-Assisted Development

AI tools were used during development for:

Architecture discussion
Code development assistance
Debugging
UI iteration
Documentation
Development workflow support

Tools used include:

ChatGPT
Claude
GitHub Copilot
Google Gemini
Antigravity

The team reviewed, tested, modified, and integrated the resulting implementation.

AI assistance does not replace the team's understanding of the implementation.

Third-Party Resources

ARGUS-X uses the following external technologies and resources:

React.js
Vite
Tailwind CSS
FastAPI
Pydantic
Pandas
NetworkX
MITRE ATT&CK
OpenAI API

The demonstration dataset is synthetic security telemetry created for the project.

Research & References

The project was informed by research and security frameworks including:

MITRE ATT&CK
NIST SP 800-61 Rev. 3
SLEUTH: Attack Scenario Reconstruction
Tactical Provenance Analysis
Microsoft Sentinel
Elastic Security

These resources provide research, security-framework, and industry context for the project.

Limitations

ARGUS-X is a hackathon prototype and currently uses deterministic, rule-based correlation and reconstruction logic.

Current limitations include:

Correlation rules are predefined.
Reconstruction coverage depends on represented telemetry patterns.
Real-world deployments would require additional telemetry parsers and attack patterns.
Larger datasets and broader attack scenarios would be required for production-scale evaluation.
Missing telemetry can make portions of an attack unobservable.

The system explicitly exposes evidence gaps rather than assuming missing information.

Future Scope

Potential future improvements include:

Additional telemetry formats such as Syslog and JSON
Broader endpoint and network telemetry coverage
Adaptive correlation
Larger attack-scenario evaluation datasets
More comprehensive MITRE ATT&CK mapping
Scalable distributed event processing
Advanced entity resolution
Automated incident reporting
Additional prevention and response integrations


Team
Team Binary Brains

Sanchi Mane
Bhavika Sawant

Problem Statement: PS19
Problem: Security Telemetry Correlation & Attack Reconstruction Engine
Event: Kurukshetra 2.0 HACKFEST 2026

Links

GitHub Repository:
https://github.com/bhavikasawant29-hue/Argus-X

Live Application:
https://argusx-one.vercel.app/

Project Philosophy
EVIDENCE > ASSUMPTION

TRACEABILITY > GUESSWORK

EXPLAINABILITY > BLACK BOX

UNCERTAINTY > FALSE CERTAINTY
ARGUS-X

From fragmented telemetry to a defensible attack story.