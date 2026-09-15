# ThreatLens

> D2 Threat Intelligence Correlation & Alert Prioritisation Assistant — A full-stack SOC workspace for real-time multi-source telemetry ingestion, deterministic alert correlation, MITRE ATT&CK mapping, and prioritised BLUF investigation briefs for commanders.

---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | threat-intelligence |
| **Track** | AI |
| **Team Lead** | Dhruv Sutariya - 24dcs129@charusat.edu.in |
| **Members** | Ayush Thummar, Ankit Lakhatariya, JaynadSinh Gohil |

---

## 🎯 Problem Statement

Defence and enterprise SOC analysts receive thousands of fragmented alerts daily from SIEM systems, EDR agents, network sensors, firewalls, and threat intelligence feeds — all in disparate formats. No human team can triage them all manually. Missing a genuine threat is catastrophic, while chasing false positives exhausts critical incident response resources. Threat assessments must also be delivered in structured BLUF (Bottom Line Up Front) format so commanders and decision-makers get actionable visibility in minutes.

---

## 💡 Solution

ThreatLens ingests multi-source security feeds through an automated normalisation engine, correlates related alerts into explainable incident campaigns using a deterministic multi-dimensional correlation engine, maps attacker tactics and techniques to the Enterprise MITRE ATT&CK framework, and generates prioritised executive BLUF summaries powered by structured AI inference with rule-based failover.

---

## ✨ Key Features

- **Multi-Source Ingestion & Normalisation:** Ingests SIEM (QRadar, Splunk), EDR (CrowdStrike, Defender), Network Sensors (Zeek, Suricata), Firewalls, and Threat Feeds (MISP, OTX) with automatic IOC extraction (IPs, domains, hashes).
- **Deterministic Correlation Engine:** Evaluates shared assets, IOCs, MITRE techniques, and kill-chain stages to group alerts into threat campaigns without hallucination risk.
- **Explainable Risk Scoring & Prioritisation:** Deterministic 0–100 risk scoring factoring asset criticality, IOC reputation, severity, and behavioral patterns mapped into commander priority bands (P1 Critical to P4 Low).
- **MITRE ATT&CK Behavioral Mapping:** Automated mapping of telemetry to verified enterprise tactics and techniques with granular evidence chains.
- **Executive BLUF Investigation Briefs:** Structured Bottom Line Up Front summaries with impact evaluation, technical triggers, and recommended containment steps.
- **Real-Time Telemetry & WebSockets:** Live threat updates broadcasted via authenticated WebSockets directly to the SOC dashboard.
- **Analyst Triage & Case Management:** Comprehensive investigation workflows, false-positive handling, and analyst note collaboration.

---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Frontend** | React 19, TypeScript 5.8, Vite 7, TailwindCSS v4, Recharts, Lucide Icons |
| **Backend API** | Python 3.13, FastAPI, Uvicorn, Pydantic v2, Pydantic-Settings |
| **Database & ORM** | Supabase PostgreSQL 17.6, SQLAlchemy 2.0 (Asyncpg & Psycopg2), Alembic (11 migrations) |
| **AI / LLM Engine** | OpenAI (GPT-4o-mini) Structured Outputs with Pydantic schemas, Tenacity Retries & Sanitization Guardrails |
| **Security & Auth** | Supabase Auth, JWT (HS256), Bcrypt (`passlib`), Role-Based Access Control (RBAC), In-Memory Rate Limiting |
| **Real-Time** | WebSockets (`/api/v1/ws/threats`) with JWT claim validation & broadcast manager |
| **Deployment** | Vercel (Full-stack Serverless Python + Vite React SPA), Docker |
| **IBM Technologies** | IBM Bob AI |
| **Testing & CI** | Pytest (60/60 passing tests across 10 test suites), GitHub Actions |

---

## 📁 Repository Structure

```
├── api/                  # Vercel serverless entrypoint (index.py)
├── src/
│   ├── backend/          # FastAPI Python application
│   │   ├── alembic/      # Database migrations (001 - 011)
│   │   ├── app/
│   │   │   ├── api/      # REST & WebSocket API routers
│   │   │   ├── core/     # Security, config, RBAC, rate-limiting
│   │   │   ├── models/   # SQLAlchemy ORM models
│   │   │   ├── schemas/  # Pydantic data contracts
│   │   │   └── services/ # Ingestion, Correlation, Scoring, MITRE, BLUF, LLM
│   │   └── tests/        # 60 automated test suites
│   └── frontend/         # React 19 Vite application
│       └── src/
│           ├── components/ # AppShell, Badges, Theme, Logo
│           ├── hooks/      # useAlerts, useThreatUpdates (WS)
│           ├── pages/      # Dashboard, Alerts, Incidents, Mitre, Briefs, Analytics, Login
│           ├── services/   # apiClient.ts (Unified API client)
│           └── types/      # TypeScript data models
├── docs/                 # Architectural and setup documentation
├── demo/                 # Demo videos and screenshots
├── vercel.json           # Vercel deployment routing & build config
└── requirements.txt      # Root Python dependencies
```

---

## ⚡ How to Run

### 1. Run with Docker

```bash
# Clone the repository
git clone https://github.com/Ankitlakhatariya/bob-ai-hackathon-threat-intelligence.git
cd bob-ai-hackathon-threat-intelligence

# Build and run with Docker
docker build -t threatlens .
docker run --rm -p 8080:80 threatlens

# Open http://localhost:8080
```

### 2. Local Development

```bash
# Backend setup (Terminal 1)
cd src/backend
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Frontend setup (Terminal 2)
cd src/frontend
npm install
npm run dev

# Open http://127.0.0.1:5173
```

### 3. Run Automated Tests

```bash
cd src/backend
python -m pytest tests/ -v
```

---

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🌐 Live Demo | [See demo/live-demo-url.txt](demo/live-demo-url.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/](presentation/) |

---

## 🏅 What We're Most Proud Of

1. **Deterministic Correlation Reliability:** Core alert correlation and 0–100 risk scoring are deterministic and explainable — eliminating LLM hallucinations from operational SOC triage.
2. **Enterprise MITRE ATT&CK Mapping:** Automatic behavioral inference maps incoming telemetry directly to verified tactics and techniques with granular evidence chains.
3. **Actionable Executive BLUF Summaries:** High-level commanders receive instant, prioritized Bottom Line Up Front briefs with clear tactical focus.
4. **100% Test Coverage:** Complete 60-test automated verification suite covering multi-source normalisation, correlation logic, RBAC, JWT security, and LLM edge cases.
