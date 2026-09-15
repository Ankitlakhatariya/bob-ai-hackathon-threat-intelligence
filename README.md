# ThreatLens

> Threat intelligence correlation workspace for analyst triage and investigation.

---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | threat-intelligence |
| **Track** | AI |
| **Team Lead** | sutariyadhruv20- 24dcs129@charusat.edu.in |
| **Members** | Ayush5112006 — 24dcs139@charusat.edu.in |

---

## 🎯 Problem Statement

> In 2–3 sentences: What problem does your project solve? Who experiences this problem?

Security teams need to correlate alerts, incidents, and threat intelligence across many signals. Analysts lose time switching between views and manually prioritizing the events that need attention.

---

## 💡 Solution

> In 2–3 sentences: What did you build? How does it solve the problem above?

ThreatLens brings alert triage, incident investigation, MITRE ATT&CK context, analyst briefs, and risk analytics into one React workspace with realistic mock threat data.

---

## ✨ Key Features

- **Alert triage:** Filter alerts by severity and status.
- **Incident investigation:** Explore incident details and relationships.
- **MITRE ATT&CK:** Review techniques associated with observed activity.
- **Analyst workflow:** Create briefs and inspect risk trends.
- **Themes:** Switch between light and dark presentation modes.

---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | TypeScript |
| **Frameworks** | React, Vite |
| **IBM Technologies** | IBM Bob |
| **Databases** | None in prototype; mock data is used |
| **Other** | Recharts, GitHub Actions |

---

## 📁 Repository Structure

```
├── src/                  # All source code
├── docs/                 # Written documentation
│   ├── problem-statement.md
│   ├── solution-overview.md
│   ├── architecture.md
│   └── setup-guide.md
├── demo/                 # Demo artifacts
│   ├── screenshots/      # App screenshots
│   └── demo-video-link.txt  # Link to demo video
├── presentation/         # Slide deck
└── submission.yaml       # Structured submission metadata
```

---

## ⚡ How to Run

> **Copy these exact steps from your [`docs/setup-guide.md`](docs/setup-guide.md)**

```bash
# 1. Clone the repo
git clone https://github.com/Ankitlakhatariya/bob-ai-hackathon-threat-intelligence.git
cd bob-ai-hackathon-threat-intelligence

# 2. Run with Docker
docker build -t threatlens .
docker run --rm -p 8080:80 threatlens

# Open http://localhost:8080
```

For local development without Docker:

```bash
# Install dependencies
cd src/frontend && npm install

# Start the Vite development server
npm run dev
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

## ⚠️ Known Limitations

> Be honest — judges appreciate transparency over overclaiming.

- Authentication and threat feeds are mocked for the prototype.
- No persistent database or production AI inference integration is included yet.
- The current WebSocket ConnectionManager is in-memory and suitable for a single-process hackathon deployment. If deployed with multiple Uvicorn workers, events will not automatically propagate between workers.
- The demo video and hosted deployment are not available yet.

---

## 🏅 What We're Most Proud Of

The cohesive analyst workflow is the strongest part: each view shares the same threat context and supports a realistic triage-to-investigation demo.

---
