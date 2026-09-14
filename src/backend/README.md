# ThreatLens Backend

**D2 Threat Intelligence Correlation & Alert Prioritisation Assistant**

Production-ready backend built with **Python 3.12+**, **FastAPI**, **Pydantic v2**, **SQLAlchemy 2.x**, **Supabase PostgreSQL**, **asyncpg**, and **Alembic**.

---

## 1. Project Overview

ThreatLens is a specialized threat correlation and alert prioritization engine for Security Operations Centers (SOC). It ingests security alerts from SIEMs, EDRs, network sensors, and threat intelligence feeds, normalizes the data, applies deterministic correlation rules to group related alerts into incidents, computes explainable risk scores (0–100), maps activities to verified MITRE ATT&CK techniques, and generates Bottom Line Up Front (BLUF) executive briefs.

---

## 2. Threat Intelligence Subsystem

The threat intelligence subsystem manages Indicators of Compromise (IOCs) and enriches alerts across the pipeline:

### Supported Indicator Types
- **IP addresses** (`198.51.100.23`)
- **Domains** (`c2-beacon.darknet.org`)
- **URLs** (`https://evil-site.com/payload.exe`)
- **File Hashes** (MD5, SHA1, SHA256)
- **Email addresses** (`phisher@malicious.com`)
- **Malware & Tool identifiers** (`mimikatz.exe`, `Cobalt Strike`)

### Indicator Attributes
- `indicator`: Unique IOC string
- `indicator_type`: `ip`, `domain`, `url`, `hash`, `email`, `malware`
- `reputation`: `malicious`, `suspicious`, `benign`, `unknown`
- `confidence`: Numerical score (0–100)
- `source`: Attribution feed or analyst source
- `first_seen` / `last_seen`: Temporal tracking
- `tags`: Classification labels (`c2`, `ransomware`, `apt29`)
- `threat_actor`: Attribution group (e.g. `APT28 / Fancy Bear`)
- `campaign`: Named threat campaign (e.g. `Operation Ghostwriter`)
- `raw_intelligence`: Complete JSON intelligence context

### Pluggable Provider Abstraction
Threat intelligence providers implement `AbstractThreatIntelProvider`:
- Seamlessly replace or add third-party feeds (VirusTotal, AlienVault OTX, AbuseIPDB, MISP).
- **Strict Anti-Fabrication Guarantee**: If an external provider is not configured or an indicator is unknown, the system strictly returns `reputation: "unknown"`, `found: false` rather than guessing or pretending an indicator is malicious.

### Automated Alert Enrichment
When an alert is ingested via `POST /api/v1/alerts` or `POST /bulk`, its indicators are automatically checked against the intelligence catalog. Alerts containing verified malicious IOCs receive:
- **Risk Score Elevation** (+20 points)
- **Automatic Severity Promotion** (Low/Medium escalated to High)
- **Attached Intelligence Context** (`metadata_info["threat_intelligence"]`)

---

## 3. Multi-Source Alert Ingestion Subsystem

The ingestion engine accepts security events from heterogeneous telemetry sources without losing raw vendor evidence:
- **SIEM** (QRadar, Splunk, Elastic, ArcSight)
- **EDR** (CrowdStrike Falcon, Microsoft Defender, Carbon Black)
- **Perimeter Firewalls** (Palo Alto Networks, Fortinet, pfSense)
- **Network Sensors & NIDS** (Zeek, Suricata, Snort)
- **Threat Intelligence Feeds** (MISP, AlienVault OTX, VirusTotal)
- **Cyber Sensors & Incident Reports**

---

## 4. Role-Based Access Control (RBAC)

The platform enforces 4 distinct roles with granular permissions:

| Role | Permissions & Capabilities | Restrictions |
|---|---|---|
| **Admin** | Full system administration, manage users, configure data sources, view all dashboards & telemetry. | None |
| **Analyst** | View & ingest alerts, investigate threats, run correlations, manage investigations, write analyst notes, flag false positives, generate BLUF reports. | Cannot manage platform users or system-level data sources. |
| **Commander** | View prioritized threats, read BLUF briefs, view high-level threat trends & strategic dashboards. | **Cannot modify raw alerts** or trigger low-level telemetry changes. |
| **Viewer** | Read-only access to monitoring overview, MITRE explorer, and threat trends. | Read-only across all modules. |

---

## 5. Setup Commands

### Step 1: Create Virtual Environment

**Windows (PowerShell or CMD):**
```powershell
cd src/backend
python -m venv .venv
.venv\Scripts\activate
```

**macOS / Linux:**
```bash
cd src/backend
python3 -m venv .venv
source .venv/bin/activate
```

### Step 2: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables

Create your `.env` file from `.env.example`:

```powershell
copy .env.example .env
```

### Step 4: Run Database Migrations

```powershell
alembic upgrade head
```

### Step 5: Start FastAPI Server

```powershell
uvicorn app.main:app --reload --port 5000
```

- **Interactive Swagger UI**: `http://localhost:5000/api/docs`
- **Health Check**: `http://localhost:5000/health`

---

## 6. Threat Intelligence Endpoints

- `POST /api/v1/intelligence/indicators`: Ingest a verified IOC into the catalog.
- `GET /api/v1/intelligence/indicators`: Query indicators with filtering (`type`, `reputation`, `threat_actor`, `campaign`, `search`).
- `GET /api/v1/intelligence/indicators/{id}`: Detailed record with `raw_intelligence`.
- `GET /api/v1/intelligence/lookup/{indicator}`: Fast IOC reputation lookup and cross-referencing against existing alerts.

---

## 7. Running Tests

Execute the automated pytest test suite:

```powershell
pytest -v
```
