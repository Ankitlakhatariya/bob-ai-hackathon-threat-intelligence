# ThreatLens Backend

**D2 Threat Intelligence Correlation & Alert Prioritisation Assistant**

Production-ready backend built with **Python 3.12+**, **FastAPI**, **Pydantic v2**, **SQLAlchemy 2.x**, **Supabase PostgreSQL**, **asyncpg**, and **Alembic**.

---

## 1. Project Overview

ThreatLens is a specialized threat correlation and alert prioritization engine for Security Operations Centers (SOC). It ingests security alerts from SIEMs, EDRs, network sensors, and threat intelligence feeds, normalizes the data, applies deterministic correlation rules to group related alerts into incidents, computes explainable risk scores (0–100), maps activities to verified MITRE ATT&CK techniques, and generates Bottom Line Up Front (BLUF) executive briefs.

---

## 2. Threat Correlation Engine

The Threat Correlation Engine combines thousands of individual security alerts into meaningful, cohesive threat groups using deterministic, explainable rules without relying on non-deterministic LLMs for core correlation.

### Correlation Dimensions & Evidence Factors
- **Same Hostname** (+0.35)
- **Same Username** (+0.30)
- **Same Source IP** (+0.30)
- **Same Destination IP** (+0.25)
- **Shared Indicators** (IPs, domains, hashes) (+0.35)
- **Shared MITRE ATT&CK Techniques** (+0.20)
- **Temporal Proximity** (scaled based on minute/hour interval)
- **Attack Kill-Chain Progression** (e.g. policy violation -> rule match -> process execution -> C2) (+0.15)
- **Threat Intelligence Attribution Match** (shared threat actor / campaign) (+0.30)

### Explainable Decision Guarantee
Every correlation link stores an explainable reason and numerical confidence score:
```json
{
  "correlationReason": "Same host 'srv-prod-app01' and Same user account 'deployer' | Observed within 8 minutes",
  "correlationScore": 0.85,
  "ruleName": "multi_attribute_correlation"
}
```

### Threat Model Attributes
- `threat_id`: Unique campaign identifier (`INC-1001` / `THREAT-1001`)
- `title`: Primary threat title
- `description` / `summary`: Consolidated incident narrative
- `severity`: Elevated severity (`critical`, `high`, `medium`, `low`)
- `risk_score`: Consolidated 0–100 risk score
- `confidence`: Statistical confidence score based on corroborating data sources
- `status`: Lifecycle state (`active`, `investigating`, `resolved`)
- `first_seen` / `last_seen`: Timeline bounds
- `alert_count`: Total member alerts
- `affected_assets`: Unique hosts, users, and IPs involved

---

## 3. Threat Intelligence Subsystem

The threat intelligence subsystem manages Indicators of Compromise (IOCs) and enriches alerts across the pipeline:
- **IP addresses**, **Domains**, **URLs**, **File Hashes**, **Email addresses**, **Malware indicators**
- Pluggable provider abstraction with anti-fabrication guarantees (returns `unknown` if unconfigured).
- Automated alert enrichment elevating risk and attaching threat context.

---

## 4. Multi-Source Alert Ingestion Subsystem

The ingestion engine accepts security events from heterogeneous telemetry sources without losing raw vendor evidence:
- **SIEM**, **EDR**, **Firewalls**, **Network Sensors / NIDS**, **Threat Feeds**, **Cyber Reports**
- 100% raw data preservation in `raw_data`.

---

## 5. Role-Based Access Control (RBAC)

The platform enforces 4 distinct roles with granular permissions:

| Role | Permissions & Capabilities | Restrictions |
|---|---|---|
| **Admin** | Full system administration, manage users, configure data sources, view all dashboards & telemetry. | None |
| **Analyst** | View & ingest alerts, investigate threats, run correlations, manage investigations, write analyst notes, flag false positives, generate BLUF reports. | Cannot manage platform users or system-level data sources. |
| **Commander** | View prioritized threats, read BLUF briefs, view high-level threat trends & strategic dashboards. | **Cannot modify raw alerts** or trigger low-level telemetry changes. |
| **Viewer** | Read-only access to monitoring overview, MITRE explorer, and threat trends. | Read-only across all modules. |

---

## 6. Setup Commands

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

## 7. Correlation & Threat Endpoints

- `POST /api/v1/threats/correlate`: Executes deterministic correlation engine across all unassigned and open alerts.
- `GET /api/v1/threats`: List correlated threat groups with pagination and sorting.
- `GET /api/v1/threats/{id}`: Detailed threat campaign summary and confidence score.
- `GET /api/v1/threats/{id}/alerts`: Retrieve member alerts in the threat.
- `GET /api/v1/threats/{id}/timeline`: Chronological progression timeline.
- `GET /api/v1/alerts/{id}/related`: Retrieve all correlated alerts with explainable reasons and scores.

---

## 8. Running Tests

Execute the automated pytest test suite:

```powershell
pytest -v
```
