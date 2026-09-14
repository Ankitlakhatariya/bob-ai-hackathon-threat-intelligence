# ThreatLens Backend

**D2 Threat Intelligence Correlation & Alert Prioritisation Assistant**

Production-ready backend built with **Python 3.12+**, **FastAPI**, **Pydantic v2**, **SQLAlchemy 2.x**, **Supabase PostgreSQL**, **asyncpg**, and **Alembic**.

---

## 1. Project Overview

ThreatLens is a specialized threat correlation and alert prioritization engine for Security Operations Centers (SOC). It ingests security alerts from SIEMs, EDRs, network sensors, and threat intelligence feeds, normalizes the data, applies deterministic correlation rules to group related alerts into incidents, computes explainable risk scores (0–100), maps activities to verified MITRE ATT&CK techniques, and generates Bottom Line Up Front (BLUF) executive briefs.

---

## 2. Threat Risk Scoring & Prioritisation Engine

The prioritisation engine distills thousands of noisy alerts into a ranked queue of threats that security analysts should investigate first.

### Transparent Scoring Factors (0–100)
The risk score is deterministic, reproducible, and mathematically calculated without relying on non-deterministic LLMs:

| Factor | Weight Range | Description |
|---|---|---|
| **`severity`** | 0 – 25 pts | Base severity of the incident (Critical=25, High=18, Medium=10, Low=5). |
| **`indicator_reputation`** | 0 – 20 pts | Presence of confirmed malicious IOCs (+20) or suspicious IOCs (+14). |
| **`correlation`** | 0 – 20 pts | Strength of correlation links (+10) and member alert volume (+10). |
| **`asset_criticality`** | 0 – 15 pts | Affected assets: Domain Controllers, Vaults, Backups, Production Gateways (+15), Servers (+10), Workstations (+5). |
| **`behavior`** | 0 – 20 pts | High-impact MITRE ATT&CK techniques (Credential Access, Lateral Movement, Ransomware encryption) and anomaly depth. |

### Strict Priority Bands
- **`0 – 24`**: **LOW** (routine review queue)
- **`25 – 49`**: **MEDIUM** (scheduled analyst triage)
- **`50 – 74`**: **HIGH** (investigate within shift)
- **`75 – 100`**: **CRITICAL** (immediate containment required)

### Stored Scoring Breakdown Example
```json
{
  "risk_score": 91,
  "priority": "CRITICAL",
  "factors": {
    "severity": 25,
    "indicator_reputation": 20,
    "correlation": 18,
    "asset_criticality": 15,
    "behavior": 13
  }
}
```

---

## 3. Threat Correlation Engine

The Threat Correlation Engine combines thousands of individual security alerts into meaningful, cohesive threat groups using deterministic, explainable rules:
- **Same Hostname** (+0.35)
- **Same Username** (+0.30)
- **Same Source IP** (+0.30)
- **Same Destination IP** (+0.25)
- **Shared Indicators** (IPs, domains, hashes) (+0.35)
- **Shared MITRE ATT&CK Techniques** (+0.20)
- **Temporal Proximity** (minute/hour intervals)
- **Attack Kill-Chain Progression** (+0.15)
- **Threat Intelligence Attribution** (+0.30)

---

## 4. Threat Intelligence Subsystem

- Manages IOCs: IPs, Domains, URLs, File Hashes, Email addresses, Malware indicators.
- Pluggable provider abstraction with anti-fabrication guarantees (returns `unknown` if unconfigured).
- Automated alert enrichment elevating risk and attaching threat context.

---

## 5. Multi-Source Alert Ingestion Subsystem

Ingests events from SIEM, EDR, Firewalls, Network Sensors, and Threat Feeds without data loss.

---

## 6. Role-Based Access Control (RBAC)

The platform enforces 4 distinct roles:
- **Admin**: Full system administration and data sources configuration.
- **Analyst**: Alert ingestion, threat investigation, correlation, and BLUF generation.
- **Commander**: Strategic overview, prioritized threats, and BLUF briefs (**cannot modify raw alerts**).
- **Viewer**: Read-only monitoring.

---

## 7. Setup Commands

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

## 8. Prioritisation & Threat Endpoints

- `GET /api/v1/threats/prioritized`: Returns threats sorted by risk score descending. Supports `?priority=CRITICAL|HIGH|MEDIUM|LOW` and `?min_score=...`.
- `GET /api/v1/threats/{id}/risk`: Detailed factors breakdown (`severity`, `indicator_reputation`, `correlation`, `asset_criticality`, `behavior`) and priority band.
- `POST /api/v1/threats/correlate`: Runs correlation engine.
- `GET /api/v1/threats`: List correlated threats.
- `GET /api/v1/threats/{id}`: Detailed threat campaign summary.
- `GET /api/v1/threats/{id}/alerts`: Retrieve member alerts in the threat.
- `GET /api/v1/threats/{id}/timeline`: Chronological progression timeline.
- `GET /api/v1/alerts/{id}/related`: Retrieve all correlated alerts with explainable reasons and scores.

---

## 9. Running Tests

Execute the automated pytest test suite:

```powershell
pytest -v
```
