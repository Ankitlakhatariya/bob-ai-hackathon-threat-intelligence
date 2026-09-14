# ThreatLens Backend

**D2 Threat Intelligence Correlation & Alert Prioritisation Assistant**

Production-ready backend built with **Python 3.12+**, **FastAPI**, **Pydantic v2**, **SQLAlchemy 2.x**, **Supabase PostgreSQL**, **asyncpg**, and **Alembic**.

---

## 1. Project Overview

ThreatLens is a specialized threat correlation and alert prioritization engine for Security Operations Centers (SOC). It ingests security alerts from SIEMs, EDRs, network sensors, and threat intelligence feeds, normalizes the data, applies deterministic correlation rules to group related alerts into incidents, computes explainable risk scores (0–100), maps activities to verified MITRE ATT&CK techniques, and generates Bottom Line Up Front (BLUF) executive briefs.

---

## 2. Multi-Source Alert Ingestion Subsystem

The ingestion engine accepts security events from heterogeneous telemetry sources without losing raw vendor evidence:

- **SIEM** (IBM QRadar, Splunk, Elastic, ArcSight)
- **EDR** (CrowdStrike Falcon, Microsoft Defender, Carbon Black)
- **Perimeter Firewalls** (Palo Alto Networks, Fortinet, pfSense)
- **Network Sensors & NIDS** (Zeek, Suricata, Snort)
- **Threat Intelligence Feeds** (MISP, AlienVault OTX, VirusTotal)
- **Cyber Sensors & Incident Reports**

### Common Normalized Internal Structure
Every event is transformed into a common model while preserving 100% of the raw vendor event in `raw_data`:

| Field | Description |
|---|---|
| `event_id` | Vendor event identifier |
| `source` | Normalized source enum (`siem`, `edr`, `network-sensor`, `threat-feed`) |
| `source_label` | Human-readable source label (e.g. `EDR Endpoint Agent`, `Firewall Sensor`) |
| `source_type` | Telemetry type (`SIEM`, `EDR`, `Firewall`, `Network Sensor`) |
| `timestamp` | UTC normalized timestamp |
| `event_type` | Categorized event type (e.g. `process_execution`, `security_rule_match`) |
| `severity` | Normalized enum (`critical`, `high`, `medium`, `low`) |
| `source_ip` / `destination_ip` | Network endpoints (Indexed) |
| `source_port` / `destination_port` | Transport ports |
| `protocol` | IP protocol (TCP, UDP, ICMP) |
| `hostname` | Affected host/workstation (Indexed) |
| `username` | User account (Indexed) |
| `domain` | Active Directory or DNS domain |
| `file_hash` | MD5 or SHA256 executable hash |
| `process_name` / `command_line` | Process details and command arguments |
| `url` | Web destination |
| `indicators` | Automatically extracted IOCs (IPs, domains, hashes) |
| `metadata` | Preserved metadata parameters |
| `raw_data` | Complete original JSON payload for audit and forensic inspection |

---

## 3. Role-Based Access Control (RBAC)

The platform enforces 4 distinct roles with granular permissions:

| Role | Permissions & Capabilities | Restrictions |
|---|---|---|
| **Admin** | Full system administration, manage users, configure data sources, view all dashboards & telemetry. | None |
| **Analyst** | View & ingest alerts, investigate threats, run correlations, manage investigations, write analyst notes, flag false positives, generate BLUF reports. | Cannot manage platform users or system-level data sources. |
| **Commander** | View prioritized threats, read BLUF briefs, view high-level threat trends & strategic dashboards. | **Cannot modify raw alerts** or trigger low-level telemetry changes. |
| **Viewer** | Read-only access to monitoring overview, MITRE explorer, and threat trends. | Read-only across all modules. |

---

## 4. Setup Commands

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

Apply the database schema, ingestion indexes, and authentication tables to Supabase PostgreSQL:

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

## 5. Alert Ingestion & Filtering API

### Ingestion Endpoints
- `POST /api/v1/alerts`: Ingest single security alert from any source (auto-normalizes, scores, extracts IOCs, and preserves `raw_data`).
- `POST /api/v1/alerts/bulk`: High-throughput ingestion of heterogeneous event batches.
- `PATCH /api/v1/alerts/{id}`: Update alert status, severity, or risk score.
- `DELETE /api/v1/alerts/{id}`: Delete alert and cascade associated telemetry events.

### Advanced Filtering Parameters (`GET /api/v1/alerts`)
- `?severity=critical|high|medium|low`
- `?source=siem|edr|network-sensor|threat-feed`
- `?status=open|investigating|resolved|false-positive`
- `?event_type=process_execution|security_rule_match`
- `?hostname=FINANCE-WS01`
- `?username=alice.smith`
- `?ip=198.51.100.50` (matches either source or destination IP)
- `?start_date=2026-09-01T00:00:00Z&end_date=2026-09-14T23:59:59Z`
- `?search=mimikatz` (free-text across IDs, hosts, IPs, descriptions)
- `?sort_by=risk_score&sort_order=desc` (supports `timestamp`, `risk_score`, `severity`, `id`)
- `?skip=0&limit=50` (pagination)

---

## 6. Running Tests

Execute the automated pytest test suite:

```powershell
pytest -v
```
