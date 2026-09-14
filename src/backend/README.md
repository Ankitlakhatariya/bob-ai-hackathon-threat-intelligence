# ThreatLens Backend

**D2 Threat Intelligence Correlation & Alert Prioritisation Assistant**

Production-ready backend built with **Python 3.12+**, **FastAPI**, **Pydantic v2**, **SQLAlchemy 2.x**, **Supabase PostgreSQL**, **asyncpg**, and **Alembic**.

---

## 1. Project Overview

ThreatLens is a specialized threat correlation and alert prioritization engine for Security Operations Centers (SOC). It ingests security alerts from SIEMs, EDRs, network sensors, and threat intelligence feeds, normalizes the data, applies deterministic correlation rules to group related alerts into incidents, computes explainable risk scores (0–100), maps activities to verified MITRE ATT&CK techniques, and generates Bottom Line Up Front (BLUF) executive briefs.

---

## 2. Architecture

```
Frontend (React + Vite + TypeScript)
               ↓ HTTP (REST)
FastAPI Backend (/api/v1 + /api compatibility)
   ├── Routers (Alerts, Threats/Incidents, Dashboard, MITRE, BLUF, Intelligence, Investigations)
   ├── Services (CorrelationEngine, ThreatScoringEngine, ThreatIntelService, MitreService, BlufService)
   ├── Pydantic v2 Schemas (Automatic camelCase serialization matching frontend types)
   └── SQLAlchemy 2.x ORM
               ↓ asyncpg / async engine
Supabase PostgreSQL (Tables, Indexes, Foreign Keys)
               ↑ JWT Verification
Supabase Auth (Bearer Token)
```

---

## 3. Technology Stack

- **Python**: 3.12+ (tested on Python 3.13)
- **Web Framework**: FastAPI 0.115+
- **ASGI Server**: Uvicorn
- **ORM**: SQLAlchemy 2.0+ (AsyncIO + Declarative Base)
- **Database Driver**: `asyncpg` (Async) & `psycopg2-binary` (Sync for Alembic)
- **Database**: Supabase PostgreSQL
- **Migrations**: Alembic 1.13+
- **Data Validation & Serialization**: Pydantic v2
- **Authentication**: Supabase Auth / PyJWT
- **Testing**: Pytest & Pytest-AsyncIO

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

Create your `.env` file from the provided `.env.example`:

```powershell
cp .env.example .env
```

Open `.env` and fill in your Supabase connection parameters:

```ini
# Supabase Configuration
SUPABASE_URL=https://<your-project-ref>.supabase.co
SUPABASE_ANON_KEY=<your-anon-publishable-key>
SUPABASE_SERVICE_ROLE_KEY=<your-service-role-key>

# Asynchronous connection string for FastAPI (asyncpg)
SUPABASE_DB_URL=postgresql+asyncpg://postgres:<password>@db.<your-project-ref>.supabase.co:5432/postgres

# Synchronous connection string for Alembic migrations
DATABASE_URL_SYNC=postgresql://postgres:<password>@db.<your-project-ref>.supabase.co:5432/postgres

# Supabase Auth
JWT_AUDIENCE=authenticated
JWT_ISSUER=https://<your-project-ref>.supabase.co/auth/v1
SUPABASE_JWT_SECRET=<your-supabase-jwt-secret>

# Application Configuration
ENVIRONMENT=development
CORS_ORIGINS=http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173
PROJECT_NAME="D2 Threat Intelligence Correlation & Alert Prioritisation Assistant"
API_V1_STR=/api/v1
LOG_LEVEL=INFO
```

### Step 4: Run Database Migrations

Apply the initial schema to Supabase PostgreSQL using Alembic:

```powershell
alembic upgrade head
```

> **Note**: If Alembic has already run or if running directly with FastAPI, the application lifespan also automatically executes `Base.metadata.create_all` and seeds the baseline 14 demo alerts and 4 threat campaigns if the database is blank.

### Step 5: Start FastAPI Server

```powershell
uvicorn app.main:app --reload --port 5000
```

The server will start on `http://localhost:5000`.

### Step 6: Explore Interactive API Documentation

- **Swagger UI**: [http://localhost:5000/api/docs](http://localhost:5000/api/docs)
- **ReDoc**: [http://localhost:5000/api/redoc](http://localhost:5000/api/redoc)
- **OpenAPI JSON**: [http://localhost:5000/api/openapi.json](http://localhost:5000/api/openapi.json)

---

## 5. System Health Check

Verify that the application and database are healthy:

```powershell
curl http://localhost:5000/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "service": "D2 Threat Intelligence Correlation & Alert Prioritisation Assistant",
  "environment": "development"
}
```

---

## 6. API Endpoint Reference

### Authentication
- `GET /api/v1/auth/me`: Validates Supabase JWT Bearer token and returns user profile + application role.

### Dashboard
- `GET /api/v1/dashboard/overview`: Returns counts for `totalOpen`, `critical`, `incidentCount`, `falsePositiveReview`.
- `GET /api/v1/dashboard/severity-distribution`: Returns alert counts grouped by severity.
- `GET /api/v1/dashboard/alert-trends`: Returns volume time series for alerts and incidents.
- `GET /api/v1/dashboard/threat-trends`: Returns daily trend breakdown.
- `GET /api/v1/dashboard/top-techniques`: Returns top MITRE ATT&CK techniques seen across alerts.
- `GET /api/v1/dashboard/recent-threats`: Returns latest correlated threat campaigns.
- `GET /api/v1/dashboard/system-status`: Returns health status of SIEM, EDR, Network, and Feed telemetry.

### Alerts
- `GET /api/v1/alerts`: List alerts with filtering by `severity`, `status`, `source`, `search`, and pagination.
- `GET /api/v1/alerts/{id}`: Single alert detail.
- `GET /api/v1/alerts/trend?range=24h`: Trend volume for 24h, 7d, or 30d windows.
- `POST /api/v1/alerts`: Ingest single security alert.
- `POST /api/v1/alerts/bulk`: Bulk alert ingestion pipeline.
- `PATCH /api/v1/alerts/{id}`: Update alert status, risk score, or resolution.

### Threats (Correlated Incidents)
- `GET /api/v1/threats` *(also accessible via `/api/v1/incidents`)*: List correlated campaigns.
- `GET /api/v1/threats/{id}`: Single threat details with confidence score.
- `GET /api/v1/threats/{id}/alerts`: List of all alerts folded into this threat.
- `GET /api/v1/threats/{id}/timeline`: Chronological progression timeline.
- `GET /api/v1/threats/{id}/mitre`: Mapped MITRE ATT&CK techniques.
- `GET /api/v1/threats/{id}/risk`: Transparent risk factors breakdown.
- `POST /api/v1/threats/correlate`: Trigger correlation engine over unassigned alerts.

### MITRE ATT&CK
- `GET /api/v1/mitre` or `GET /api/v1/mitre/techniques`: Full verified technique catalog.
- `GET /api/v1/mitre/techniques/{id}`: Single technique details and tactics.
- `GET /api/v1/mitre/tactics`: List of 10 enterprise tactics.

### BLUF (Bottom Line Up Front)
- `GET /api/v1/bluf`: Map of all incident BLUF briefs keyed by incident ID.
- `GET /api/v1/bluf/{threat_id}`: BLUF brief for a specific threat.
- `POST /api/v1/bluf/{threat_id}/generate`: Generate or refresh executive summary.

### Threat Intelligence
- `GET /api/v1/intelligence/indicators`: List indicators of compromise (IOCs).
- `GET /api/v1/intelligence/lookup/{indicator}`: Fast IOC reputation lookup and alert cross-referencing.
- `POST /api/v1/intelligence/indicators`: Ingest new threat indicator.

### Investigations
- `GET /api/v1/investigations`: List investigation cases with status/priority filter.
- `POST /api/v1/investigations`: Create new investigation case.
- `PATCH /api/v1/investigations/{id}`: Update investigation status.
- `POST /api/v1/investigations/{id}/notes`: Append analyst notes with timestamps.
- `POST /api/v1/investigations/{id}/resolve`: Mark investigation resolved.
- `POST /api/v1/investigations/{id}/false-positive`: Flag as false positive.
- `POST /api/v1/investigations/{id}/escalate`: Escalate priority (P1–P4).

### Data Sources
- `GET /api/v1/data-sources`: Monitor health and lag of SIEM, EDR, and sensors.
- `POST /api/v1/data-sources`: Register a new telemetry source.
- `PATCH /api/v1/data-sources/{id}`: Update heartbeat and status.
- `DELETE /api/v1/data-sources/{id}`: Deregister source.

---

## 7. Running Tests

Execute the automated pytest test suite:

```powershell
pytest -v
```

---

## 8. Security Considerations

1. **No Hardcoded Secrets**: All credentials, database passwords, and keys are sourced from `.env`.
2. **Credential Redaction**: Structured logging automatically redacts passwords, bearer tokens, and API keys.
3. **CORS Configuration**: Restricts access to authorized frontend origins.
4. **JWT Verification**: Verifies signature, expiry, and audience claims against Supabase Auth.
5. **No Secrets Exposed to Frontend**: `SUPABASE_SERVICE_ROLE_KEY` and DB connection strings remain strictly on the backend.
