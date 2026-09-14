# ThreatLens Backend

**D2 Threat Intelligence Correlation & Alert Prioritisation Assistant**

Production-ready backend built with **Python 3.12+**, **FastAPI**, **Pydantic v2**, **SQLAlchemy 2.x**, **Supabase PostgreSQL**, **asyncpg**, and **Alembic**.

---

## 1. Project Overview

ThreatLens is a specialized threat correlation and alert prioritization engine for Security Operations Centers (SOC). It ingests security alerts from SIEMs, EDRs, network sensors, and threat intelligence feeds, normalizes the data, applies deterministic correlation rules to group related alerts into incidents, computes explainable risk scores (0–100), maps activities to verified MITRE ATT&CK techniques, and generates Bottom Line Up Front (BLUF) executive briefs.

---

## 2. Architecture & Security

```
Frontend (React + Vite + TypeScript)
               ↓ HTTP (Bearer JWT)
FastAPI Backend (/api/v1 + /api compatibility)
   ├── Routers (Auth, Alerts, Threats, Dashboard, MITRE, BLUF, Intelligence, Investigations)
   ├── RBAC Layer (Admin, Analyst, Commander, Viewer role-based permissions)
   ├── Services (CorrelationEngine, ThreatScoringEngine, ThreatIntelService, MitreService, BlufService)
   ├── Pydantic v2 Schemas (Automatic camelCase serialization matching frontend types)
   └── SQLAlchemy 2.x ORM
               ↓ asyncpg / async engine
Supabase PostgreSQL (Tables, Indexes, Foreign Keys)
               ↑ JWT Verification
Supabase Auth (Bearer Token)
```

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

Apply the database schema and authentication tables to Supabase PostgreSQL:

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

## 5. Authentication Endpoints

- `POST /api/v1/auth/register`: Register user with secure password hashing (`email`, `password`, `full_name`, `role`).
- `POST /api/v1/auth/login`: Authenticate and receive `access_token` and `refresh_token`.
- `POST /api/v1/auth/refresh`: Exchange refresh token for new access and refresh token pair.
- `POST /api/v1/auth/logout`: End session and log audit event.
- `GET /api/v1/auth/me`: Returns the authenticated user's profile, role, and active permissions array.

---

## 6. Running Tests

```powershell
pytest -v
```
