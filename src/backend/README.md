# ThreatLens — Backend

> Express + MongoDB (MERN stack) API server for the ThreatLens threat intelligence platform.

## Owner

- **Dhruv** — Backend Developer
- **Jaynadsinh** — AI/ML Developer
- **Ankit** — Cybersecurity & Integration Lead

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js |
| Framework | Express.js |
| Database | MongoDB + Mongoose |
| Dev tools | nodemon, morgan |

## Quick Start

```bash
# 1. Install dependencies
cd src/backend
npm install

# 2. Create .env from the template
cp .env.example .env
# Edit .env with your MongoDB URI

# 3. Seed the database with demo data
npm run seed

# 4. Start the dev server (hot-reload via nodemon)
npm run dev
```

The server starts on `http://localhost:5000` by default.

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Health check |
| GET | `/api/alerts` | List alerts (filter: `?severity=`, `?status=`, `?source=`) |
| GET | `/api/alerts/trend?range=` | Alert trend data (24h / 7d / 30d) |
| GET | `/api/alerts/:id` | Get single alert |
| POST | `/api/alerts` | Create alert |
| PATCH | `/api/alerts/:id` | Update alert |
| DELETE | `/api/alerts/:id` | Delete alert |
| GET | `/api/incidents` | List incidents |
| GET | `/api/incidents/:id` | Get single incident |
| POST | `/api/incidents` | Create incident |
| PATCH | `/api/incidents/:id` | Update incident |
| DELETE | `/api/incidents/:id` | Delete incident |
| GET | `/api/mitre` | List MITRE ATT&CK techniques |
| GET | `/api/mitre/:id` | Get single technique |
| GET | `/api/briefs` | Get all analyst briefs (keyed by incident ID) |
| GET | `/api/briefs/:incidentId` | Get brief for a specific incident |
| POST | `/api/briefs` | Create a brief |
| GET | `/api/dashboard/summary` | Dashboard summary stats |
| GET | `/api/dashboard/system-status` | System health indicators |

## Project Structure

```
src/backend/
├── package.json
├── .env.example
├── .gitignore
└── src/
    ├── server.js              ← Entry point
    ├── config/
    │   └── db.js              ← MongoDB connection
    ├── models/
    │   ├── Alert.js
    │   ├── Incident.js
    │   ├── MitreTechnique.js
    │   └── Brief.js
    ├── controllers/
    │   ├── alertController.js
    │   ├── incidentController.js
    │   ├── mitreController.js
    │   ├── briefController.js
    │   └── dashboardController.js
    ├── routes/
    │   ├── alertRoutes.js
    │   ├── incidentRoutes.js
    │   ├── mitreRoutes.js
    │   ├── briefRoutes.js
    │   └── dashboardRoutes.js
    ├── middleware/
    │   └── errorHandler.js
    └── seeds/
        └── seed.js            ← Demo data seeder
```

## Notes

- The frontend documents expected API response shapes in `src/frontend/src/types/` and the service layer in `src/frontend/src/services/`. Endpoints are aligned with those contracts.
- All error responses follow the `ApiErrorBody` shape: `{ error: { code, message, details? } }`.
- Frontend is consuming **mock data** until these endpoints are live — update `src/frontend/src/services/mockApi.ts` to point at these URLs.