# ThreatLens — Frontend

> See the signal. Stop the threat.

Frontend for **D2 — Threat Intelligence Correlation & Alert Prioritisation Assistant**.

## Owner

- **Ayush** — Frontend Developer

## Planned Stack

- React 18 + Vite
- TypeScript
- Tailwind CSS
- React Router
- Lucide React (icons)
- Recharts (charts)

## Scope

- Security operations dashboard UI (alerts, incidents, MITRE ATT&CK, BLUF briefs, analytics)
- Frontend-only mock/demo data — clearly labeled as simulated
- API service layer as a **contract only** (for future backend/AI integration by Dhruv and Jaynadsinh)
- No real authentication, no real threat detection, no backend logic

## Planned Routes

| Route | Page |
|---|---|
| `/` | Landing |
| `/login` | Demo access |
| `/dashboard` | Security overview |
| `/alerts` | Alert intelligence |
| `/alerts/:alertId` | Alert investigation |
| `/incidents` | Threat correlation |
| `/mitre` | MITRE ATT&CK explorer |
| `/briefs` | BLUF investigation briefs |
| `/analytics` | Threat analytics |
| `/settings` | Settings / product info |

## Mock Data

All sample alerts, incidents, risk scores, and correlation confidence values are
**simulated demo data**. Nothing here represents a real security event.

## Run

```bash
cd src/frontend
npm install
npm run dev       # http://localhost:5173
```

## Structure

```
src/frontend/
  index.html
  src/
    main.tsx              # entry — theme + router providers
    App.tsx              # route table
    index.css            # Tailwind v4 + theme tokens (dark-first, light option)
    components/
      logo/              # ThreatLensLogo SVG
      theme/             # ThemeProvider (dark/light)
    pages/               # one folder per product page (built incrementally)
    types/               # API contracts (added with data layer)
    services/            # mock/API service layer (added with data layer)
```