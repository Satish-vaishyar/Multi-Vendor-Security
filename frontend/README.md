# Frontend — Security Compliance Auditor UI (SIH 26155)

React 19 + Vite + Tailwind + React Query + Zustand app in this folder.
It talks **only** to the FastAPI backend (`../backend/`, 42 routes under `/api/v1`).
The frontend never touches network devices, the database, the LLM, or ML models
directly — everything goes through the REST API. Uploads are analyzed locally and
remediation Apply is always a dry run (`device_touched: false`).

Full user walkthrough (login → upload → audit → results → remediation):
see [`../FRONTEND_GUIDE.md`](../FRONTEND_GUIDE.md).

## Prerequisites

- Node.js 18+ and npm
- Backend running at `http://127.0.0.1:8000` (or update `VITE_API_BASE_URL` below)

## Quickstart

```powershell
cd frontend
npm install
npm run dev     # open the URL Vite prints (default http://localhost:5173)
```

Backend (separate terminal, from repo root):

```powershell
cd backend
copy .env.example .env
uv sync
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Demo login: `admin@example.com` / `admin123` (email pre-filled — type the password).

## Environment variables

| File | Purpose | Default |
|---|---|---|
| `.env.development` | Backend URL for `npm run dev` | `VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1` |
| `.env.production` | Backend URL baked in at `npm run build` / Docker build | `VITE_API_BASE_URL=https://api.yourdomain.com/api/v1` (edit before building) |

After editing env files, restart `npm run dev`. For Docker/single-domain hosting,
`docker-compose.yml` accepts a `VITE_API_BASE_URL` build arg — see `../DEPLOY.md`.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Start Vite dev server with HMR |
| `npm run build` | Type-check (`tsc -b`) + production build to `dist/` |
| `npm run preview` | Preview the production build locally |
| `npm run lint` | Lint with Oxlint |

## Project layout

```
frontend/
  src/
    api/        # axios client + endpoint wrappers (token handling, base URL from env)
    pages/      # Login, Dashboard, Upload, ConfigurationDetails, AuditProgress,
                # AuditResults, Compliance, Vulnerabilities, PQC, Analytics,
                # Findings, Remediation, Training, Assets, Reports, Settings
    components/ # shared UI (layout, sidebar, cards, tables, dialogs)
    store/      # zustand auth/session state
    hooks/      # react-query data hooks
  public/       # static assets
  tests/        # playwright e2e (see playwright.config.ts)
```

## Backend dependency map (where UI data comes from)

| UI area | Backend endpoints |
|---|---|
| Login / Settings | `POST /api/v1/auth/login`, `GET /api/v1/auth/me` |
| Upload | `POST /api/v1/configurations/upload`, `/bulk-upload`, `GET /{id}/canonical-ir`, `GET /{id}/unknowns` |
| Audits | `POST /api/v1/audits`, `GET /api/v1/audits/{id}`, `GET /results` |
| Findings / Compliance / Vulns / PQC / Analytics | `GET /api/v1/findings…`, engine endpoints (see `../backend/docs/API_REFERENCE.md`) |
| Remediation | approve + dry-run apply endpoints (`device_touched: false` always) |
| Training | unknown-token queue: suggest mapping → approve |
| Reports | generate + download PDF audit report |

Authoritative endpoint list: `../backend/docs/API_REFERENCE.md`
(live spec always at `http://127.0.0.1:8000/docs` when the backend runs).

## Troubleshooting

| Symptom | Fix |
|---|---|
| Login fails / `Network Error` | Backend isn't running or URL mismatch. Check `http://127.0.0.1:8000/docs` loads and `.env.development` matches it. Restart `npm run dev` after edits. |
| Upload rejected (empty / too large) | Backend limit is 5 MB, non-empty UTF-8 text; `.txt .cfg .conf .json .xml .text .log` natively accepted (others accepted with a warning). |
| Audit stuck in QUEUED/RUNNING | Backend runs audits synchronously in-process; keep the backend terminal alive and retry. Check backend logs. |
| No findings / score looks wrong | Confirm **Canonical IR** tab is non-empty and frameworks/engines were checked at Start Audit. Re-run with all boxes ticked. |
| Blank pages / 404 on refresh | SPA — serve via `npm run dev`, not by opening files directly. |
| Port 5173 busy | `npm run dev -- --port 5174`. No backend change needed. |
