# Multi-Vendor Security — AI-Driven Network Security Compliance Auditor
### SIH 2026 · Problem Statement 26155 · NTRO

Vendor-neutral network security auditing: heterogeneous device configs in,
**Canonical Security Baseline Model** in the middle, Compliance + PQC +
Security Analytics + CVE engines, evidence-backed findings and PDF reports out.

Repo: https://github.com/Satish-vaishyar/Multi-Vendor-Security

## Architecture at a glance

```
Browser (frontend/ React 19 + Vite + Tailwind, or backend /ui console)
   │  HTTP → /api/v1 only (never touches devices, DB, LLM directly)
   ▼
backend/  (FastAPI, 49 routes — 42 under /api/v1 + meta/UI/docs)
   ├──▶ okf/     knowledge: 102 properties, 70 controls, 5 frameworks,
   │              CVE/CPE/version-range engine, Featherless gpt-oss-120b
   │              gateway with offline fallback
   └──▶ models/  ML M1–M13 (M1 detect, M2 OOV, M3 mapping, M5 validate,
                 M6 risk, M7 fleet, M8 dedup in the audit path;
                 M9–M13 research-only)
```

Remediation **Apply is always a dry run** (`device_touched: false`) by design —
no flow in this repo contacts real network devices.

## Folders

| Folder | Role | Start with |
|---|---|---|
| `backend/` | **Runnable API**: unified FastAPI service (`/api/v1`) + HTML test console (`/ui`). Built with `uv`. Reuses `okf/` + `models/`, duplicates nothing | `backend/README.md` → `backend/docs/SETUP.md` → `backend/docs/USER_GUIDE.md` |
| `frontend/` | **Runnable UI**: React 19 + Vite + Tailwind app (Dashboard, Upload, Audits, Findings, Vulnerabilities, PQC, Analytics, Remediation, Training, Reports) | `FRONTEND_GUIDE.md` → `frontend/README.md` |
| `docs/` | Problem specification: `arch.md` (10-layer architecture), `api.md` (API contract), `models.md` (M1–M13), `okf.md` + `cve_okf.md` (knowledge design), `tech_stack.md`, `frontend.md` | `docs/arch.md`, `docs/api.md` |
| `okf/` | Operational Knowledge Framework: 102 properties, 70 controls, 5 frameworks, compliance + CVE/CPE/version-range engines, Featherless `gpt-oss-120b` LLM gateway (offline fallback), test console | `okf/README.md` |
| `models/` | ML models M1–M13, datasets, trained artifacts, performance report | `models/README.md`, `models/MODELS_PERFORMANCE.md` |
| `test-files/` | 7 sample configs (Cisco ×2, Juniper, Fortinet, Palo Alto, Arista + edge-case file) for the demo flow | `test-files/README.md` |

## Prerequisites

- **Backend**: Python 3.12+, [`uv`](https://docs.astral.sh/uv/) package manager
- **Frontend**: Node.js 18+ and npm
- **Docker** (optional, for `docker-compose.yml` production stack)
- **Database**: none for local dev (in-memory stores); Supabase Postgres for production (see `DEPLOY.md`)

## Run it (5 minutes, local dev)

```powershell
git clone https://github.com/Satish-vaishyar/Multi-Vendor-Security.git
cd Multi-Vendor-Security

# Terminal 1 — backend
cd backend
copy .env.example .env   # defaults work offline; add LLM/NVD keys later
uv sync
uv run pytest -q
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
# console: http://127.0.0.1:8000/ui   API docs: http://127.0.0.1:8000/docs

# Terminal 2 — frontend
cd frontend
npm install
npm run dev              # open the URL Vite prints (default http://localhost:5173)
```

Demo login: `admin@example.com` / `admin123` (change via `ADMIN_EMAIL` / `ADMIN_PASSWORD` in `backend/.env`).

> **New here?** Follow [`APPLICATION_SETUP.md`](APPLICATION_SETUP.md) — complete
> setup for every module (`backend/`, `frontend/`, `okf/`, `models/`, Docker),
> env reference, verification checklist, and troubleshooting.

> The frontend points at the backend via `frontend/.env.development`
> (`VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1`).
> If your backend runs elsewhere, edit that file and restart `npm run dev`.

## 10-minute demo script

1. Login with the demo account.
2. Upload `test-files/01-cisco-insecure-router.txt` → Start Audit (all frameworks + all engines) → note the score.
3. Upload `test-files/02-cisco-secure-router.txt` → same audit → confirm its score is higher.
4. Bulk-upload `03`, `04`, `05`, `06` → one audit each → vendor auto-detection across Juniper / Fortinet / Palo Alto / Arista.
5. Upload `07-edge-unknown-tokens.txt` → **Unknown Tokens** tab → **Training** page (Suggest mapping → Approve).
6. From an audit: Vulnerabilities → PQC → Analytics → Reports → download PDF.
7. Compliance finding → Remediation → Approve → dry-run apply (`device_touched: false`).

Full click-paths: `FRONTEND_GUIDE.md`. Backend console + curl flows: `backend/docs/USER_GUIDE.md`.

## Run it (production, Docker)

```powershell
copy backend\.env.example backend\.env   # fill JWT_SECRET, DATABASE_URL, CORS_ORIGINS
docker compose up --build
# Frontend http://localhost:8080 | Backend http://localhost:8000
```

Checklist (env, Supabase schema, verification, security notes): `DEPLOY.md`.

## Documentation index

| Doc | Contents |
|---|---|
| `APPLICATION_SETUP.md` | **Complete setup for all modules** — prerequisites, backend, frontend, okf, models, Docker, env reference, verification, troubleshooting |
| `backend/docs/SETUP.md` | Prerequisites, install with `uv`, `.env` keys, running, verification, troubleshooting |
| `backend/docs/USER_GUIDE.md` | Starting the server, using the console tab-by-tab, training-loop demo, curl flows |
| `backend/docs/API_REFERENCE.md` | All 49 live endpoints (42 under `/api/v1`) with methods, payloads, examples |
| `backend/docs/IMPLEMENTATION.md` | Spec traceability: `arch.md` layers L1–L10 and `api.md` groups → code files |
| `backend/docs/RTM_PS.md` | SIH-26155 problem statement → implementation (10/10 features) |
| `backend/docs/TRM_ARCH.md` | `arch.md` → implementation traceability |
| `backend/docs/BUILD_STATUS.md` | Built vs missing vs extra w.r.t. the problem statement (gap analysis) |
| `backend/docs/ARCHITECTURE.md` | 2-page architecture (SIH evaluation deliverable) |
| `FRONTEND_GUIDE.md` | Frontend user guide: login → upload → audit → results → remediation |
| `DEPLOY.md` | Production hosting checklist (env, Supabase, Docker, verification) |
| `test-files/README.md` | What each sample config proves |

## Tech summary

Python + FastAPI + Pydantic · in-memory stores for local dev (PostgreSQL via Supabase in
production) · ReportLab PDFs · JWT auth · `uv` for env/deps · pytest for tests ·
React 19 + Vite + Tailwind + React Query + Zustand (frontend).
Heavy lifting reused from `okf/` (102 properties, 70 controls, 5 frameworks,
CVE/CPE/version-range engine, Featherless `gpt-oss-120b` gateway with offline fallback)
and `models/` (M1 detect, M2 OOV, M3 mapping, M5 validate, M6 risk, M7 fleet, M8 dedup).

## Security notes

- **Secrets live only in `backend/.env`** (git-ignored, never committed, excluded from
  Docker images via `backend/.dockerignore`). Copy from `backend/.env.example` and fill in.
- Never commit API keys (`FEATHERLESS_API_KEY`, `NVD_API_KEY`) or the Supabase
  `DATABASE_URL` — if a secret ever leaks into git history, **rotate it immediately**.
- Production requires a strong `JWT_SECRET` (the dev default is rejected), explicit
  `CORS_ORIGINS` (no `*`), and `REQUIRE_AUTH=true`. See `DEPLOY.md`.
