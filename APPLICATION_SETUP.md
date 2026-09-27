# Application Setup - complete guide (all modules)

Covers every module of this repo: `backend/`, `frontend/`, `okf/`, `models/`,
`docs/`, `test-files/`, plus the Docker production stack.
Commands below are **PowerShell** (Windows 10/11). On macOS/Linux use `cp`
instead of `copy` and `export` instead of `$env:`.

Repo: https://github.com/Satish-vaishyar/Multi-Vendor-Security

## 0. Prerequisites

| Need | Version / note | Check |
|---|---|---|
| Git | any recent | `git --version` |
| Python via `uv` | `uv` 0.5+; project uses Python 3.12+ (`uv` downloads it automatically) | `uv --version` |
| Node.js + npm | Node 18+ | `node --version` |
| Docker (optional) | only for the production stack (§7) | `docker --version` |
| Disk / RAM | ~1 GB for `backend/.venv` (numpy/scipy/sklearn/torch), 4 GB RAM free | - |
| Network | only for first-time installs and optional live LLM/NVD calls - the app itself runs **fully offline** | - |

Install `uv` (Windows):
```powershell
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
# then restart the shell
```

## 1. Get the code

```powershell
git clone https://github.com/Satish-vaishyar/Multi-Vendor-Security.git
cd Multi-Vendor-Security
```

Expected layout (all modules must stay siblings - `backend/` finds `okf/`
and `models/` via `OKF_DIR=../okf`, `MODELS_DIR=../models`):

```
Multi-Vendor-Security\
  backend/    # runnable FastAPI API + /ui test console (START HERE for running)
  frontend/   # runnable React UI
  okf/        # knowledge layer (library used by backend; optionally standalone)
  models/     # ML training/eval + committed trained artifacts (library used by backend)
  docs/       # problem specification (read-only)
  test-files/ # 7 sample configs for the demo flow (read-only)
  docker-compose.yml  # production stack (backend + frontend, Supabase DB)
  DEPLOY.md   # production checklist
```

## 2. Module: `backend/` (the API - required)

The unified FastAPI service. Serves **60 routes** (56 under `/api/v1` + meta/UI/docs),
orchestrates `okf/` + `models/`, owns auth, audit pipeline, findings, PDF reports.

```powershell
cd backend
copy .env.example .env   # defaults work offline; see env table in §8
uv sync --group dev      # creates .venv/, installs runtime + pytest/httpx
uv run python ../models/scripts/download_minilm.py  # one-time vendoring (~90 MB) of the MiniLM embedding weights into models/artifacts/minilm/ - needs network once; the app reuses it offline on every start
uv run pytest -q         # tests must pass before first run
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
# add --reload for development auto-reload
# if port 8000 is taken: --port 8001
```

Verify:

| URL | Expected |
|---|---|
| http://127.0.0.1:8000/health | `{"success":true,"status":"healthy"}` |
| http://127.0.0.1:8000/docs | interactive OpenAPI (try every endpoint) |
| http://127.0.0.1:8000/ui | HTML test console (6 tabs; API-only, talks to `/api/v1`) |

Demo login: `admin@example.com` / `admin123` (override via `ADMIN_EMAIL` /
`ADMIN_PASSWORD` in `backend/.env`).

Module docs: `backend/README.md` (overview) → `backend/docs/SETUP.md`
(install/config/troubleshoot) → `backend/docs/USER_GUIDE.md` (console + curl flows)
→ `backend/docs/API_REFERENCE.md` (all 60 endpoints).

> First run downloads the MiniLM embedding model (~90 MB, HuggingFace cache) so
> M2/M3/M8 use the real 384-dim backbone the artifacts were trained on. Without
> network they fall back to TF-IDF (M1/M5/M6/M7 unaffected).

## 3. Module: `frontend/` (the React UI - required for UI demo)

React 19 + Vite + Tailwind + React Query + Zustand. Talks **only** to the backend
REST API - never to devices, DB, LLM, or models directly.

```powershell
cd frontend
npm install
npm run dev   # open the URL Vite prints (default http://localhost:5173)
```

Configure which backend it talks to:

| File | Used by | Default |
|---|---|---|
| `.env.development` | `npm run dev` | `VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1` |
| `.env.production` | `npm run build` / Docker build | `VITE_API_BASE_URL=https://api.yourdomain.com/api/v1` - edit before building |

Restart `npm run dev` after editing env files. Other scripts: `npm run build`
(type-check + production bundle to `dist/`), `npm run preview`, `npm run lint`.

User walkthrough: `FRONTEND_GUIDE.md`. Dev notes: `frontend/README.md`.

## 4. Module: `okf/` (Operational Knowledge Framework - library, no setup needed)

Vendor-neutral knowledge layer: 103 properties, 82 controls, 5 frameworks
(CIS/NIST/STIG/ISO27001/CERT-In), compliance + CVE/CPE/version-range engines, and the
**single** LLM gateway (`llm_gateway.py`, Featherless `gpt-oss-120b` with offline
fallback). **No install step is required** - `backend/` imports it via `OKF_DIR`.

Run its standalone pieces only if you are developing the knowledge layer itself:

```powershell
cd okf
copy .env.example .env   # optional; only needed for LIVE LLM calls (FEATHERLESS_API_KEY)
uv sync                  # only if okf is opened as its own project (has requirements.txt)
uv run pytest -q         # knowledge/engine unit tests
uv run uvicorn main:app --host 127.0.0.1 --port 8100   # optional standalone OKF service
```

Design docs: `docs/okf.md`, `docs/cve_okf.md`; traceability: `okf/RTM_OKF_CVE.md`.

## 5. Module: `models/` (ML M1-M13 - library, no setup needed)

Model sources (`src/m1_vendor.py` … `m13_vqe.py`), training scripts, datasets,
evaluation, and the **committed trained artifacts** (`artifacts/*.pkl`,
`m3_index.pkl`, …) that `backend/` loads at runtime via `MODELS_DIR`.
**No install step is required** - artifacts ship with the repo and Python deps
(sklearn/xgboost/torch/…) come from `backend/`'s `uv sync`.

Re-train / re-evaluate only if you are developing the models:

```powershell
cd models
# uses backend/.venv (or its own venv from requirements.txt for quantum libs):
..\backend\.venv\Scripts\python.exe src\evaluate_all.py
```

References: `models/README.md`, `models/MODELS_PERFORMANCE.md`, `models/RTM_MODELS.md`;
spec: `docs/models.md`. In the audit path: M1 detect, M2 OOV, M3 mapping,
M5 validate, M6 risk, M7 fleet, M8 dedup. M9-M13 are research-only.

## 6. Module: `docs/` + `test-files/` (read-only, no setup)

- `docs/`: problem specification - read `arch.md` (10-layer architecture) and
  `api.md` (API contract) first; then `models.md`, `okf.md`, `cve_okf.md`,
  `tech_stack.md`, `frontend.md`.
- `test-files/`: 7 sample configs for the demo (see `test-files/README.md`):
  `01` insecure Cisco (low score) vs `02` secure Cisco (high score),
  `03-06` Juniper/Fortinet/Palo Alto/Arista bulk-upload,
  `07` unknown-token edge case for the Training page.

## 7. Production stack (Docker + Supabase - optional)

```powershell
copy backend\.env.example backend\.env   # fill JWT_SECRET, DATABASE_URL, CORS_ORIGINS
docker compose up --build
# Frontend http://localhost:8080 | Backend http://localhost:8000
```

Full checklist (env, `backend/app/db/schema.sql` on Supabase, verification,
security notes): `DEPLOY.md`.

## 8. Environment reference

Backend (`backend/.env` - **git-ignored, never commit**; copy from `.env.example`):

| Variable | Required? | Effect |
|---|---|---|
| `JWT_SECRET` | yes, change it (≥32 random chars; dev default rejected in production) | signs login tokens |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | no (default `admin@example.com` / `admin123`) | demo login |
| `FEATHERLESS_API_KEY` | no - offline heuristics without it | live `gpt-oss-120b` parsing via `okf/llm_gateway.py` |
| `NVD_API_KEY` | no - local seed CVE KB works; keyless retry on rejection | raises NVD sync rate limits |
| `DATABASE_URL` | production only (Supabase Postgres URL) | in-memory stores are used for local dev |
| `CORS_ORIGINS` / `TRUSTED_HOSTS` | production (`*` is dev-only) | allowed frontend origins |
| `REQUIRE_AUTH` | `true` in production | enforce JWT on `/api/v1` (except login) |
| `OKF_DIR` / `MODELS_DIR` | no (defaults `../okf`, `../models`) | repoint only if you moved the folders |
| `HOST` / `PORT` | no (defaults `127.0.0.1` / `8000`) | bind address |

Frontend (tracked placeholders, safe to commit - contain URLs only, no secrets):
`frontend/.env.development` → local backend; `frontend/.env.production` → public API URL.

OKF standalone (`okf/.env` - git-ignored): `FEATHERLESS_API_KEY`,
`FEATHERLESS_BASE_URL`, `OKF_MODEL`, `OKF_VERSION`. Only needed for live LLM
calls outside the backend.

## 9. End-to-end verification (10 minutes)

1. Backend tests green: `cd backend; uv run pytest -q`.
2. Backend up: `/health` → healthy; `/docs` loads.
3. Frontend up: `npm run dev` → login with demo account → Dashboard.
4. Upload `test-files/01-cisco-insecure-router.txt` → Start Audit (all frameworks +
   all engines) → note low score; repeat with `02-cisco-secure-router.txt` →
   confirm higher score.
5. Bulk-upload `03-06` → vendor auto-detection right (Juniper/Fortinet/Palo Alto/Arista).
6. `07-edge-unknown-tokens.txt` → Unknown Tokens tab → Training page → Suggest → Approve.
7. Audit → Vulnerabilities, PQC, Analytics → Reports → download PDF.
8. Compliance finding → Remediation → Approve → dry-run apply shows
   `device_touched: false` (devices are never touched).

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| `uv : command not found` | install `uv`, then **restart** the shell |
| `Address already in use` (:8000) | another server running - use `--port 8001` (and point UI env at it) |
| `ModuleNotFoundError` in backend | stale `.venv` - delete `backend/.venv/`, re-run `uv sync --group dev` |
| `sklearn InconsistentVersionWarning` | harmless (artifacts trained on 1.9.0); M1 still classifies correctly |
| `InsecureKeyLengthWarning` (JWT) | dev `JWT_SECRET` too short - set a long random value |
| `/ui` shows `{"detail":"Not Found"}` | uvicorn started from wrong directory - `cwd` must be `backend/` |
| LLM features say `offline` | no `FEATHERLESS_API_KEY` - expected without key |
| Frontend `Network Error` on login | backend down or `VITE_API_BASE_URL` mismatch - check `/docs` loads, restart `npm run dev` |
| Audit stuck QUEUED/RUNNING | audits run in-process - keep backend terminal alive, retry |
| Port 5173 busy | `npm run dev -- --port 5174` |
| Windows AV flags `.venv` | exclude the project folder from real-time scanning |

## 11. Security rules (read before contributing)

- Secrets live **only** in `backend/.env` (and `okf/.env` for standalone OKF work) -
  both git-ignored and excluded from Docker images. Never commit `*_API_KEY` or `DATABASE_URL`.
- If a secret ever leaks into git history, **rotate it immediately**.
- Production: strong `JWT_SECRET`, explicit `CORS_ORIGINS` (no `*`), `REQUIRE_AUTH=true`.
- Remediation Apply is dry-run by design - no code path may contact real devices.
