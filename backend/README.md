# Orbit - Multi-Vendor Security: backend

Unified backend + test console for the NTRO problem statement:
upload network configs from any vendor → normalize to a vendor-neutral
**Canonical Security Baseline Model** → analyze with four engines
(**Compliance, PQC, Security Analytics, CVE**) → unified findings, risk,
remediation and PDF reports. Also hosts auth (JWT/MFA/SSO/RBAC/tenancy),
background jobs, recurring audits, webhooks and read-only collection.

Repo: https://github.com/Qirova-Technologies/Orbit-Multi-Vendor-Security

## Repository layout

```
Orbit-Multi-Vendor-Security/
  backend/     # ← START HERE: unified FastAPI service + HTML test console (uv project)
    README.md            # this file - overview + quickstart
    docs/
      SETUP.md           # installation, configuration, running, troubleshooting
      USER_GUIDE.md      # starting the app + using it (UI walkthrough + CLI)
      API_REFERENCE.md   # every endpoint exposed once the server is up (106 routes)
      IMPLEMENTATION.md  # arch.md / api.md → code traceability
    app/                 # FastAPI service (api, core, parsers, engines, services, db)
    worker.py            # background job worker (collection, CVE sync, retention, schedules)
    cli.py               # migrate, check-config, anonymize, corpus-eval, catalogue-import
    frontend/index.html  # test console - talks ONLY to /api/v1 over HTTP
    tests/               # end-to-end pytest suite (506 tests)
  docs/        # product + operations guides (+ the read-only SIH spec)
  okf/         # Operational Knowledge Framework (controls, compliance + CVE engines, LLM gateway)
  models/      # ML models M1-M13 + datasets + trained artifacts
```

## How the pieces fit

```
Browser (React app) ──HTTP /api/v1 only──▶ backend/ ──┬──▶ okf/    (knowledge: 103 properties,
                                                            82 controls, CVE engine, LLM gateway)
                                                └──▶ models/ (M1 detect, M2 OOV, M3 mapping, M5 validate,
                                                            M6 risk, M7 fleet, M8 dedup; artifacts/*.pkl)
```

- `backend/` **orchestrates**; it contains no control rules, no CVE data, no trained
  models of its own - those live in `okf/` and `models/` and are reused, never duplicated.
- The frontend never imports backend code and never touches the LLM, NVD, database
  or ML models directly - everything goes through the REST API (`api.md` §34).

## Quickstart (5 minutes)

```powershell
cd backend
copy .env.example .env        # defaults work offline; add keys later (see SETUP.md)
uv sync                       # install dependencies into .venv
uv run pytest -q              # full pytest suite should pass (506 tests collected)
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
uv run python -m app.worker   # optional: jobs, schedules, collection, CVE sync
```

Then open:

| URL | What |
|---|---|
| http://127.0.0.1:8000/docs | Interactive OpenAPI docs (try every endpoint in the browser) |
| http://127.0.0.1:8000/health | Health check → `{"success":true,"status":"healthy"}` |

Demo login: `admin@example.com` / `admin123` (change in `.env`).

## 60-second demo (in the web app, `frontend/`)

1. **Upload & Audit** → *Create demo asset* → paste the insecure Cisco sample
   (pre-loaded) → *Upload* (detects `CISCO / IOS-XE / 17.9.2`) → tick frameworks → *Run audit*.
2. See compliance score, per-framework scores, ~80 unified findings
   (compliance + CVE + security + PQC), then *Load evidence chain* for the
   why-did-this-fail view.
3. **Reports** → *Generate* → *Download* the PDF audit report.

Full click-paths, expected results and CLI equivalents: `docs/USER_GUIDE.md`.

## Documentation index

| Doc | Contents |
|---|---|
| `docs/SETUP.md` | Prerequisites, install with `uv`, `.env` keys, running, verification, troubleshooting |
| `docs/USER_GUIDE.md` | Starting the server, using the console tab-by-tab, training-loop demo, curl flows |
| `docs/API_REFERENCE.md` | All 106 documented endpoints (103 under `/api/v1`) with methods, payloads and examples |
| `docs/RTM_PS.md` | Official SIH26155 problem statement → implementation (10/10 features ✅) |
| `docs/TRM_ARCH.md` | `arch.md` §1-§64 → implementation (41 ✅, 7 prototype-scoped 🟡) |
| `docs/BUILD_STATUS.md` | Built vs missing vs extra w.r.t. the PS (gap analysis) |
| `docs/ARCHITECTURE.md` | 2-page architecture (SIH evaluation deliverable) |
| `docs/IMPLEMENTATION.md` | Spec traceability: `arch.md` layers L1-L10 and `api.md` groups → code files |

## Tech summary

Python + FastAPI + Pydantic · in-memory stores (dev) / PostgreSQL + pgvector
(prod, see `../DEPLOY.md`) · Postgres job queue + `worker.py` · ReportLab PDFs ·
JWT auth with TOTP MFA, OIDC SSO, 5-role RBAC, tenant scoping + RLS · `uv` for
env/deps · pytest for tests. Heavy lifting reused from `okf/`
(103 properties, 82 controls, 5 frameworks, CVE/CPE/version-range engine,
Featherless `gpt-oss-120b` gateway with offline fallback) and `models/`
(M1 detect, M2 OOV, M3 mapping, M5 validate, M6 risk, M7 fleet, M8 dedup;
M9-M13 research-only, never in the audit path).
