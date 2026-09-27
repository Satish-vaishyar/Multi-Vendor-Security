# Setup - install, configure, run, verify, troubleshoot

## 1. Prerequisites

| Need | Version / note |
|---|---|
| Windows 10/11 + PowerShell 5.1 (or any OS with PowerShell/pwsh) | commands below are PowerShell |
| `uv` package manager | check with `uv --version` (used here: 0.5.29). Install: `powershell -c "irm https://astral.sh/uv/install.ps1 \| iex"`, then restart the shell |
| Python | `uv` downloads it automatically (project uses 3.13); a system Python 3.12+ also works |
| Disk / RAM | ~1 GB for `.venv` (numpy/scipy/sklearn), 4 GB RAM free |
| Network | only needed for first `uv sync` and optional live LLM/NVD calls - the app itself runs **fully offline** |

> First run downloads the MiniLM embedding model (~90 MB, HuggingFace cache) so
> M2/M3/M8 use the real 384-dim backbone the artifacts were trained on. Without
> network, they fall back to TF-IDF (M1/M5/M6/M7 unaffected).

Sibling folders must sit next to `backend/` (default layout, no action needed):

```
F:\Multi-vendor\backend\   ← you are here
F:\Multi-vendor\okf\       ← knowledge layer (controls, CVE engine, LLM gateway)
F:\Multi-vendor\models\    ← ML artifacts (m1_*.pkl, m6_xgb.pkl, …)
```

If you moved them, point `OKF_DIR` / `MODELS_DIR` in `.env` at the new locations.

## 2. Install

```powershell
cd F:\Multi-vendor\backend
uv sync --group dev        # creates .venv/, installs runtime + pytest/httpx
```

## 3. Configure (`.env`)

```powershell
copy .env.example .env
notepad .env
```

| Variable | Required? | Effect |
|---|---|---|
| `JWT_SECRET` | **yes, change it** | signs login tokens (dev default works, but use ≥32 random chars) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | no (defaults `admin@example.com` / `admin123`) | demo login |
| `FEATHERLESS_API_KEY` | no | without it: offline heuristic parsing (all tests pass). With it: live `gpt-oss-120b` unknown-vendor parsing via `okf/llm_gateway.py` - verified live (0.96-0.98 confidence suggestions) |
| `NVD_API_KEY` | no | raises NVD sync rate limits for `POST /vulnerabilities/sync`. If the key is rejected by NVD, sync automatically retries keyless - verified live |
| `OKF_DIR` / `MODELS_DIR` | no | defaults `../okf`, `../models` |
| `HOST` / `PORT` | no | informational defaults `127.0.0.1` / `8000` |

The frontend takes **no secrets** - it logs in through `/api/v1/auth/login`
and sends `Authorization: Bearer <token>`.

## 4. Run

```powershell
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
# --reload  (add for development auto-reload)
```

If port 8000 is taken: `--port 8001` (and point the `/ui` base-URL box at it).

## 5. Verify

```powershell
uv run pytest -q            # 56 tests (flows + every error branch + engine/model units)
uv run pytest -q --cov     # 100% statement coverage over app/ (fail_under=100 enforced)
```

Then in a browser: `http://127.0.0.1:8000/health` → `{"success":true,"status":"healthy"}`,
`/ui` for the console, `/docs` for interactive OpenAPI.

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `uv : command not found` | install `uv`, then **restart** PowerShell |
| `Address already in use` | another server on :8000 - use `--port 8001` |
| `ModuleNotFoundError: src...` | stale `.venv` from before the import-bridge fix - delete `.venv/`, re-run `uv sync` |
| `sklearn InconsistentVersionWarning` (unpickling) | harmless (artifacts trained on 1.9.0, running 1.9.1); M1 still classifies correctly |
| `InsecureKeyLengthWarning` (JWT) | dev `JWT_SECRET` < 32 bytes - set a long random value in `.env` |
| `/ui` shows `{"detail":"Not Found"}` | you started uvicorn from the wrong directory - `cwd` must be `backend/` (run via `uv run` as above) |
| LLM features say `offline` | no `FEATHERLESS_API_KEY` - expected; add key for live parsing |
| NVD sync is slow / 403 | no/slow network or missing `NVD_API_KEY`; local seed CVE KB still works |
| Report generation returns 500 | `reports.pdf` column missing - apply `app/db/migrate_002.sql` in Supabase SQL editor (the API also self-applies it on each `POST /reports`) |
| Windows AV flags `.venv` | exclude the project folder from real-time scanning |

## 7. Production notes (not done here, by design)

In-memory stores (`app/core/store.py`) → PostgreSQL (+pgvector);
add Redis/Celery for audit/CVE-sync/PDF jobs; Nginx in front; secrets manager
for `.env`; Prometheus/Grafana later. See `docs/IMPLEMENTATION.md §9` and
`../docs/tech_stack.md`.
