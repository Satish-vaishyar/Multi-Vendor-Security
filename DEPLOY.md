# Production hosting checklist - SIH-26155 auditor

## 1. Backend env (`backend/.env` - NEVER commit this file)

Copy the template and fill in secrets:

```powershell
copy backend\.env.example backend\.env
```

| Key | Value |
|---|---|
| `ENV` | `production` |
| `JWT_SECRET` | `<openssl rand -hex 32>` - required, the dev default is rejected |
| `DATABASE_URL` | `postgresql://postgres:<pw>@db.<ref>.supabase.co:5432/postgres?sslmode=require` |
| `CORS_ORIGINS` | `https://app.yourdomain.com` - no `"*"` in production |
| `TRUSTED_HOSTS` | `api.yourdomain.com` |
| `REQUIRE_AUTH` | `true` |
| `DATA_ENCRYPTION_KEYS` | versioned key ring for field encryption (or a Vault/AWS KMS provider) |
| `METRICS_TOKEN` | bearer token required by `/metrics` in production |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | strong values |

## 2. Database (Supabase Postgres)

Run the app migrations (idempotent; applies `001`-`016`, including tenancy,
auth/MFA, audit log, retention, report packs and live collection). Never run
them by hand-editing `schema.sql`:

```powershell
cd backend
uv run python -m app.cli migrate
uv run python -m app.cli check-config          # prints every missing/weak setting
uv run python -m app.cli encrypt-existing      # once, if configs predate encryption
uv run python -m app.cli rls-enable            # optional: enforce row-level security
```

`/readyz` returns `503` until the schema is current (`GET /readyz` →
`db.schema_current`).

## 3. Build + run

```powershell
docker compose up --build
```

- Frontend: http://localhost:8080 → proxies `/api/` to `backend:8000`
- Backend: http://localhost:8000 · Docs: `/docs` (disabled when `ENABLE_DOCS=false`)
- Worker: `worker` service runs `python -m app.worker` for jobs, collection,
  recurring audits, CVE sync and retention. Scale with
  `docker compose up --scale worker=3`.
- Single-domain hosting: bake the public API URL into the frontend build:

```powershell
$env:VITE_API_BASE_URL="https://api.yourdomain.com/api/v1"; docker compose up --build
```

## 4. Verify

```powershell
curl http://localhost:8000/health    # -> {"success":true,"status":"healthy"}
curl http://localhost:8000/readyz    # -> {"status":"ready","db":{"status":"up","schema_current":true}}
```

Plus, before shipping: `uv run pytest` in `backend/` (coverage gate),
`uv run python -m pytest -q` in `okf/`, and `npm run build` + `npx playwright test`
in `frontend/`.

## 5. Security notes

- Secrets live **only** in `backend/.env` / host secrets manager, never in images.
- `.env` is excluded from Docker images (`backend/.dockerignore`) and from git (root `.gitignore`).
- Remediation Apply is dry-run only (`device_touched: false`) by design; live
  collection is read-only and needs an allow-listed target with a pinned host key.
- Have every admin enrol MFA (Settings → Two-factor authentication) or configure
  OIDC SSO before opening the UI to users.
- Rotate the Supabase password after sharing; update `DATABASE_URL` accordingly.
- If a secret ever leaks into git history, rotate it immediately (rewrite won't
  purge copies others already pulled).
