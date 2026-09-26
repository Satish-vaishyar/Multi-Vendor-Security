# Production hosting checklist — SIH-26155 auditor

## 1. Backend env (`backend/.env` — NEVER commit this file)

Copy the template and fill in secrets:

```powershell
copy backend\.env.example backend\.env
```

| Key | Value |
|---|---|
| `ENV` | `production` |
| `JWT_SECRET` | `<openssl rand -hex 32>` — required, the dev default is rejected |
| `DATABASE_URL` | `postgresql://postgres:<pw>@db.<ref>.supabase.co:5432/postgres?sslmode=require` |
| `CORS_ORIGINS` | `https://app.yourdomain.com` — no `"*"` in production |
| `TRUSTED_HOSTS` | `api.yourdomain.com` |
| `REQUIRE_AUTH` | `true` |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | strong values |

## 2. Database (Supabase Postgres)

Schema lives at `backend/app/db/schema.sql` (10 tables, pgvector + pgcrypto).
Re-run any time to migrate idempotently:

```powershell
psql "$env:DATABASE_URL" -f backend/app/db/schema.sql
```

## 3. Build + run

```powershell
docker compose up --build
```

- Frontend: http://localhost:8080 → proxies `/api/` to `backend:8000`
- Backend: http://localhost:8000 · Docs: `/docs`
- Single-domain hosting: bake the public API URL into the frontend build:

```powershell
$env:VITE_API_BASE_URL="https://api.yourdomain.com/api/v1"; docker compose up --build
```

## 4. Verify

```powershell
curl http://localhost:8000/health    # -> {"status":"healthy"}
curl http://localhost:8000/readyz    # -> {"status":"ready","db":{"status":"up","public_tables":10}}
```

Plus, before shipping: `uv run pytest` in `backend/` (coverage gate) and
`npm run build` in `frontend/`.

## 5. Security notes

- Secrets live **only** in `backend/.env` / host secrets manager, never in images.
- `.env` is excluded from Docker images (`backend/.dockerignore`) and from git (root `.gitignore`).
- Remediation Apply is dry-run only (`device_touched: false`) by design.
- Rotate the Supabase password after sharing; update `DATABASE_URL` accordingly.
- If a secret ever leaks into git history, rotate it immediately (rewrite won't
  purge copies others already pulled).
