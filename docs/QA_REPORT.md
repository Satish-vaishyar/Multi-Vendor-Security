# QA Report — Playwright end-to-end suite

Date: 2026-10-10. Scope: `frontend/tests/e2e` (70 tests, 12 spec files, Chromium only)
against the local stack: FastAPI backend on `:8000`, Vite dev server on `:5173`,
Postgres `postgresql://postgres:postgres@localhost:55432/auditor_test_c`.
LOCAL ONLY: no commits, no third-party network calls.

## How the stack was started

The backend was already running on `:8000` (PID 33504, started 2026-10-10 17:43 local
by the previous session via `frontend/tests/e2e/start-backend.sh` from the repo root).
Verified before use, not restarted (its ephemeral JWT/Fernet secrets are not recoverable,
and a restart would orphan already-encrypted rows):

- `GET /health` returns `{"status":"healthy"}`; unauthenticated API calls return 401
  (auth is on).
- Login with the documented QA admin credentials from `start-backend.sh` /
  `tests/e2e/helpers/api.ts` (`qa-admin@example.com`) succeeds; the user is in
  `ORG-DEFAULT`.
- The database `auditor_test_c` is migrated and populated (107 assets, 103 audits at
  the time of checking); `start-backend.sh` points only at this local database
  (`QA_DATABASE_URL` default `postgresql://...localhost:55432/auditor_test_c`).
- Backend sanity on the idle system: login 0.08 s, dashboard summary 0.14 s, one full
  4-framework + CVE + PQC + analytics audit 0.7 s end to end.
- No `migrate` was run (schema already current; nothing indicated otherwise).
- No process listens on `:5173` between runs; Playwright's `webServer` entry in
  `playwright.config.ts` starts/stops Vite itself.

## Exact commands to run the suite

From the repo root (Git Bash):

```bash
# backend (only if not already running; from the repo root)
bash frontend/tests/e2e/start-backend.sh
# migrate ONLY with the test DATABASE_URL set, from backend/ (not needed if already migrated)
DATABASE_URL=postgresql://postgres:postgres@localhost:55432/auditor_test_c \
  .venv/Scripts/python -m app.cli migrate
# the suite
cd frontend && npx playwright test --reporter=list
# static checks (all must be clean)
npx tsc --noEmit && npm run build && npm run lint
```

`global-setup.ts` runs automatically before the suite: it reuses/creates the shared
`qa-seed-insecure` / `qa-seed-hardened` assets (asset creation dedupes by
name+vendor+product, so re-runs reuse them) and publishes their ids via `QA_SEED`.

## What is covered (spec by spec)

| Spec | Journey / coverage |
|---|---|
| `first-run.spec.ts` | Journey 1: brand-new org via CLI, forced password change + validation, guarded routes, empty states on every page, sample config → quick audit → results, Get Started checklist advances to 2/5 |
| `audit-journey.spec.ts` | Journey 2 (serial): UI upload → vendor detect → audit → results + coverage panel → findings filter/search → finding detail → remediation plan → CSV/JSON exports → PDF report (%PDF header, %%EOF, SHA-256 header matches bytes and record) → evidence/fleet exports integrity headers (API) |
| `mfa.spec.ts` | TOTP RFC 6238 helper vector; enrol authenticator in Settings + recovery codes; login second-factor matrix (missing/wrong/replayed/valid code); recovery code single-use; disable MFA with password + code |
| `multi-vendor.spec.ts` | All 8 `okf/tests/corpus` configs through the real UI: vendor, confidence > 0.8, structured parser + platform, coverage panel == API, sane findings/ids/severities, page score == API score; hardened scores 30+ above insecure; deterministic re-audit |
| `rbac.spec.ts` | VIEWER: hidden nav/upload/integrations/admin, admin pages bounce, read-only audits/exceptions/schedules, friendly permission errors (no raw 403 text), server-side 403s + secret masking (raw config, canonical IR, results, evidence) |
| `workflows.spec.ts` | Risk acceptance four-eyes (self-approve refused, second approver activates, auditor sees no buttons, reject flow); recurring schedule create/run-now/pause/resume/delete + server-side interval validation; webhook SSRF policy in UI and API + non-admin 403 |
| `auth.spec.ts` | UI login → dashboard, invalid credentials, unauthenticated redirect, session persists across reload, logout re-guards |
| `dashboard.spec.ts` | KPIs/charts/nav links, Run New Audit navigation, dashboard summary API |
| `browse-reports.spec.ts` | Audits list, findings page, bogus report id surfaces a readable backend error, report form validation |
| `edge.spec.ts` | Unknown audit/finding error states + Retry, unknown route redirect, 401 session expiry clears token, offline assets page with Retry + recovery, mobile Start-audit dialog fit |
| `upload-audit.spec.ts` | Upload Configuration → Start Audit dialog flow incl. no-file validation |
| `ui-quality.spec.ts` | Mobile (375×812) drawer/overflow/login/drop-zone, a11y smoke (labels, names, headings, landmarks) on every main page, command-palette asset search |

## Results

| Run | Passed | Flaky (passed on retry) | Failed | Did not run | Wall | Exit |
|---|---|---|---|---|---|---|
| Run 1 — baseline before fixes | 38 | 18 | 8 | 6 (serial-skipped after failures) | 11.7 min | 1 |
| Run 2 — after fixes | 64 | 6 | 0 | 0 | 2.4 min | 0 |
| Run 3 — stability re-run | 70 | 0 | 0 | 0 | 1.5 min | 0 |

Static checks (after fixes): `npx tsc --noEmit` exit 0, `npm run build` exit 0,
`npm run lint` exit 0 (6 pre-existing oxlint *warnings* in `src/pages/PQC.tsx` and
`src/pages/Remediation.tsx`, unrelated to this work).

Run 1 was slow and flaky because the machine was contended (evidence: trivial tests
taking 30–90 s; audit API calls that take <1 s idle timing out at 60 s). Every run-1
failure class was re-run in isolation afterwards: all load-attributed failures pass
alone; the three deterministic failures below reproduced alone and were fixed.

## Bugs found and fixed (test-side; no app code changed)

1. `frontend/tests/e2e/workflows.spec.ts` — the Asset `<select>` on `/exceptions` and
   `/schedules` renders only the newest 100 assets (`page_size: 100`, newest first).
   The shared `qa-seed-insecure` asset sits at position ~107 after many runs, so
   `selectOption({ label: 'qa-seed-insecure' })` deterministically finds no option.
   Fix: each test creates its own uniquely named asset (always newest → on page 1)
   *before* loading the page, and the schedule test uploads a config to it first
   because "Run now" re-audits the asset's latest configuration. All assertions kept.
2. `frontend/tests/e2e/first-run.spec.ts` ("checklist advances") — after the sample
   audit, `/get-started` showed "1 of 5" for the full 20 s assertion window. Root cause
   traced via the retry trace: the first visit cached `GET /dashboard/summary`
   (assets = 0) in the 5 s server-side TTL cache; the post-audit fetch 4 s later got a
   cache hit, and the 60 s client `staleTime` then suppressed any refetch. Fix: poll the
   summary API until `assets.total > 0`, `page.reload()`, then assert "2 of 5" +
   progressbar 40 as before.
3. `frontend/tests/e2e/multi-vendor.spec.ts` — the two API-only tests (hardened-vs-
   insecure, determinism) run two full audits each (~17–24 s even idle) but had the
   60 s default timeout; they timed out under parallel load. Fix: `test.setTimeout(180_000)`,
   matching the sibling UI tests in the same file. No assertions changed.

Deliberately NOT changed: `docs/product_readiness_gaps.md` (untouched per instructions).

## Known issues / flaky tests

- Run 2 had 6 first-attempt flakes, all green on immediate retry (config `retries: 1`
  absorbed them, exit 0): `browse-reports:9`, `dashboard:10`, `edge:10`, `edge:20`,
  `edge:28`, `first-run:16`. Run 3 had zero flakes. Pattern is cold-start/parallel-
  startup contention (suite generator: many browsers hitting fresh Vite + single
  uvicorn worker at once), not product defects. Re-run the suite if a cold-start flake
  appears; do not "fix" by deleting assertions.
- Product limitations noticed but out of scope (no app changes made): asset dropdowns
  are capped at the newest 100 with no search (old assets cannot be picked in the
  exception/schedule forms once the fleet exceeds 100); `GET /dashboard/summary` is
  TTL-cached per org for 5 s with no mutation invalidation (checklist/KPIs can lag a
  few seconds after creating assets/audits); frontend `QueryClient` default
  `staleTime: 60 s`.
- Shared-database caveat: the suite reuses one database across runs; asset rows
  accumulate (dedupe is by name+vendor+product per org). Tests that need seed data
  must create their own assets (as `workflows.spec.ts` now does) rather than relying
  on list position.

## Honest limits of what was NOT tested

- Browsers: Chromium (Desktop Chrome) only — no Firefox, WebKit, or real mobile browsers.
- The 8-platform multi-vendor check proves the pipeline runs end to end with sane
  scores on 8 authored corpus files; it does not prove parser accuracy on real-world
  customer configs.
- PDF integrity (header, %%EOF, SHA-256 match) is asserted; PDF *content* correctness
  is not.
- Webhook SSRF policy is asserted at creation/validation time; actual delivery,
  retries, and ticketing integrations are not exercised (no third-party calls).
- No load/stress testing, no multi-worker backend, no TLS/prod topology, no email
  delivery, no backup/restore, no migration-from-older-version testing.
- Backend Python unit tests were not run (out of scope for this e2e task).
- MFA tests depend on TOTP time windows and passed, but clock-skew behaviour was not
  probed beyond the replay guard.
