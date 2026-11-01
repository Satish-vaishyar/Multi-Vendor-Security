# Audit history, drift and recurring audits

Code: `backend/app/services/history.py`, `backend/app/core/schedules.py`, `backend/app/api/v1/history.py`.
Tables: `audit_snapshots`, `schedules` (migration 007). Tests: `backend/tests/test_history.py`.

## Why snapshots
The `audits` table is an upsert (same config on the same asset = same audit id), so it cannot show change over time.
Every completed audit RUN therefore appends one compact snapshot: score, coverage, counts, knowledge versions and the
list of non-passing finding keys (`compliance:<control>`, `cve:<CVE-id>`, `pqc:<alg>:<proto>`, `security:<type>:<prop>`).
Remediation what-if re-audits (`snapshot=False`) never appear in the history.

## What it answers
| Question | Where |
|---|---|
| What is new / fixed / got worse since last run? | `GET /api/v1/history/assets/{id}/compare` (defaults to previous -> latest) |
| Did the score move because the config changed or because the CVE DB / control packs changed? | `config_changed`, `knowledge_changed` on every snapshot and comparison |
| How long has this finding been open? | `age_days` (unbroken streak; resets if it was fixed and came back) |
| What exactly changed in the config? | `GET .../config-diff?from=&to=` - secrets masked, changed secrets only counted |
| Is the estate getting better? | `GET /api/v1/history/trend?days=90[&asset_id=]` (dashboard card) |
| What needs attention this week? | `GET /api/v1/history/changes` (new critical/high, severity increases, score moves >= 5) |

"Could not assess" (UNKNOWN) findings are stored but never counted as new failures.

## Recurring audits
`POST /api/v1/schedules` (`interval_minutes` >= `SCHEDULE_MIN_MINUTES`, default 15) re-audits the asset's **latest uploaded
configuration** on that interval through the normal job queue. Without live collection the configuration itself does not
change, but findings do: new CVEs, updated control packs. The history layer shows exactly that.
* Scheduler ticks run inside every worker, claim due rows with `FOR UPDATE SKIP LOCKED` and advance `next_run_at` before
  enqueueing: a crash skips a run instead of duplicating it.
* Pausing and resuming never replays missed runs. An asset with no config reports `NO_CONFIG`; a full queue `QUEUE_FULL`.
* `POST /api/v1/schedules/{id}/run` fires one immediately.

## Retention
`SNAPSHOT_RETENTION_DAYS` (365) - older snapshots are purged hourly by workers, but each asset always keeps its latest 30.

## Limits
* Scheduling re-audits a stored config; it does not fetch a fresh one (live collection, P2-1, would enqueue the same jobs).
* No push notifications yet: the change feed is pull-based until integrations (P2-4) add webhooks / ticketing.
