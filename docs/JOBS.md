# Background jobs

Audits, reports and whole-fleet batches run in a Postgres-backed queue (`jobs` table, migration 006) so large
workloads never hit HTTP time-outs and the API stays responsive. No Redis / Celery is needed.

## Using it

| Call | Purpose | Role |
|---|---|---|
| `POST /api/v1/jobs/bulk-audit` (multipart `files[]`, `frameworks`, `run_cve`, `criticality`) | Onboard + audit a fleet: one asset per device (named from the config hostname, reused if it exists), one queued audit per file, one `batch_id` | AUDITOR |
| `POST /api/v1/jobs/audit` / `POST /api/v1/jobs/report` | Queue a single audit / PDF | AUDITOR |
| `GET /api/v1/jobs?status=&kind=&batch_id=` ; `GET /api/v1/jobs/{id}` | Status, progress, result, error | VIEWER |
| `GET /api/v1/jobs/batches/{batch_id}` | Batch progress (`RUNNING` / `COMPLETED` / `FINISHED_WITH_ERRORS`) | VIEWER |
| `POST /api/v1/jobs/{id}/cancel` ; `POST /api/v1/jobs/{id}/retry` | Cancel a queued/running job; re-queue a failed/cancelled one | AUDITOR |

The UI has a **Background jobs** page: drop many configs, watch the batch progress bar, open finished audits, retry
failures. The synchronous `POST /api/v1/audits` still exists for single devices.

## Semantics

* **Exactly-once claiming:** workers claim with `FOR UPDATE SKIP LOCKED`; any number of worker processes/containers
  can run side by side (tested with 6 racing threads and two real OS processes).
* **Retries:** an exception is retried with exponential backoff (5 s, 10 s, 20 s ...) up to `JOB_MAX_ATTEMPTS` (3);
  input errors that can never succeed (missing config/asset/audit) fail immediately and are not retried.
* **Crash recovery:** a worker that dies leaves a `RUNNING` row; after `JOB_STALE_SECONDS` without heartbeat it is
  re-queued (or failed if out of attempts). A late result from a replaced worker is ignored.
* **Idempotent work:** audit ids are deterministic per (org, asset, config) and findings are upserted, so a retry never
  duplicates data.
* **Tenancy:** jobs belong to an org; the API only shows/cancels/retries your org's jobs; the worker re-enters the
  job's org before touching any data. Per-org queue cap (`MAX_QUEUED_JOBS_PER_ORG`) returns HTTP 429.
* **Audit trail:** job completion / failure are written to the append-only audit log.
* **Retention:** finished jobs are purged after `JOB_RETENTION_DAYS`.

## Running workers

```bash
python -m app.worker            # long-running worker (SIGTERM finishes the current job, then exits)
python -m app.worker --once     # drain the queue and exit (cron / CI)
docker compose up --scale worker=3
```
Development: `EMBEDDED_WORKER=true` (the default outside production) runs one worker thread inside the API process.
Production: keep it `false` and run dedicated workers. Run `python -m app.cli migrate` first (adds the queue columns).

## Limits (honest)

* Polling (default every 2 s), not push - fine for audit workloads, not for sub-second latency.
* The enqueue request still validates and fingerprints every uploaded file; a 500-file batch holds the request for
  that long (disk-spooled, not RAM). Upload in several batches if your proxy time-out is short.
* CPU-bound ML runs per worker process; scale by adding worker processes, not threads.
* Scheduled / recurring audits and live device collection (P2-1, P2-2) are not built yet; they would enqueue the same
  `audit` jobs.
