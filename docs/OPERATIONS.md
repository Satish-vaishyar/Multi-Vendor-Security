# Operations runbook

Audience: whoever is on call for the auditor. Config reference: `backend/.env.example`; security setup: `docs/SECURITY.md`;
job queue internals: `docs/JOBS.md`. Alert rules: `docs/ops/prometheus_alerts.yml`.

## 1. Processes and health

| Process | Command | Health |
|---|---|---|
| API | `uvicorn app.main:app` | `GET /health` (liveness), `GET /readyz` (503 when the DB is down/outdated) |
| Worker(s) | `python -m app.worker` | heartbeat row in `worker_heartbeats` -> `auditor_worker_last_heartbeat_age_seconds` |

Production runs dedicated workers (`EMBEDDED_WORKER=false`). Workers also run hourly maintenance: stale-job recovery, job/snapshot
purge and the data-retention job.

## 2. Metrics and logs

* `GET /metrics` (Prometheus text format, no client library). Set `METRICS_TOKEN` (>= 16 chars) and scrape with
  `Authorization: Bearer <token>`. In production the endpoint answers **503 until the token is set** (`python -m app.cli check-config`
  prints a warning). Never expose it publicly; restrict it at the ingress as well.
* Series: `auditor_http_requests_total{method,route,status}`, `auditor_http_request_duration_seconds` (histogram),
  `auditor_http_requests_in_flight`, `auditor_jobs{status}`, `auditor_job_queue_oldest_age_seconds`, `auditor_workers_seen`,
  `auditor_worker_last_heartbeat_age_seconds`, `auditor_worker_last_maintenance_timestamp_seconds`,
  `auditor_retention_last_run_timestamp_seconds`, `auditor_db_up`, `auditor_build_info{version,env}`.
  `route` is the route **template** (`/api/v1/assets/{asset_id}`), never the raw path; unmatched URLs collapse to `unmatched`.
  HTTP counters are per API process (sum across replicas in PromQL); queue and worker gauges come from the database.
* Logs: `LOG_FORMAT=json` emits one JSON object per line (`ts, level, logger, msg, request_id, org_id, exc`). Secrets
  (passwords, tokens, JWTs, `Authorization` values, config secrets) are redacted in both formats. Correlate a user report with
  `X-Request-ID` (echoed in every response).

## 3. Backup and restore (Supabase Postgres)

The database is the only stateful component (reports' PDFs, configs, audit log, job queue). The knowledge base under `okf/` is in git.

* **Backups:** enable Supabase daily backups (Pro plan and above) and, for point-in-time recovery, the PITR add-on. Additionally take a
  logical dump before every upgrade or migration:
  `pg_dump "$DATABASE_URL" --format=custom --no-owner --file auditor-$(date +%F).dump`
  Store dumps encrypted, in a different account/region. Field-encrypted columns stay encrypted in dumps, so **back up
  `DATA_ENCRYPTION_KEYS` separately** (secret manager); a dump without the key cannot be read, and the key without the dump is useless.
* **Restore drill (do this quarterly, against a scratch project/DB - never over production by reflex):**
  1. Create an empty Postgres (Supabase restore-to-new-project or local container).
  2. `pg_restore --no-owner --clean --if-exists -d "$SCRATCH_URL" auditor-YYYY-MM-DD.dump`
  3. `DATABASE_URL=$SCRATCH_URL python -m app.cli migrate` (idempotent; brings the schema to current).
  4. Start the API against it and check `/readyz`, log in, open an asset, download a report.
* **Real restore:** stop workers first, restore, run `migrate`, set `DATABASE_URL`, start API, then workers. Jobs that were `RUNNING`
  are re-queued automatically after `JOB_STALE_SECONDS`. Anything after the backup point is lost; the audit log restored from
  backup is the authoritative trail up to that point.

## 4. Runbooks

### API down
`/health` fails: check the container/process and its logs (`LOG_FORMAT=json` makes `request_id` greppable). Startup refuses with
"Unsafe production configuration" when `JWT_SECRET`, `ADMIN_PASSWORD`, `CORS_ORIGINS`, `TRUSTED_HOSTS`, `DATA_ENCRYPTION_KEYS` or
`DATABASE_URL` are unsafe - run `python -m app.cli check-config` with the same environment.

### Worker down
Alert `AuditorWorkerDown` (no heartbeat for 5 min).
1. `auditor_jobs{status="QUEUED"}` growing and `..._heartbeat_age_seconds` high = no worker is alive. Restart the worker service.
2. Check its logs for `worker loop error` (DB connectivity) or crashes on start (`validate_production` problems).
3. Jobs that were running when the worker died are re-queued by any worker after `JOB_STALE_SECONDS` (default 900 s); nothing is lost.
4. Emergency only: set `EMBEDDED_WORKER=true` on the API to process the queue in-process, then revert.

### Queue stuck
Alert `AuditorQueueStuck` (oldest runnable QUEUED job > 15 min while workers are alive).
1. `SELECT kind, status, count(*), min(created_at) FROM jobs GROUP BY 1,2;` and look at `locked_by`/`locked_at` of RUNNING rows.
2. RUNNING rows with an old `locked_at`: wait for `requeue_stale` (60 s maintenance tick) or lower `JOB_STALE_SECONDS`.
3. A single heavy job (very large config, LLM/NVD call) blocking all workers: add workers (claiming uses `FOR UPDATE SKIP LOCKED`, safe).
4. Poison job (fails repeatedly): it stops after `JOB_MAX_ATTEMPTS`; cancel it via `POST /api/v1/jobs/{job_id}/cancel`.
5. Per-org flooding: `MAX_QUEUED_JOBS_PER_ORG` rejects new work with 429-style errors; raise only after finding the cause.

### Database failover
Symptoms: `auditor_db_up 0`, `/readyz` 503, `worker loop error` in worker logs.
1. Confirm in the Supabase dashboard whether a failover/maintenance is under way; the pooler endpoint (`DATABASE_URL`) should
   survive a primary switch, a direct-connection URL will not.
2. The API recovers by itself once connections succeed (broken pooled connections are discarded). Workers retry every <= 30 s.
3. After recovery verify `/readyz`, queue depth draining, and run `python -m app.cli migrate` if a restore from backup happened.
4. If the database was restored to an older point, expect missing audits/reports after that point; re-run affected audits.

### Key rotation
`DATA_ENCRYPTION_KEYS` is a comma-separated list, newest first.
1. Generate: `python -m app.cli gen-key`.
2. Deploy with `DATA_ENCRYPTION_KEYS=<new>,<old>` to API **and** workers (old rows still decrypt, new writes use `<new>`).
3. Re-encrypt every stored value: `python -m app.cli reencrypt` (take a `pg_dump` first; the command is idempotent and may be re-run).
4. Verify (`/readyz`, open a configuration, run an audit), then deploy with only `<new>`. Keep the old key in the secret manager until
   the last backup encrypted with it has aged out of your retention window.
5. `JWT_SECRET` rotation logs everyone out (tokens are short-lived anyway): change it on all API replicas together.
6. `METRICS_TOKEN`: change it in the app environment and the Prometheus credentials file together.

### Data retention
Runs automatically in each worker's hourly maintenance (`RETENTION_ENABLED=true`); concurrent runs are serialised by a Postgres advisory lock.
Purges are cross-tenant and age-based. Defaults (0 disables a rule):

| Data | Rule | Env |
|---|---|---|
| `audit_log` | rows older than 400 d deleted | `AUDIT_LOG_RETENTION_DAYS` |
| `revoked_tokens` | already-expired revocations deleted | - |
| `reports.pdf` | PDF bytes dropped after 365 d, report metadata kept (regenerate from the audit) | `REPORT_PDF_RETENTION_DAYS` |
| `webhook_deliveries` | 30 d | `WEBHOOK_DELIVERY_RETENTION_DAYS` |
| `audit_snapshots` | 365 d, each asset's newest 30 always kept | `SNAPSHOT_RETENTION_DAYS` |
| `configurations.config_text` | raw text of **superseded** configs replaced by a marker; **off by default** | `CONFIG_RETENTION_DAYS` |
| `jobs` | finished audit/report/webhook jobs, 30 d | `JOB_RETENTION_DAYS` |

* Preview: `python -m app.cli retention --dry-run` or `POST /api/v1/admin/retention/run?dry_run=true` (ADMIN; dry run is the default).
  Apply now: `python -m app.cli retention` or `...?dry_run=false`.
* The audit log is append-only: the DB trigger blocks every UPDATE and blocks DELETE unless the transaction sets
  `app.audit_retention = 'on'`, which only the retention job does. Every real run writes an `audit_log` row
  (`action = retention.purge`, actor `system:retention`) with the per-table counts and the retention periods used.
* Legal hold / longer audit retention: raise `AUDIT_LOG_RETENTION_DAYS` (or set 0) **before** the next hourly run, and export the log
  to your SIEM. Deleted rows are only recoverable from database backups.
* Alert `AuditorRetentionNotRunning` fires when no worker has completed a retention run for 2 h.
