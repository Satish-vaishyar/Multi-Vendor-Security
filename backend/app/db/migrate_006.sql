-- Migration 006: Postgres-backed job queue (audits, reports, batches) on the existing `jobs` table.
-- Idempotent. Legacy rows (cve_sync / fleet jobs written as COMPLETED/FAILED) are untouched.

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS attempts        INT         NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS max_attempts    INT         NOT NULL DEFAULT 3;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS priority        INT         NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS run_after       TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS locked_by       TEXT;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS locked_at       TIMESTAMPTZ;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS started_at      TIMESTAMPTZ;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS finished_at     TIMESTAMPTZ;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS progress        INT         NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS error           TEXT;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS batch_id        TEXT;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS created_by      TEXT;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS cancel_requested BOOLEAN    NOT NULL DEFAULT false;

-- the claim query scans only runnable work, ordered by priority then age
CREATE INDEX IF NOT EXISTS idx_jobs_runnable ON jobs (priority DESC, created_at) WHERE status = 'QUEUED';
CREATE INDEX IF NOT EXISTS idx_jobs_running  ON jobs (locked_at) WHERE status = 'RUNNING';
CREATE INDEX IF NOT EXISTS idx_jobs_batch    ON jobs (batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_jobs_org_time ON jobs (org_id, created_at DESC);
