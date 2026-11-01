-- Migration 011: data retention + worker heartbeat. Idempotent.

-- audit_log stays append-only (UPDATE always blocked). DELETE is allowed ONLY inside a transaction that sets
-- app.audit_retention = 'on' (done solely by app.services.retention, which then records the purge itself).
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' AND coalesce(current_setting('app.audit_retention', true), '') = 'on' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'audit_log is append-only';
END; $$ LANGUAGE plpgsql;

CREATE INDEX IF NOT EXISTS idx_reports_created   ON reports (created_at) WHERE pdf IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_deliveries_time   ON webhook_deliveries (created_at);

-- one row per worker process; used by /metrics and the "worker down" alert
CREATE TABLE IF NOT EXISTS worker_heartbeats (
  worker_id        TEXT PRIMARY KEY,
  last_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_maintenance TIMESTAMPTZ,
  last_retention   TIMESTAMPTZ
);
