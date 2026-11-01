-- Migration 005: multi-tenancy, hardened authentication, immutable audit log.
-- Idempotent. Existing rows are assigned to ORG-DEFAULT.

CREATE TABLE IF NOT EXISTS organizations (
  org_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO organizations (org_id, name) VALUES ('ORG-DEFAULT', 'Default Organization')
  ON CONFLICT (org_id) DO NOTHING;

-- tenant column on every business table
ALTER TABLE users            ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id);
ALTER TABLE assets           ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id);
ALTER TABLE configurations   ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id);
ALTER TABLE audits           ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id);
ALTER TABLE findings         ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id);
ALTER TABLE training_queue   ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id);
ALTER TABLE mapping_registry ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id);
ALTER TABLE remediations     ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id);
ALTER TABLE reports          ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id);
ALTER TABLE jobs             ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id);

CREATE INDEX IF NOT EXISTS idx_users_org            ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_assets_org           ON assets(org_id);
CREATE INDEX IF NOT EXISTS idx_configurations_org   ON configurations(org_id);
CREATE INDEX IF NOT EXISTS idx_audits_org           ON audits(org_id);
CREATE INDEX IF NOT EXISTS idx_findings_org         ON findings(org_id);
CREATE INDEX IF NOT EXISTS idx_training_org         ON training_queue(org_id);
CREATE INDEX IF NOT EXISTS idx_mapping_registry_org ON mapping_registry(org_id);
CREATE INDEX IF NOT EXISTS idx_remediations_org     ON remediations(org_id);
CREATE INDEX IF NOT EXISTS idx_reports_org          ON reports(org_id);
CREATE INDEX IF NOT EXISTS idx_jobs_org             ON jobs(org_id);

-- authentication hardening
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti TEXT PRIMARY KEY,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_exp ON revoked_tokens(expires_at);

-- append-only audit trail of who did what
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  org_id TEXT,
  actor_id TEXT,
  actor_email TEXT,
  role TEXT,
  action TEXT NOT NULL,
  method TEXT,
  path TEXT,
  status INT,
  ip TEXT,
  request_id TEXT,
  detail JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts    ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_org   ON audit_log(org_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id);

CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END; $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_log_no_update ON audit_log;
CREATE TRIGGER trg_audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- migration bookkeeping used by `python -m app.cli migrate`
CREATE TABLE IF NOT EXISTS schema_migrations (
  name TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
