-- Migration 007: audit history (append-only snapshots) and recurring audit schedules. Idempotent.

-- One row per completed audit RUN (the audits table upserts, so it cannot show change over time).
CREATE TABLE IF NOT EXISTS audit_snapshots (
  snapshot_id   TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  asset_id      TEXT NOT NULL,
  audit_id      TEXT NOT NULL,
  configuration_id TEXT,
  config_sha256 TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  trigger       TEXT NOT NULL DEFAULT 'manual',          -- manual | schedule | batch
  compliance_score DOUBLE PRECISION,
  coverage_pct  DOUBLE PRECISION,
  counts        JSONB NOT NULL DEFAULT '{}',             -- failed / critical / high / cve / pqc ...
  versions      JSONB NOT NULL DEFAULT '{}',             -- knowledge versions used (explains drift without a config change)
  findings      JSONB NOT NULL DEFAULT '[]',             -- compact list of FAIL/UNKNOWN finding keys
  changes       JSONB NOT NULL DEFAULT '{}'              -- diff against the previous snapshot of the same asset
);
CREATE INDEX IF NOT EXISTS idx_snap_asset_time ON audit_snapshots (org_id, asset_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_snap_org_time   ON audit_snapshots (org_id, created_at DESC);

-- Recurring re-audit of an asset's latest configuration.
CREATE TABLE IF NOT EXISTS schedules (
  schedule_id      TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  name             TEXT NOT NULL,
  asset_id         TEXT NOT NULL,
  interval_minutes INT  NOT NULL,
  frameworks       JSONB NOT NULL DEFAULT '["CIS","NIST","STIG","ISO27001"]',
  run_cve          BOOLEAN NOT NULL DEFAULT true,
  enabled          BOOLEAN NOT NULL DEFAULT true,
  next_run_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_run_at      TIMESTAMPTZ,
  last_job_id      TEXT,
  last_status      TEXT,
  created_by       TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules (next_run_at) WHERE enabled;
CREATE INDEX IF NOT EXISTS idx_schedules_org ON schedules (org_id, created_at DESC);
