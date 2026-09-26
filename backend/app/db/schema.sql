-- SIH-26155 production schema (Supabase / PostgreSQL 17 + pgvector).
-- Mirrors backend/app/core/store.py dicts + docs/arch.md §37 tables.
-- Safe to run multiple times (IF NOT EXISTS / idempotent triggers).

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS citext;

-- ---------- users / auth ----------
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email CITEXT UNIQUE NOT NULL,
  name TEXT NOT NULL DEFAULT 'Admin',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'ADMIN',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- assets ----------
CREATE TABLE IF NOT EXISTS assets (
  asset_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  vendor TEXT,
  product TEXT,
  model TEXT,
  version TEXT,
  serial_number TEXT,
  ip_address TEXT,
  environment TEXT,
  criticality TEXT NOT NULL DEFAULT 'MEDIUM',
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- configurations ----------
CREATE TABLE IF NOT EXISTS configurations (
  configuration_id TEXT PRIMARY KEY,
  asset_id TEXT REFERENCES assets(asset_id) ON DELETE SET NULL,
  filename TEXT,
  size INT,
  lines INT,
  sha256 TEXT,
  config_text TEXT NOT NULL,
  detected_vendor TEXT,
  detected_platform TEXT,
  detected_version TEXT,
  detection JSONB NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'UPLOADED',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_configurations_asset ON configurations(asset_id);
CREATE INDEX IF NOT EXISTS idx_configurations_sha ON configurations(sha256);

-- ---------- audits ----------
CREATE TABLE IF NOT EXISTS audits (
  audit_id TEXT PRIMARY KEY,
  asset_id TEXT REFERENCES assets(asset_id) ON DELETE SET NULL,
  configuration_id TEXT REFERENCES configurations(configuration_id) ON DELETE SET NULL,
  vendor JSONB NOT NULL DEFAULT '{}',
  frameworks TEXT[] NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'COMPLETED',
  progress INT NOT NULL DEFAULT 100,
  stages JSONB NOT NULL DEFAULT '{}',
  config_sha256 TEXT,
  versions JSONB NOT NULL DEFAULT '{}',
  summary JSONB NOT NULL DEFAULT '{}',
  by_framework JSONB NOT NULL DEFAULT '{}',
  compliance JSONB NOT NULL DEFAULT '{}',
  cve JSONB NOT NULL DEFAULT '{}',
  pqc JSONB NOT NULL DEFAULT '{}',
  security JSONB NOT NULL DEFAULT '{}',
  canonical_ir JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  duration_s DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_audits_asset ON audits(asset_id);

-- ---------- findings (unified: compliance/cve/pqc/security) ----------
CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT PRIMARY KEY,
  audit_id TEXT REFERENCES audits(audit_id) ON DELETE CASCADE,
  asset_id TEXT,
  engine TEXT NOT NULL,
  type TEXT,
  title TEXT,
  severity TEXT NOT NULL DEFAULT 'MEDIUM',
  status TEXT NOT NULL DEFAULT 'FAIL',
  control_id TEXT,
  evidence JSONB NOT NULL DEFAULT '{}',
  risk JSONB NOT NULL DEFAULT '{}',
  remediation JSONB NOT NULL DEFAULT '{}',
  confidence DOUBLE PRECISION,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_engine ON findings(engine);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);

-- ---------- training queue + mapping registry (adaptive learning loop) ----------
CREATE TABLE IF NOT EXISTS training_queue (
  training_id TEXT PRIMARY KEY,
  vendor TEXT,
  platform TEXT,
  raw_command TEXT NOT NULL,
  context JSONB NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'PENDING',
  suggestion JSONB NOT NULL DEFAULT '{}',
  embedding vector(384),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_training_status ON training_queue(status);

CREATE TABLE IF NOT EXISTS mapping_registry (
  id TEXT PRIMARY KEY,
  vendor TEXT,
  platform TEXT,
  source_token TEXT NOT NULL,
  canonical_property TEXT NOT NULL,
  canonical_value JSONB,
  confidence DOUBLE PRECISION,
  status TEXT NOT NULL DEFAULT 'approved',
  approved_by TEXT,
  mapping_version TEXT NOT NULL DEFAULT '1.0',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mappings_token ON mapping_registry(source_token);

-- ---------- remediations / reports / background jobs ----------
CREATE TABLE IF NOT EXISTS remediations (
  id TEXT PRIMARY KEY,
  finding_id TEXT REFERENCES findings(finding_id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'PENDING',
  steps JSONB NOT NULL DEFAULT '[]',
  approved_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reports (
  report_id TEXT PRIMARY KEY,
  audit_id TEXT REFERENCES audits(audit_id) ON DELETE SET NULL,
  format TEXT NOT NULL DEFAULT 'PDF',
  status TEXT NOT NULL DEFAULT 'COMPLETED',
  download_path TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS jobs (
  job_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'COMPLETED',
  payload JSONB NOT NULL DEFAULT '{}',
  result JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- updated_at trigger for assets ----------
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_assets_touch ON assets;
CREATE TRIGGER trg_assets_touch BEFORE UPDATE ON assets
FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
