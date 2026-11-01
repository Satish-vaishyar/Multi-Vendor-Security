-- Migration 017: cloud security assessment module (docs/CLOUD_MODULE_RTM.md, step S02). Idempotent and purely additive:
-- four new tables, no change to any existing table. Every table carries org_id, so `python -m app.cli rls-enable`
-- (which enables row-level security on every table that has an org_id column) covers them without edits.
-- Cloud findings live here and never in `findings`, so existing dashboards, risk scores and reports are unchanged.

CREATE TABLE IF NOT EXISTS cloud_scans (
  scan_id          TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  mode             TEXT NOT NULL DEFAULT 'static' CHECK (mode IN ('static', 'live')),
  status           TEXT NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
  file_name        TEXT,
  content_sha256   TEXT,
  size_bytes       BIGINT,
  providers        JSONB NOT NULL DEFAULT '[]'::jsonb,
  formats          JSONB NOT NULL DEFAULT '[]'::jsonb,
  summary          JSONB NOT NULL DEFAULT '{}'::jsonb,
  coverage         JSONB NOT NULL DEFAULT '{}'::jsonb,
  rule_pack_version TEXT,
  engine_versions  JSONB NOT NULL DEFAULT '{}'::jsonb,
  error            TEXT,
  created_by       TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_cloud_scans_org_created ON cloud_scans (org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS cloud_resources (
  resource_id    TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  scan_id        TEXT NOT NULL REFERENCES cloud_scans(scan_id) ON DELETE CASCADE,
  resource_key   TEXT NOT NULL,
  provider       TEXT NOT NULL,
  service        TEXT,
  resource_type  TEXT NOT NULL,
  logical_name   TEXT,
  physical_id    TEXT,
  scope          JSONB NOT NULL DEFAULT '{}'::jsonb,
  properties     JSONB NOT NULL DEFAULT '{}'::jsonb,
  relationships  JSONB NOT NULL DEFAULT '[]'::jsonb,
  source         JSONB NOT NULL DEFAULT '{}'::jsonb,
  evidence_mode  TEXT NOT NULL DEFAULT 'static' CHECK (evidence_mode IN ('static', 'live')),
  confidence     DOUBLE PRECISION NOT NULL DEFAULT 1.0 CHECK (confidence >= 0 AND confidence <= 1),
  unknown_fields JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_cloud_resources_scan ON cloud_resources (org_id, scan_id);

CREATE TABLE IF NOT EXISTS cloud_findings (
  finding_id     TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  scan_id        TEXT NOT NULL REFERENCES cloud_scans(scan_id) ON DELETE CASCADE,
  resource_id    TEXT REFERENCES cloud_resources(resource_id) ON DELETE SET NULL,
  rule_id        TEXT NOT NULL,
  rule_version   TEXT,
  title          TEXT NOT NULL,
  severity       TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
  evidence_state TEXT NOT NULL CHECK (evidence_state IN
                   ('PASS_STATIC', 'FAIL_STATIC', 'UNKNOWN_STATIC', 'NOT_APPLICABLE',
                    'PASS_LIVE', 'FAIL_LIVE', 'UNKNOWN_LIVE', 'CONFLICT')),
  engine         TEXT NOT NULL DEFAULT 'orbit',
  observed       JSONB,
  expected       JSONB,
  source         JSONB NOT NULL DEFAULT '{}'::jsonb,
  frameworks     JSONB NOT NULL DEFAULT '[]'::jsonb,
  remediation    JSONB NOT NULL DEFAULT '{}'::jsonb,
  dedupe_key     TEXT,
  exception_id   TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cloud_findings_scan ON cloud_findings (org_id, scan_id, severity);
CREATE INDEX IF NOT EXISTS idx_cloud_findings_dedupe ON cloud_findings (scan_id, dedupe_key);

CREATE TABLE IF NOT EXISTS cloud_exceptions (
  exception_id  TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  rule_id       TEXT NOT NULL,
  resource_key  TEXT,
  owner         TEXT NOT NULL,
  justification TEXT NOT NULL,
  requested_by  TEXT,
  approved_by   TEXT,
  status        TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'REVOKED')),
  expires_at    TIMESTAMPTZ NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cloud_exceptions_lookup ON cloud_exceptions (org_id, rule_id, status);
