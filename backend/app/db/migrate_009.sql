-- Risk acceptance / exceptions with four-eyes approval and mandatory expiry (P2-5).
CREATE TABLE IF NOT EXISTS finding_exceptions (
  exception_id TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  asset_id     TEXT NOT NULL,
  finding_key  TEXT NOT NULL,                      -- control_id / CVE id / analytics rule id (stable across audits)
  reason       TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'PENDING',    -- PENDING | APPROVED | REJECTED | REVOKED
  requested_by TEXT NOT NULL,
  decided_by   TEXT,
  decision_comment TEXT,
  expires_at   TIMESTAMPTZ NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_fexc_org_asset ON finding_exceptions (org_id, asset_id, status);
