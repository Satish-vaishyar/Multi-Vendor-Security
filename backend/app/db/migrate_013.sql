-- Migration 013: report sign-off (auditor approval of an issued report) + optional encrypted auth header for webhooks. Idempotent.

CREATE TABLE IF NOT EXISTS report_signoffs (
  signoff_id    TEXT PRIMARY KEY,
  report_id     TEXT NOT NULL REFERENCES reports(report_id) ON DELETE CASCADE,
  org_id        TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  signed_by     TEXT NOT NULL,
  role          TEXT NOT NULL,
  comment       TEXT NOT NULL DEFAULT '',
  signed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  report_sha256 TEXT NOT NULL                       -- SHA-256 of the report PDF at the moment of signing
);
CREATE INDEX IF NOT EXISTS idx_report_signoffs_report ON report_signoffs (report_id, signed_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_report_signoffs_user ON report_signoffs (report_id, signed_by);

-- optional "Header-Name: value" credential for ticketing receivers (Jira / ServiceNow); Fernet-encrypted, never returned by the API
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS auth_header_enc TEXT;
