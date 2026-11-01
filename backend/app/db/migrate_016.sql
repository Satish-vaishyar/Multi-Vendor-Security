-- Migration 016: lab verification records for remediation templates. Idempotent.
-- A fix is labelled "lab-verified" only when a record here proves it on a configuration pair: the control FAILED before
-- the fix and PASSED after it (and, when a rollback configuration was supplied, FAILED again after the rollback).
CREATE TABLE IF NOT EXISTS fix_verifications (
  verification_id TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  control_id      TEXT NOT NULL,
  vendor          TEXT NOT NULL,
  platform        TEXT NOT NULL DEFAULT '',
  os_version      TEXT,
  device_model    TEXT,
  status          TEXT NOT NULL CHECK (status IN ('VERIFIED', 'FAILED')),
  before_status   TEXT,
  after_status    TEXT,
  rollback_status TEXT,
  rollback_tested BOOLEAN NOT NULL DEFAULT false,
  reason          TEXT,
  evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
  verified_by     TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fix_verifications_lookup ON fix_verifications (org_id, control_id, vendor, created_at DESC);
