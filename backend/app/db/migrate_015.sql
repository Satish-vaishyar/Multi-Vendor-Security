-- Migration 015: live collection (read-only SSH). Idempotent.
CREATE TABLE IF NOT EXISTS device_credentials (
  credential_id TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  name          TEXT NOT NULL,
  username      TEXT NOT NULL,
  auth_type     TEXT NOT NULL DEFAULT 'password' CHECK (auth_type IN ('password', 'key')),
  secret_enc    TEXT NOT NULL,                      -- Fernet / KMS-envelope encrypted; never returned by any API
  created_by    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);
CREATE INDEX IF NOT EXISTS idx_device_credentials_org ON device_credentials (org_id);

CREATE TABLE IF NOT EXISTS collection_targets (
  asset_id          TEXT PRIMARY KEY REFERENCES assets(asset_id) ON DELETE CASCADE,
  org_id            TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  host              TEXT NOT NULL,
  port              INTEGER NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
  profile           TEXT NOT NULL,
  credential_id     TEXT REFERENCES device_credentials(credential_id) ON DELETE SET NULL,
  host_key          TEXT,                            -- pinned SHA256 fingerprint
  last_collected_at TIMESTAMPTZ,
  last_status       TEXT,
  last_error        TEXT,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_collection_targets_org ON collection_targets (org_id);
