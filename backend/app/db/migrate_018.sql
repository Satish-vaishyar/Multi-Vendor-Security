-- Migration 018: cloud module extras (docs/CLOUD_MODULE_RTM.md S23): opt-in retained sources, recurring scans, links from cloud
-- scans to existing webhooks and assets. Idempotent and purely additive: new tables only, no change to any existing table. Rows that
-- point at existing tables (webhooks, assets) only reference them; deleting a link never touches the referenced row, and deleting
-- the referenced row removes just the link. Every table carries org_id so `rls-enable` covers them without edits.

-- An uploaded file is kept ONLY when the uploader asks for it and the scan found no hard-coded secret. Content is encrypted at rest
-- (core/crypto) and expires; it exists solely so a recurring scan can re-run the same bytes through the sandboxed scanner.
CREATE TABLE IF NOT EXISTS cloud_sources (
  source_id    TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  scan_id      TEXT NOT NULL REFERENCES cloud_scans(scan_id) ON DELETE CASCADE,
  file_name    TEXT,
  sha256       TEXT NOT NULL,
  size_bytes   BIGINT NOT NULL,
  content_enc  TEXT NOT NULL,
  created_by   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_sources_scan ON cloud_sources (scan_id);
CREATE INDEX IF NOT EXISTS idx_cloud_sources_org ON cloud_sources (org_id, expires_at);

CREATE TABLE IF NOT EXISTS cloud_schedules (
  schedule_id      TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  source_id        TEXT NOT NULL REFERENCES cloud_sources(source_id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  interval_minutes INTEGER NOT NULL CHECK (interval_minutes >= 60 AND interval_minutes <= 527040),
  enabled          BOOLEAN NOT NULL DEFAULT true,
  next_run_at      TIMESTAMPTZ NOT NULL,
  last_run_at      TIMESTAMPTZ,
  last_scan_id     TEXT,
  last_status      TEXT,
  created_by       TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cloud_schedules_due ON cloud_schedules (enabled, next_run_at);

-- Subscribes an EXISTING webhook (created, validated and delivered by the existing webhook machinery) to cloud events.
CREATE TABLE IF NOT EXISTS cloud_webhook_links (
  link_id    TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  webhook_id TEXT NOT NULL REFERENCES webhooks(webhook_id) ON DELETE CASCADE,
  events     JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, webhook_id)
);

-- Opt-in association of a cloud scan with an existing asset (read-only reference; the asset row is never modified).
CREATE TABLE IF NOT EXISTS cloud_asset_links (
  link_id    TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  scan_id    TEXT NOT NULL REFERENCES cloud_scans(scan_id) ON DELETE CASCADE,
  asset_id   TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, scan_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_cloud_asset_links_asset ON cloud_asset_links (org_id, asset_id);
