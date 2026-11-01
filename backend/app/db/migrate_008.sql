-- Migration 008: outbound webhooks (notifications) and their delivery log. Idempotent.

CREATE TABLE IF NOT EXISTS webhooks (
  webhook_id   TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL DEFAULT 'ORG-DEFAULT' REFERENCES organizations(org_id),
  name         TEXT NOT NULL,
  url          TEXT NOT NULL,
  secret_enc   TEXT NOT NULL,                      -- HMAC signing secret, encrypted at rest (enc:v1:...)
  events       JSONB NOT NULL DEFAULT '[]',
  format       TEXT NOT NULL DEFAULT 'json',       -- json | slack | teams
  enabled      BOOLEAN NOT NULL DEFAULT true,
  consecutive_failures INT NOT NULL DEFAULT 0,
  disabled_reason TEXT,
  last_status  TEXT,
  last_delivery_at TIMESTAMPTZ,
  created_by   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks (org_id) WHERE enabled;

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  delivery_id  TEXT PRIMARY KEY,
  webhook_id   TEXT NOT NULL,
  org_id       TEXT NOT NULL DEFAULT 'ORG-DEFAULT',
  event        TEXT NOT NULL,
  status       TEXT NOT NULL,                      -- SUCCESS | FAILED
  http_status  INT,
  error        TEXT,
  attempt      INT NOT NULL DEFAULT 1,
  duration_ms  INT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_deliveries_hook ON webhook_deliveries (webhook_id, created_at DESC);
