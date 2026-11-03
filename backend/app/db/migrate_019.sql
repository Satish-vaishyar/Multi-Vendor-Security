-- Shared token buckets for the API rate limiter and the login IP throttle, so every API process and replica counts
-- against the same budget (keys: org:<id>, user:<id>, ip:<addr>). Holds no tenant data and no secrets; idle rows are pruned.
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  bucket_key TEXT PRIMARY KEY,
  tokens     DOUBLE PRECISION NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_updated ON rate_limit_buckets (updated_at);
