-- Migration 002: generic record payload column for DB-backed persistence.
-- Every table keeps its typed key/filter columns; the full API record dict
-- lives in `data` so reads come from Postgres only (no in-memory store).
-- Idempotent (IF NOT EXISTS).

ALTER TABLE users            ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}';
ALTER TABLE assets           ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}';
ALTER TABLE configurations   ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}';
ALTER TABLE audits           ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}';
ALTER TABLE findings         ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}';
ALTER TABLE training_queue   ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}';
ALTER TABLE mapping_registry ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}';
ALTER TABLE remediations     ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}';
ALTER TABLE reports          ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}';
ALTER TABLE jobs             ADD COLUMN IF NOT EXISTS data JSONB NOT NULL DEFAULT '{}';

-- Report PDFs are bytes: dedicated BYTEA column (never JSON).
ALTER TABLE reports ADD COLUMN IF NOT EXISTS pdf BYTEA;
