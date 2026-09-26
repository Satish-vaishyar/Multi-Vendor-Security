-- Migration 003: filter columns used by the persistence layer.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS control_id TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION;
