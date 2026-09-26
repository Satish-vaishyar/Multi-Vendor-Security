-- Migration 004: findings keep their audit_id as a plain reference (no FK).
-- Rationale: findings are long-lived evidence; deleting an audit must not
-- wipe them, and offline/test fixtures may reference synthetic audit ids.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_audit_id_fkey;
