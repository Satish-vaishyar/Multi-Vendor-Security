-- Indexes for server-side pagination / filtering / sorting and dashboard aggregates.
-- Idempotent: safe to re-run. Every list query is org-scoped, so org_id leads.
CREATE INDEX IF NOT EXISTS idx_findings_org_created   ON findings(org_id, created_at DESC, finding_id);
CREATE INDEX IF NOT EXISTS idx_findings_org_audit     ON findings(org_id, audit_id);
CREATE INDEX IF NOT EXISTS idx_findings_org_asset     ON findings(org_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_org_sev_stat  ON findings(org_id, severity, status);
CREATE INDEX IF NOT EXISTS idx_findings_org_engine    ON findings(org_id, engine, status);
CREATE INDEX IF NOT EXISTS idx_findings_fail_control  ON findings(org_id, control_id) WHERE UPPER(status) = 'FAIL';
CREATE INDEX IF NOT EXISTS idx_assets_org_created     ON assets(org_id, created_at DESC, asset_id);
CREATE INDEX IF NOT EXISTS idx_assets_org_status      ON assets(org_id, status, vendor);
CREATE INDEX IF NOT EXISTS idx_audits_org_created     ON audits(org_id, created_at DESC, audit_id);
CREATE INDEX IF NOT EXISTS idx_audits_org_asset_ts    ON audits(org_id, asset_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audits_org_status      ON audits(org_id, status);
CREATE INDEX IF NOT EXISTS idx_reports_org_created    ON reports(org_id, created_at DESC, report_id);
CREATE INDEX IF NOT EXISTS idx_reports_org_audit      ON reports(org_id, audit_id);
CREATE INDEX IF NOT EXISTS idx_training_org_status    ON training_queue(org_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_remediations_org_find  ON remediations(org_id, finding_id, created_at DESC);
