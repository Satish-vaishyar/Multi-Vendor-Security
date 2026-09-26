-- OKF PostgreSQL schema v1.0.0
-- Covers okf.md §18-19 (knowledge tables) + cve_okf.md §14 (vulnerability tables).
-- Apply: psql -d okf -f 001_okf.sql  (requires pgcrypto for gen_random_uuid)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------- OKF knowledge ----------
CREATE TABLE IF NOT EXISTS canonical_properties (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  property_id TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT 'general',
  datatype TEXT NOT NULL DEFAULT 'boolean',
  description TEXT NOT NULL DEFAULT '',
  allowed_values JSONB NOT NULL DEFAULT '[]',
  security_level TEXT NOT NULL DEFAULT 'MEDIUM',
  version TEXT NOT NULL DEFAULT '1.0'
);
CREATE TABLE IF NOT EXISTS frameworks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  framework_id TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL, version TEXT NOT NULL DEFAULT '',
  publisher TEXT NOT NULL DEFAULT '', source_url TEXT NOT NULL DEFAULT '',
  release_date DATE
);
CREATE TABLE IF NOT EXISTS controls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  control_id TEXT UNIQUE NOT NULL, title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'general',
  severity TEXT NOT NULL DEFAULT 'MEDIUM', framework_id TEXT REFERENCES frameworks(framework_id),
  version TEXT NOT NULL DEFAULT '1.0', evidence_type TEXT NOT NULL DEFAULT 'CONFIGURATION',
  remediation_id TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), source TEXT NOT NULL DEFAULT 'curated',
  author TEXT NOT NULL DEFAULT 'okf'
);
CREATE TABLE IF NOT EXISTS control_conditions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  control_id TEXT REFERENCES controls(control_id) ON DELETE CASCADE,
  property_id TEXT REFERENCES canonical_properties(property_id),
  operator TEXT NOT NULL DEFAULT 'EQUALS', expected_value JSONB,
  logical_group TEXT NOT NULL DEFAULT 'all', position INT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS framework_controls (
  framework_id TEXT REFERENCES frameworks(framework_id),
  control_id TEXT REFERENCES controls(control_id) ON DELETE CASCADE,
  framework_control_id TEXT NOT NULL,
  PRIMARY KEY (framework_id, control_id)
);
CREATE TABLE IF NOT EXISTS crosswalks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_control TEXT NOT NULL, target_control TEXT NOT NULL,
  relationship TEXT NOT NULL DEFAULT 'equivalent',
  confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
  UNIQUE (source_control, target_control)
);
CREATE TABLE IF NOT EXISTS evidence_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  control_id TEXT REFERENCES controls(control_id) ON DELETE CASCADE,
  property_id TEXT NOT NULL, operator TEXT NOT NULL DEFAULT 'EQUALS',
  expected_value JSONB, evidence_type TEXT NOT NULL DEFAULT 'CONFIGURATION'
);
CREATE TABLE IF NOT EXISTS compliance_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  control_id TEXT REFERENCES controls(control_id) ON DELETE CASCADE,
  rule_yaml TEXT NOT NULL, version TEXT NOT NULL DEFAULT '1.0'
);
CREATE TABLE IF NOT EXISTS remediation_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  remediation_id TEXT UNIQUE NOT NULL, control_id TEXT REFERENCES controls(control_id),
  vendor TEXT NOT NULL DEFAULT 'any', platform TEXT NOT NULL DEFAULT 'any',
  version_range TEXT NOT NULL DEFAULT '', commands JSONB NOT NULL DEFAULT '[]',
  validation JSONB NOT NULL DEFAULT '[]', rollback JSONB NOT NULL DEFAULT '[]',
  approval_required BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS vendor_mappings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor TEXT NOT NULL, platform TEXT NOT NULL DEFAULT 'any', version TEXT NOT NULL DEFAULT '',
  raw_command TEXT NOT NULL, canonical_property TEXT REFERENCES canonical_properties(property_id),
  canonical_value JSONB, confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
  source TEXT NOT NULL DEFAULT 'curated', approved_by TEXT, status TEXT NOT NULL DEFAULT 'approved',
  mapping_version TEXT NOT NULL DEFAULT '1.0', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS exceptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  control_id TEXT REFERENCES controls(control_id), asset_id TEXT NOT NULL,
  reason TEXT NOT NULL, approved_by TEXT NOT NULL, expiry DATE
);
CREATE TABLE IF NOT EXISTS risk_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT UNIQUE NOT NULL, weights JSONB NOT NULL DEFAULT '{}', version TEXT NOT NULL DEFAULT '1.0'
);
CREATE TABLE IF NOT EXISTS dependencies (
  control_id TEXT REFERENCES controls(control_id) ON DELETE CASCADE,
  depends_on TEXT NOT NULL, PRIMARY KEY (control_id, depends_on)
);
CREATE TABLE IF NOT EXISTS okf_versions (
  component TEXT PRIMARY KEY, version TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- audit runtime ----------
CREATE TABLE IF NOT EXISTS audit_runs (
  audit_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL, config_hash TEXT NOT NULL,
  parser_version TEXT NOT NULL DEFAULT '1.0', mapping_version TEXT NOT NULL DEFAULT '1.0',
  control_pack_version TEXT NOT NULL DEFAULT '1.0', cve_db_version TEXT NOT NULL DEFAULT '1.0',
  pqc_rules_version TEXT NOT NULL DEFAULT '1.0', canonical_ir JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT PRIMARY KEY, audit_id TEXT REFERENCES audit_runs(audit_id),
  engine TEXT NOT NULL DEFAULT 'compliance', type TEXT NOT NULL DEFAULT 'COMPLIANCE',
  control_id TEXT, cve_id TEXT, title TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'MEDIUM',
  status TEXT NOT NULL DEFAULT 'OPEN', asset_id TEXT NOT NULL,
  evidence JSONB NOT NULL DEFAULT '{}', risk JSONB NOT NULL DEFAULT '{}',
  remediation JSONB NOT NULL DEFAULT '{}', confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS approvals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), kind TEXT NOT NULL,
  ref_id TEXT NOT NULL, decided_by TEXT NOT NULL, decision TEXT NOT NULL,
  comment TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- vulnerability KB (cve_okf §14) ----------
CREATE TABLE IF NOT EXISTS cves (
  cve_id TEXT PRIMARY KEY, description TEXT NOT NULL DEFAULT '',
  published_date DATE, last_modified DATE, source TEXT NOT NULL DEFAULT 'NVD'
);
CREATE TABLE IF NOT EXISTS cve_cvss (
  cve_id TEXT REFERENCES cves(cve_id) ON DELETE CASCADE,
  version TEXT NOT NULL, base_score DOUBLE PRECISION, severity TEXT,
  vector TEXT NOT NULL DEFAULT '', exploitability_score DOUBLE PRECISION,
  impact_score DOUBLE PRECISION, PRIMARY KEY (cve_id, version)
);
CREATE TABLE IF NOT EXISTS cve_cwe (cve_id TEXT REFERENCES cves(cve_id) ON DELETE CASCADE, cwe TEXT NOT NULL, PRIMARY KEY (cve_id, cwe));
CREATE TABLE IF NOT EXISTS cve_references (cve_id TEXT REFERENCES cves(cve_id) ON DELETE CASCADE, url TEXT NOT NULL, tags JSONB NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS cpe_dictionary (cpe TEXT PRIMARY KEY, vendor TEXT NOT NULL, product TEXT NOT NULL, version TEXT NOT NULL DEFAULT '', deprecated BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE IF NOT EXISTS cpe_match_criteria (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), cve_id TEXT REFERENCES cves(cve_id) ON DELETE CASCADE,
  cpe TEXT NOT NULL, start_version TEXT, start_operator TEXT, end_version TEXT, end_operator TEXT,
  vulnerable BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS cve_products (cve_id TEXT REFERENCES cves(cve_id) ON DELETE CASCADE, vendor TEXT NOT NULL, product TEXT NOT NULL, cpe TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cve_version_ranges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), cve_id TEXT REFERENCES cves(cve_id) ON DELETE CASCADE,
  cpe TEXT NOT NULL, start_version TEXT, start_inclusive BOOLEAN NOT NULL DEFAULT TRUE,
  end_version TEXT, end_inclusive BOOLEAN NOT NULL DEFAULT TRUE, vulnerable BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS cve_matches (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), audit_id TEXT REFERENCES audit_runs(audit_id),
  asset_id TEXT NOT NULL, cve_id TEXT REFERENCES cves(cve_id), product TEXT NOT NULL,
  installed_version TEXT NOT NULL, affected BOOLEAN NOT NULL, fixed_version TEXT,
  confidence JSONB NOT NULL DEFAULT '{}', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS crypto_assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), audit_id TEXT REFERENCES audit_runs(audit_id),
  asset_id TEXT NOT NULL, protocol TEXT NOT NULL, algorithm TEXT NOT NULL,
  key_size INT, usage TEXT NOT NULL DEFAULT '', location TEXT NOT NULL DEFAULT '',
  class TEXT NOT NULL DEFAULT 'classical', pqc_status TEXT NOT NULL DEFAULT 'unknown'
);
INSERT INTO okf_versions(component, version) VALUES
  ('okf', '1.0.0'), ('canonical_ir', '1.0'), ('control_pack', '1.0'),
  ('cve_db', 'seed-1'), ('pqc_rules', '1.0'), ('risk_model', 'rules-1')
ON CONFLICT (component) DO NOTHING;
