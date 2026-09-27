/* Shared TypeScript contracts mirroring the FastAPI Pydantic schemas (frontend.md §45).
   Backend is the source of truth — never hardcode backend data (§46). */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type FindingType = "COMPLIANCE" | "CVE" | "VULNERABILITY" | "PQC" | "SECURITY" | "CONFIGURATION";
export type FindingStatus = "OPEN" | "FAIL" | "PASS" | string;
export type AuditStatus = "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
export type ComplianceStatus = "PASS" | "FAIL" | "PARTIAL" | "NOT_APPLICABLE" | "UNKNOWN";
export type VulnStatus = "VULNERABLE" | "NOT_AFFECTED" | "UNKNOWN";
export type PqcStatus = "READY" | "TRANSITION" | "AT_RISK" | "UNKNOWN";
export type TrainingStatus = "PENDING" | "APPROVED" | "REJECTED";

export interface ApiSuccess<T> {
  success: true;
  data: T;
  message: string;
  request_id?: string;
}

export interface User {
  id: string;
  name: string;
  email: string;
  role: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: { id: string; name: string; role: string };
}

export interface Asset {
  asset_id: string;
  name: string;
  vendor?: string;
  product?: string;
  model?: string;
  version?: string;
  serial_number?: string;
  ip_address?: string;
  environment?: string;
  criticality?: string;
  status?: string;
  [k: string]: unknown;
}

export interface Paged<T> {
  items: T[];
  page: number;
  page_size: number;
  total: number;
}

export interface ConfigurationMeta {
  configuration_id: string;
  asset_id?: string;
  filename?: string;
  size?: number;
  status?: string;
  vendor?: string;
  platform?: string;
  version?: string;
  detected_vendor?: string;
  detected_platform?: string;
  detected_version?: string;
  parser?: { type: string; confidence: number };
  [k: string]: unknown;
}

export interface AuditRecord {
  audit_id: string;
  status: AuditStatus | string;
  progress?: number;
  stages?: Record<string, string>;
  summary?: AuditSummary;
  [k: string]: unknown;
}

export interface AuditSummary {
  compliance_score?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  [k: string]: unknown;
}

export interface FrameworkScore {
  score?: number;
  compliance_score?: number;
  total?: number;
  passed?: number;
  failed?: number;
  unknown?: number;
  [k: string]: unknown;
}

export interface AuditResults {
  audit_id: string;
  asset_id?: string;
  configuration_id?: string;
  status?: string;
  vendor?: Record<string, unknown>;
  summary?: AuditSummary;
  frameworks?: Record<string, FrameworkScore>;
  cve?: Record<string, unknown>;
  pqc?: Record<string, unknown>;
  security?: { risk_score?: number; anomalies_total?: number; patterns?: unknown[]; [k: string]: unknown };
  counts?: { total_findings?: number; by_engine?: Record<string, number>; by_severity?: Record<string, number>; by_status?: Record<string, number> };
  findings?: Finding[];
  unknown_lines?: string[];
  llm_offline?: boolean;
  config_sha256?: string;
  versions?: Record<string, string>;
  canonical_ir?: Record<string, unknown>;
  ir_validation?: Record<string, unknown>;
  [k: string]: unknown;
}

export interface EvidenceItem {
  control_id?: string;
  property?: string;
  observed_value?: unknown;
  expected_value?: unknown;
  source?: Record<string, unknown>;
  [k: string]: unknown;
}

export interface Finding {
  finding_id: string;
  type?: string;
  engine?: string;
  title?: string;
  severity?: Severity | string;
  asset_id?: string;
  audit_id?: string;
  status?: string;
  description?: string;
  evidence?: Record<string, unknown>;
  risk?: Record<string, unknown>;
  remediation?: Record<string, unknown>;
  asset?: Record<string, unknown>;
  source?: Record<string, unknown>;
  [k: string]: unknown;
}

export interface ControlItem {
  control_id: string;
  title?: string;
  status?: ComplianceStatus | string;
  severity?: Severity | string;
  evidence?: unknown;
  [k: string]: unknown;
}

export interface VulnItem {
  finding_id: string;
  cve_id?: string;
  product?: string;
  installed_version?: string;
  severity?: Severity | string;
  status?: VulnStatus | string;
  fixed_version?: string;
  cvss?: { score?: number; severity?: string; [k: string]: unknown };
  cpe?: string;
  [k: string]: unknown;
}

export interface TrainingItem {
  training_id: string;
  vendor?: string;
  platform?: string;
  raw_command?: string;
  context?: string[];
  status?: TrainingStatus | string;
  [k: string]: unknown;
}

export interface Suggestion {
  canonical_property: string;
  value?: unknown;
  confidence?: number;
  [k: string]: unknown;
}

export interface ReportRecord {
  report_id: string;
  status: string;
  download_url?: string;
  [k: string]: unknown;
}

export interface DashboardSummary {
  assets?: { total?: number; healthy?: number; at_risk?: number };
  compliance?: { overall?: number };
  findings?: { critical?: number; high?: number; medium?: number; low?: number };
  cve?: { critical?: number; high?: number };
  pqc?: { ready?: number; transition?: number; at_risk?: number; audits?: number };
  training?: { pending?: number };
  [k: string]: unknown;
}
