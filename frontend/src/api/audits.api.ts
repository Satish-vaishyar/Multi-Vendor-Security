import { SLOW_TIMEOUT, api, unwrap } from "./client";
import type { AuditRecord, AuditResults, EvidenceItem } from "../types";

export interface CreateAuditBody {
  asset_id: string;
  configuration_id: string;
  frameworks: string[];
  run_cve: boolean;
  run_pqc: boolean;
  run_security_analysis: boolean;
  generate_report: boolean;
}

export async function createAudit(body: CreateAuditBody) {
  // Synchronous full-pipeline run (compliance + CVE + PQC + analytics) — slow when cold.
  const r = await api.post("/audits", body, { timeout: SLOW_TIMEOUT });
  return unwrap<{ audit_id: string; status: string }>(r.data);
}

/** Lightweight audit list for pickers (one call, no heavy payloads). */
export async function listAudits(): Promise<{ items: AuditListItem[]; total: number }> {
  const r = await api.get("/audits");
  return unwrap<{ items: AuditListItem[]; total: number }>(r.data);
}

export interface AuditListItem {
  audit_id: string;
  asset_id?: string;
  configuration_id?: string;
  status: string;
  progress?: number;
  summary?: { compliance_score?: number; critical?: number; high?: number; medium?: number; low?: number; security_risk?: number; pqc_readiness?: number };
  frameworks?: Record<string, { score?: number }>;
  cve?: Record<string, number>;
  engines?: Record<string, Record<string, number>>;
}

export async function getAudit(id: string): Promise<AuditRecord> {
  const r = await api.get(`/audits/${id}`);
  return unwrap<AuditRecord>(r.data);
}

export async function getAuditResults(id: string): Promise<AuditResults> {
  const r = await api.get(`/audits/${id}/results`);
  return unwrap<AuditResults>(r.data);
}

/** Lightweight brief (no findings/canonical_ir payload) for pickers. */
export async function getAuditSummary(id: string) {
  const r = await api.get(`/audits/${id}/summary`);
  return unwrap<{
    audit_id: string; status: string; progress?: number;
    summary?: { compliance_score?: number; critical?: number; high?: number; medium?: number; low?: number; security_risk?: number; pqc_readiness?: number };
    frameworks?: Record<string, { score?: number }>;
    cve?: Record<string, number>;
    engines?: Record<string, number>;
    engine_sev?: Record<string, Record<string, number>>;
  }>(r.data);
}

export async function getAuditEvidence(id: string): Promise<{ items: EvidenceItem[] }> {
  const r = await api.get(`/audits/${id}/evidence`);
  return unwrap<{ items: EvidenceItem[] }>(r.data);
}
