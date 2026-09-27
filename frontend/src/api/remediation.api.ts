import { api, unwrap } from "./client";

export interface RemediationStep {
  order: number;
  command: string;
}

export interface RemediationPlan {
  finding_id: string;
  title: string;
  severity: string;
  engine: string;
  type: string;
  control_id: string;
  status: string;
  asset_id: string;
  audit_id: string;
  fix_title: string;
  source: string;
  vendor: string;
  platform: string;
  vendor_version: string;
  steps: RemediationStep[];
  validation: string[];
  rollback: string[];
  rollback_available: boolean;
  approval_required: boolean;
  risk: Record<string, unknown>;
  evidence: Record<string, unknown>;
  remediation_detail: Record<string, unknown>;
}

export interface RemediationHistoryItem {
  id: string;
  finding_id: string;
  status: string;
  approved_by: string;
  comment: string;
  approved_at?: number;
  created_at?: number;
}

export async function getRemediation(findingId: string): Promise<RemediationPlan> {
  const r = await api.get(`/remediation/${encodeURIComponent(findingId)}`);
  return unwrap<RemediationPlan>(r.data);
}

export async function getRemediationHistory(findingId: string) {
  const r = await api.get(`/remediation/${encodeURIComponent(findingId)}/history`);
  return unwrap<{ finding_id: string; items: RemediationHistoryItem[]; total: number }>(r.data);
}

export async function approveRemediation(findingId: string, body: { approved_by: string; comment?: string }) {
  const r = await api.post(`/remediation/${encodeURIComponent(findingId)}/approve`, body);
  return unwrap<{ id: string } & Record<string, unknown>>(r.data);
}

export async function applyRemediation(findingId: string, body: { id: string; updated_config_text: string }) {
  const r = await api.post(`/remediation/${encodeURIComponent(findingId)}/apply`, body);
  return unwrap(r.data);
}
