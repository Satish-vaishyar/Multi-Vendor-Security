import { api, unwrap } from "./client";

export interface RiskException {
  exception_id: string;
  asset_id: string;
  finding_key: string;
  reason: string;
  status: "PENDING" | "APPROVED" | "REJECTED" | "REVOKED" | string;
  requested_by: string;
  decided_by?: string | null;
  decision_comment?: string | null;
  expires_at: number;
  created_at: number;
  decided_at?: number | null;
  active: boolean;
}

export const listExceptions = async (status?: string) =>
  unwrap<{ items: RiskException[]; max_days: number }>((await api.get("/exceptions", { params: status ? { status } : {} })).data);
export const requestException = async (b: { asset_id: string; finding_key: string; reason: string; days: number }) =>
  unwrap<RiskException>((await api.post("/exceptions", b)).data);
export const decideException = async (id: string, op: "approve" | "reject" | "revoke", comment = "") =>
  unwrap<RiskException>((await api.post(`/exceptions/${id}/${op}`, { comment })).data);

/** Download findings as CSV/JSON through the authenticated client (a plain link would lack the bearer token). */
export async function downloadFindings(auditId: string, format: "csv" | "json") {
  const r = await api.get(`/reports/export/${auditId}`, { params: { format }, responseType: "blob" });
  const url = URL.createObjectURL(r.data as Blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${auditId}-findings.${format}`;
  a.click();
  URL.revokeObjectURL(url);
}
