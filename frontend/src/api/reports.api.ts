import { SLOW_TIMEOUT, api, unwrap } from "./client";
import type { ReportRecord } from "../types";

export async function createReport(body: { audit_id: string; format?: string; sections?: string[] }): Promise<ReportRecord> {
  const r = await api.post("/reports", body, { timeout: SLOW_TIMEOUT });
  return unwrap<ReportRecord>(r.data);
}

export async function getReport(id: string): Promise<ReportRecord> {
  const r = await api.get(`/reports/${id}`);
  return unwrap<ReportRecord>(r.data);
}

export async function downloadReport(id: string): Promise<Blob> {
  const r = await api.get(`/reports/${id}/download`, { responseType: "blob" });
  return r.data as Blob;
}

export interface Signoff { signoff_id: string; report_id: string; signed_by: string; role: string; comment: string; signed_at: number; report_sha256: string }

export async function listSignoffs(id: string): Promise<Signoff[]> {
  const r = await api.get(`/reports/${id}/signoffs`);
  return unwrap<{ items: Signoff[] }>(r.data).items;
}

export async function signReport(id: string, comment: string): Promise<Signoff> {
  const r = await api.post(`/reports/${id}/signoff`, { comment });
  return unwrap<Signoff>(r.data);
}

/** Authenticated file download (a plain link would lack the bearer token). */
async function saveBlob(url: string, params: Record<string, string | number>, filename: string) {
  const r = await api.get(url, { params, responseType: "blob", timeout: SLOW_TIMEOUT });
  const href = URL.createObjectURL(r.data as Blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(href);
}

export const downloadFleet = (format: "pdf" | "csv" | "json") => saveBlob("/reports/fleet", { format }, `fleet-report.${format}`);
export const downloadEvidencePack = (auditId: string, framework: string, format: "csv" | "json") =>
  saveBlob(`/reports/evidence/${auditId}`, { framework, format }, `${auditId}-${framework}-evidence.${format}`);
