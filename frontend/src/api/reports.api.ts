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
