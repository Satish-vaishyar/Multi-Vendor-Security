import { api, SLOW_TIMEOUT, unwrap } from "./client";

export interface CloudScan {
  scan_id: string;
  status: string;
  file_name?: string;
  providers?: string[];
  summary?: { states?: Record<string, number>; failed_by_severity?: Record<string, number>; resources?: number; statement?: string };
  coverage?: Record<string, unknown>;
  rule_pack_version?: string;
  created_by?: string;
  created_at?: string;
}

export interface CloudFinding {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: string;
  evidence_state: string;
  engine: string;
  source: { file?: string; line_start?: number; resource_address?: string; provider?: string; resource_type?: string; notes?: string[] };
  remediation?: { summary?: string; snippet?: { format: string; text: string; disclaimer: string } };
}

export const cloudStatus = async () =>
  unwrap<{ enabled: boolean; scanner: { status: string } }>((await api.get("/cloud/status")).data);
export const listCloudScans = async () => unwrap<{ items: CloudScan[] }>((await api.get("/cloud/scans")).data);
export const getCloudScan = async (id: string) => unwrap<CloudScan>((await api.get(`/cloud/scans/${id}`)).data);
export const listCloudFindings = async (id: string, p: { state?: string; severity?: string; page: number }) =>
  unwrap<{ items: CloudFinding[]; total: number; page: number; size: number }>(
    (await api.get(`/cloud/scans/${id}/findings`, { params: { ...p, size: 50 } })).data);

export async function uploadCloudScan(file: File) {
  const form = new FormData();
  form.append("file", file);
  return unwrap<{ scan_id: string; status: string; statement: string }>(
    (await api.post("/cloud/scans", form, { timeout: SLOW_TIMEOUT, headers: { "Content-Type": "multipart/form-data" } })).data);
}

/** Download through the authenticated client (a plain link would lack the bearer token). */
export async function downloadCloudScan(id: string, format: "json" | "csv" | "sarif") {
  const r = await api.get(`/cloud/scans/${id}/export`, { params: { format }, responseType: "blob" });
  const url = URL.createObjectURL(r.data as Blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${id}.${format}`;
  a.click();
  URL.revokeObjectURL(url);
}
