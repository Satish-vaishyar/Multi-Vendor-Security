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

export async function uploadCloudScan(file: File, retain = false) {
  const form = new FormData();
  form.append("file", file);
  return unwrap<{ scan_id: string; status: string; statement: string; retention?: { kept: boolean; reason?: string } | null }>(
    (await api.post("/cloud/scans", form, { params: retain ? { retain: true } : undefined, timeout: SLOW_TIMEOUT, headers: { "Content-Type": "multipart/form-data" } })).data);
}

/** Download through the authenticated client (a plain link would lack the bearer token). */
export async function downloadCloudScan(id: string, format: "json" | "csv" | "sarif" | "pdf") {
  const r = await api.get(`/cloud/scans/${id}/export`, { params: { format }, responseType: "blob" });
  const url = URL.createObjectURL(r.data as Blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${id}.${format}`;
  a.click();
  URL.revokeObjectURL(url);
}

/* Recurring scans, webhook links and asset links (RTM S23). All opt-in; the kept file is encrypted and expires. */
export interface CloudSchedule {
  schedule_id: string; source_id: string; scan_id?: string | null; name: string; interval_minutes: number; enabled: boolean;
  next_run_at: number | null; last_run_at: number | null; last_scan_id?: string | null; last_status?: string | null;
}
export interface CloudWebhookLink { webhook_id: string; name: string; format: string; enabled: boolean; events: string[] }
export interface CloudAssetLink { asset_id: string; asset_name: string }

export const getKeptFile = async (scanId: string) =>
  unwrap<{ kept: boolean; expires_at: string | null }>((await api.get(`/cloud/scans/${scanId}/source`)).data);
export const deleteKeptFile = async (scanId: string) => unwrap<{ deleted: boolean }>((await api.delete(`/cloud/scans/${scanId}/source`)).data);
export const listCloudSchedules = async () =>
  unwrap<{ items: CloudSchedule[]; limits: { min_interval_minutes: number; max_schedules: number; retention_days: number } }>(
    (await api.get("/cloud/schedules")).data);
export const createCloudSchedule = async (b: { scan_id: string; interval_minutes: number; name?: string }) =>
  unwrap<CloudSchedule>((await api.post("/cloud/schedules", b)).data);
export const patchCloudSchedule = async (id: string, b: { enabled?: boolean; interval_minutes?: number }) =>
  unwrap<CloudSchedule>((await api.patch(`/cloud/schedules/${id}`, b)).data);
export const deleteCloudSchedule = async (id: string) => unwrap<{ deleted: boolean }>((await api.delete(`/cloud/schedules/${id}`)).data);
export const runCloudSchedule = async (id: string) =>
  unwrap<{ status: string; scan_id: string | null }>((await api.post(`/cloud/schedules/${id}/run`, undefined, { timeout: SLOW_TIMEOUT })).data);
export const listCloudWebhookLinks = async () =>
  unwrap<{ items: CloudWebhookLink[]; events: string[]; formats: string[] }>((await api.get("/cloud/webhook-links")).data);
export const linkCloudWebhook = async (id: string, events: string[]) =>
  unwrap<{ webhook_id: string; events: string[] }>((await api.put(`/cloud/webhook-links/${id}`, { events })).data);
export const unlinkCloudWebhook = async (id: string) => unwrap<{ deleted: boolean }>((await api.delete(`/cloud/webhook-links/${id}`)).data);
export const listScanAssets = async (scanId: string) => unwrap<{ items: CloudAssetLink[] }>((await api.get(`/cloud/scans/${scanId}/assets`)).data);
export const linkScanAsset = async (scanId: string, assetId: string) =>
  unwrap<CloudAssetLink>((await api.post(`/cloud/scans/${scanId}/assets`, { asset_id: assetId })).data);
export const unlinkScanAsset = async (scanId: string, assetId: string) =>
  unwrap<{ deleted: boolean }>((await api.delete(`/cloud/scans/${scanId}/assets/${encodeURIComponent(assetId)}`)).data);
export const listExistingWebhooks = async () =>
  unwrap<{ items: { webhook_id: string; name: string; format: string; enabled: boolean }[] }>((await api.get("/integrations/webhooks")).data);
