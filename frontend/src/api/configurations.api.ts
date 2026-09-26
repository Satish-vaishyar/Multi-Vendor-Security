import { SLOW_TIMEOUT, api, unwrap } from "./client";
import type { ConfigurationMeta } from "../types";

export async function uploadConfiguration(file: File, asset_id: string, vendor = "", platform = ""): Promise<ConfigurationMeta> {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("asset_id", asset_id);
  if (vendor) fd.append("vendor", vendor);
  if (platform) fd.append("platform", platform);
  const r = await api.post("/configurations/upload", fd, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: SLOW_TIMEOUT,
  });
  return unwrap<ConfigurationMeta>(r.data);
}

export async function bulkUpload(files: File[], asset_id: string) {
  const fd = new FormData();
  files.forEach((f) => fd.append("files", f));
  fd.append("asset_id", asset_id);
  const r = await api.post("/configurations/bulk-upload", fd, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: SLOW_TIMEOUT,
  });
  return unwrap(r.data);
}

export async function parseConfiguration(id: string) {
  const r = await api.post(`/configurations/${id}/parse`);
  return unwrap(r.data);
}

export async function getConfiguration(id: string): Promise<ConfigurationMeta> {
  const r = await api.get(`/configurations/${id}`);
  return unwrap<ConfigurationMeta>(r.data);
}

export async function getCanonicalIr(id: string): Promise<Record<string, unknown>> {
  const r = await api.get(`/configurations/${id}/canonical-ir`);
  return unwrap<Record<string, unknown>>(r.data);
}

export async function getUnknowns(id: string): Promise<{ unknown_count?: number; total?: number; items: unknown[] }> {
  const r = await api.get(`/configurations/${id}/unknowns`, { timeout: SLOW_TIMEOUT });
  return unwrap(r.data);
}
