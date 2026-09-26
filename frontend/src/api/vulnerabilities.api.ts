import { api, unwrap } from "./client";

export async function getVulnsForAudit(auditId: string) {
  const r = await api.get(`/vulnerabilities/${auditId}`);
  return unwrap<{ summary?: Record<string, number>; items?: unknown[] } & Record<string, unknown>>(r.data);
}

export async function getVulnDetail(auditId: string, findingId: string) {
  const r = await api.get(`/vulnerabilities/${auditId}/${findingId}`);
  return unwrap(r.data);
}

export async function browseCves(params: Record<string, string | number> = {}) {
  const r = await api.get("/vulnerabilities/cves", { params });
  return unwrap(r.data);
}

export async function syncCves(body: Record<string, unknown> = {}) {
  const r = await api.post("/vulnerabilities/sync", body);
  return unwrap(r.data);
}

export async function syncStatus(jobId: string) {
  const r = await api.get(`/vulnerabilities/sync/${jobId}`);
  return unwrap(r.data);
}

export async function blastRadius(body: Record<string, unknown>) {
  const r = await api.post("/vulnerabilities/blast-radius", body);
  return unwrap(r.data);
}
