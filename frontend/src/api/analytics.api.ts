import { api, unwrap } from "./client";

export async function getAnalytics(auditId: string) {
  const r = await api.get(`/analytics/${auditId}`);
  return unwrap(r.data);
}

export async function startFleet(asset_ids: string[]) {
  const r = await api.post("/analytics/fleet", { asset_ids });
  return unwrap<{ job_id: string; status: string }>(r.data);
}

export async function fleetStatus(jobId: string) {
  const r = await api.get(`/analytics/fleet/${jobId}`);
  return unwrap(r.data);
}
