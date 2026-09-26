import { SLOW_TIMEOUT, api, unwrap } from "./client";

export async function trainingQueue(status = "PENDING") {
  const r = await api.get("/training/queue", { params: { status } });
  return unwrap<{ items: unknown[]; total?: number } & Record<string, unknown>>(r.data);
}

export async function suggestMapping(trainingId: string) {
  // Hits the LLM gateway (or heuristic fallback) — can be slow when cold.
  const r = await api.post(`/training/${trainingId}/suggest`, null, { timeout: SLOW_TIMEOUT });
  return unwrap(r.data);
}

export async function approveMapping(trainingId: string, body: { canonical_property: string; canonical_value: unknown; comment?: string }) {
  const r = await api.post(`/training/${trainingId}/approve`, body);
  return unwrap(r.data);
}

export async function rejectMapping(trainingId: string, reason: string) {
  const r = await api.post(`/training/${trainingId}/reject`, { reason });
  return unwrap(r.data);
}

export async function trainingJob(jobId: string) {
  const r = await api.get(`/training/jobs/${jobId}`);
  return unwrap(r.data);
}
