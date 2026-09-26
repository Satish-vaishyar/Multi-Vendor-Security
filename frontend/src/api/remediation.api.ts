import { api, unwrap } from "./client";

export async function getRemediation(findingId: string) {
  const r = await api.get(`/remediation/${findingId}`);
  return unwrap(r.data);
}

export async function approveRemediation(findingId: string, body: { approved_by: string; comment?: string }) {
  const r = await api.post(`/remediation/${findingId}/approve`, body);
  return unwrap<{ id: string } & Record<string, unknown>>(r.data);
}

export async function applyRemediation(findingId: string, body: { id: string; updated_config_text: string }) {
  const r = await api.post(`/remediation/${findingId}/apply`, body);
  return unwrap(r.data);
}
