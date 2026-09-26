import { api, unwrap } from "./client";

export async function getFrameworks() {
  const r = await api.get("/compliance/frameworks");
  return unwrap(r.data);
}

export async function getComplianceOverall(auditId: string) {
  const r = await api.get(`/compliance/${auditId}`);
  return unwrap(r.data);
}

export async function getComplianceFramework(auditId: string, fw: string) {
  const r = await api.get(`/compliance/${auditId}/framework/${fw}`);
  return unwrap(r.data);
}

export async function getComplianceControls(auditId: string) {
  const r = await api.get(`/compliance/${auditId}/controls`);
  return unwrap<{ items: unknown[] } & Record<string, unknown>>(r.data);
}
