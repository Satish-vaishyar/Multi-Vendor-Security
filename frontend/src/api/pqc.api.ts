import { api, unwrap } from "./client";

export async function getPqc(auditId: string) {
  const r = await api.get(`/pqc/${auditId}`);
  return unwrap(r.data);
}
