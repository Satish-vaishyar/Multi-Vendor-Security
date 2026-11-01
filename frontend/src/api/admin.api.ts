import { api, unwrap } from "./client";

export interface AdminUser {
  id: string;
  name: string;
  email: string;
  role: string;
  org_id: string;
  disabled: boolean;
  must_change_password: boolean;
}

export interface AuditLogRow {
  id: number;
  ts: string;
  actor_email: string | null;
  role: string | null;
  action: string;
  method: string | null;
  path: string | null;
  status: number | null;
  ip: string | null;
}

export async function listUsers() {
  const r = await api.get("/admin/users");
  return unwrap<{ items: AdminUser[]; total: number }>(r.data);
}

export async function createUser(body: { email: string; name: string; password: string; role: string }) {
  const r = await api.post("/admin/users", body);
  return unwrap<AdminUser>(r.data);
}

export async function patchUser(id: string, body: { role?: string; disabled?: boolean; new_password?: string }) {
  const r = await api.patch(`/admin/users/${id}`, body);
  return unwrap<AdminUser>(r.data);
}

export async function auditLog(params: { limit?: number; offset?: number; action?: string }) {
  const r = await api.get("/admin/audit-log", { params });
  return unwrap<{ items: AuditLogRow[]; limit: number; offset: number }>(r.data);
}
