import { api, unwrap } from "./client";

export async function okfProperties(category?: string) {
  const r = await api.get("/okf/properties", { params: category ? { category } : {} });
  return unwrap(r.data);
}

export async function okfControls(params: Record<string, string> = {}) {
  const r = await api.get("/okf/controls", { params });
  return unwrap(r.data);
}

export async function okfControl(id: string) {
  const r = await api.get(`/okf/controls/${id}`);
  return unwrap(r.data);
}

export async function okfCrosswalk(id: string) {
  const r = await api.get(`/okf/crosswalk/${id}`);
  return unwrap(r.data);
}

export async function detectVendor(body: { configuration_id?: string; config_text?: string }) {
  const r = await api.post("/detection/vendor", body);
  return unwrap<Record<string, unknown>>(r.data);
}
