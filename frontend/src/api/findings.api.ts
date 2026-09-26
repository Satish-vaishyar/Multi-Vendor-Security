import { api, unwrap } from "./client";
import type { Finding } from "../types";

export async function listFindings(params: Record<string, string | number | boolean | undefined> = {}) {
  const clean: Record<string, string | number | boolean> = {};
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") clean[k] = v;
  const r = await api.get("/findings", { params: clean });
  return unwrap<{ items: Finding[]; total: number }>(r.data);
}

export async function getFinding(id: string): Promise<Finding> {
  const r = await api.get(`/findings/${id}`);
  return unwrap<Finding>(r.data);
}
