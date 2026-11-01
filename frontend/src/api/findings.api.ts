import { api, unwrap } from "./client";
import type { Finding } from "../types";

export async function listFindings(params: Record<string, string | number | boolean | undefined> = {}) {
  const clean: Record<string, string | number | boolean> = {};
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") clean[k] = v;
  // Backend stores CVE findings as type VULNERABILITY — translate the UI label.
  if (String(clean.type ?? "").toUpperCase() === "CVE") clean.type = "VULNERABILITY";
  // Server-side pagination: callers that do not page get the largest page (200).
  if (clean.page_size === undefined) clean.page_size = 200;
  const r = await api.get("/findings", { params: clean });
  return unwrap<{ items: Finding[]; total: number; page: number; page_size: number }>(r.data);
}

export async function getFinding(id: string): Promise<Finding> {
  const r = await api.get(`/findings/${id}`);
  return unwrap<Finding>(r.data);
}
