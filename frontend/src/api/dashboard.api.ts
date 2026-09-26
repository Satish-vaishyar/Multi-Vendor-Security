import { api, unwrap } from "./client";
import type { DashboardSummary } from "../types";

export async function getSummary(): Promise<DashboardSummary> {
  const r = await api.get("/dashboard/summary");
  return unwrap<DashboardSummary>(r.data);
}
