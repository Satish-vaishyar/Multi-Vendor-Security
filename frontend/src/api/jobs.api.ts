import { SLOW_TIMEOUT, api, unwrap } from "./client";

export interface Job {
  job_id: string;
  kind: "audit" | "report" | string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED" | string;
  progress: number;
  error?: string | null;
  attempts: number;
  max_attempts: number;
  batch_id?: string | null;
  created_by?: string | null;
  payload: Record<string, unknown>;
  result: Record<string, unknown>;
  created_at?: number;
  started_at?: number | null;
  finished_at?: number | null;
}

export interface BatchSummary {
  batch_id: string;
  total: number;
  finished: number;
  progress_pct: number;
  counts: Record<string, number>;
  state: "RUNNING" | "COMPLETED" | "FINISHED_WITH_ERRORS";
}

export interface BulkAuditResult {
  batch_id: string;
  accepted: number;
  rejected: { filename: string; reason: string }[];
  jobs: { filename: string; device: string; asset_id: string; configuration_id: string; job_id: string }[];
}

export async function listJobs(params: { status?: string; kind?: string; batch_id?: string; limit?: number } = {}) {
  const r = await api.get("/jobs", { params });
  return unwrap<{ items: Job[] }>(r.data).items;
}

export async function getBatch(batchId: string) {
  const r = await api.get(`/jobs/batches/${batchId}`);
  return unwrap<BatchSummary>(r.data);
}

export async function bulkAudit(files: File[], opts: { frameworks: string[]; criticality: string; runCve: boolean }) {
  const fd = new FormData();
  files.forEach((f) => fd.append("files", f));
  fd.append("frameworks", opts.frameworks.join(","));
  fd.append("criticality", opts.criticality);
  fd.append("run_cve", String(opts.runCve));
  const r = await api.post("/jobs/bulk-audit", fd, { headers: { "Content-Type": "multipart/form-data" }, timeout: SLOW_TIMEOUT });
  return unwrap<BulkAuditResult>(r.data);
}

export async function cancelJob(id: string) {
  const r = await api.post(`/jobs/${id}/cancel`);
  return unwrap<{ job_id: string; status: string }>(r.data);
}

export async function retryJob(id: string) {
  const r = await api.post(`/jobs/${id}/retry`);
  return unwrap<{ job_id: string; status: string }>(r.data);
}
