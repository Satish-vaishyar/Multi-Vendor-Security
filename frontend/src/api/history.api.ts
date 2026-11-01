import { api, unwrap } from "./client";

export interface SnapshotChanges {
  previous_snapshot_id?: string;
  new?: number;
  resolved?: number;
  severity_increased?: number;
  unchanged?: number;
  new_critical_high?: number;
  config_changed?: boolean;
  knowledge_changed?: string[];
  score_delta?: number;
}

export interface Snapshot {
  snapshot_id: string;
  audit_id: string;
  configuration_id?: string | null;
  config_sha256?: string | null;
  trigger: string;
  compliance_score: number | null;
  coverage_pct: number | null;
  counts: Record<string, number | null>;
  versions: Record<string, string | null>;
  changes: SnapshotChanges;
  created_at: number;
}

export interface FindingChange { k: string; st: string; sev: string; t: string; e: string; age_days?: number }

export interface Comparison {
  asset_id: string;
  from: Snapshot;
  to: Snapshot;
  new: FindingChange[];
  resolved: FindingChange[];
  severity_increased: FindingChange[];
  persisting: FindingChange[];
  score_delta: number;
  config_changed: boolean;
  knowledge_changed: string[];
}

export interface ConfigDiff {
  added: number;
  removed: number;
  secret_lines_changed: number;
  identical: boolean;
  truncated: boolean;
  diff: string[];
}

export interface TrendPoint { day: string; assets: number; score: number; critical: number; high: number; failed: number; coverage_pct: number }

export interface ChangeItem {
  snapshot_id: string;
  asset_id: string;
  asset_name?: string | null;
  audit_id: string;
  trigger: string;
  compliance_score: number | null;
  changes: SnapshotChanges;
  created_at: number;
}

export interface Schedule {
  schedule_id: string;
  name: string;
  asset_id: string;
  interval_minutes: number;
  frameworks: string[];
  run_cve: boolean;
  enabled: boolean;
  last_job_id?: string | null;
  last_status?: string | null;
  created_by?: string | null;
  next_run_at: number | null;
  last_run_at: number | null;
}

export async function assetHistory(assetId: string) {
  return unwrap<{ items: Snapshot[] }>((await api.get(`/history/assets/${assetId}`, { params: { limit: 200 } })).data).items;
}
export async function compareRuns(assetId: string, from?: string, to?: string) {
  return unwrap<Comparison>((await api.get(`/history/assets/${assetId}/compare`, { params: { from, to } })).data);
}
export async function configDiff(assetId: string, from: string, to: string) {
  return unwrap<ConfigDiff>((await api.get(`/history/assets/${assetId}/config-diff`, { params: { from, to } })).data);
}
export async function trend(days = 90, assetId?: string) {
  return unwrap<{ points: TrendPoint[] }>((await api.get("/history/trend", { params: { days, asset_id: assetId } })).data).points;
}
export async function recentChanges(days = 7) {
  return unwrap<{ items: ChangeItem[] }>((await api.get("/history/changes", { params: { days } })).data).items;
}
export async function listSchedules(assetId?: string) {
  return unwrap<{ items: Schedule[] }>((await api.get("/schedules", { params: { asset_id: assetId } })).data).items;
}
export async function createSchedule(b: { name: string; asset_id: string; interval_minutes: number; frameworks: string[]; run_cve: boolean }) {
  return unwrap<Schedule>((await api.post("/schedules", b)).data);
}
export async function patchSchedule(id: string, b: Partial<Pick<Schedule, "enabled" | "interval_minutes" | "name" | "run_cve">>) {
  return unwrap<Schedule>((await api.patch(`/schedules/${id}`, b)).data);
}
export async function deleteSchedule(id: string) {
  await api.delete(`/schedules/${id}`);
}
export async function runSchedule(id: string) {
  return unwrap<{ status: string }>((await api.post(`/schedules/${id}/run`)).data);
}
