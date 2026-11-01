import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { listAssets } from "../api/assets.api";
import { createSchedule, deleteSchedule, listSchedules, patchSchedule, recentChanges, runSchedule } from "../api/history.api";
import { toMessage } from "../api/client";
import { Badge, Card, Empty, ErrorState, Field, Hint, Loader, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";
import { useAuth } from "../stores/auth";
import { hasRole } from "../utils/roles";

const PRESETS: [string, number][] = [["Every hour", 60], ["Every 6 hours", 360], ["Daily", 1440], ["Weekly", 10080], ["Monthly", 43200]];
const FW = ["CIS", "NIST", "STIG", "ISO27001", "CERTIN"];
const when = (t?: number | null) => (t ? new Date(t * 1000).toLocaleString() : "—");
const every = (m: number) => PRESETS.find((p) => p[1] === m)?.[0] ?? `Every ${m} min`;

function Form() {
  const qc = useQueryClient();
  const assets = useQuery({ queryKey: ["assets", "all"], queryFn: () => listAssets({ page: 1, page_size: 100, status: "ACTIVE" }) });
  const [f, setF] = useState({ name: "", asset_id: "", interval: 1440, frameworks: ["CIS", "NIST", "STIG", "ISO27001"], cve: true });
  const [err, setErr] = useState("");
  const create = useMutation({
    mutationFn: () => createSchedule({ name: f.name || `Re-audit ${f.asset_id}`, asset_id: f.asset_id, interval_minutes: f.interval, frameworks: f.frameworks, run_cve: f.cve }),
    onSuccess: () => { setErr(""); setF({ ...f, name: "" }); void qc.invalidateQueries({ queryKey: ["schedules"] }); },
    onError: (e) => setErr(toMessage(e)),
  });
  return (
    <Card title="New recurring audit" sub="Re-audits the asset's latest uploaded configuration, so new CVEs and updated control packs surface without anyone clicking.">
      <form className="grid gap-3 md:grid-cols-4" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
        <Field label="Asset">
          <select className={inputCls} value={f.asset_id} onChange={(e) => setF({ ...f, asset_id: e.target.value })} required>
            <option value="">Select…</option>
            {(assets.data?.items ?? []).map((a) => <option key={a.asset_id} value={a.asset_id}>{a.name}</option>)}
          </select>
        </Field>
        <Field label="Name (optional)"><input className={inputCls} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
        <Field label="How often">
          <select className={inputCls} value={f.interval} onChange={(e) => setF({ ...f, interval: Number(e.target.value) })}>
            {PRESETS.map(([l, m]) => <option key={m} value={m}>{l}</option>)}
          </select>
        </Field>
        <div className="flex items-end"><button className={`${btnPrimary} w-full`} disabled={!f.asset_id || create.isPending}>{create.isPending ? "Creating…" : "Create schedule"}</button></div>
        <div className="flex flex-wrap items-center gap-3 text-xs text-ink2 md:col-span-4">
          {FW.map((x) => (
            <label key={x} className="flex items-center gap-1">
              <input type="checkbox" checked={f.frameworks.includes(x)} onChange={(e) => setF({ ...f, frameworks: e.target.checked ? [...f.frameworks, x] : f.frameworks.filter((y) => y !== x) })} /> {x}
            </label>
          ))}
          <label className="flex items-center gap-1"><input type="checkbox" checked={f.cve} onChange={(e) => setF({ ...f, cve: e.target.checked })} /> CVE matching</label>
        </div>
      </form>
      {err && <p role="alert" className="mt-2 rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}
    </Card>
  );
}

function Changes() {
  const q = useQuery({ queryKey: ["changes"], queryFn: () => recentChanges(7), refetchInterval: 30000 });
  const items = q.data ?? [];
  return (
    <Card title="What changed this week" sub="New critical/high findings, findings that got worse, and score moves of 5+ points">
      {q.isLoading ? <Loader /> : !items.length ? <Empty label="Nothing notable changed in the last 7 days." /> : (
        <ul className="space-y-1.5 text-sm">
          {items.map((c) => (
            <li key={c.snapshot_id} className="flex flex-wrap items-center gap-2 rounded-lg bg-surface2 px-2.5 py-2">
              <Link className="font-medium text-primary hover:underline" to={`/assets/${c.asset_id}`}>{c.asset_name ?? c.asset_id}</Link>
              <span className="text-xs text-ink3">{when(c.created_at)} · {c.trigger}</span>
              <span className="ml-auto flex flex-wrap items-center gap-2 text-xs">
                {(c.changes.new_critical_high ?? 0) > 0 && <Badge value={`${c.changes.new_critical_high} NEW CRIT/HIGH`} kind="sev" />}
                {!!c.changes.severity_increased && <span className="text-warn">{c.changes.severity_increased} worse</span>}
                <span className={(c.changes.score_delta ?? 0) < 0 ? "text-danger" : "text-ok"}>{(c.changes.score_delta ?? 0) > 0 ? "+" : ""}{c.changes.score_delta ?? 0} pts</span>
                {!c.changes.config_changed && !!c.changes.knowledge_changed?.length && <span className="text-ink3">knowledge update, config unchanged</span>}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export default function Schedules() {
  const qc = useQueryClient();
  const canEdit = hasRole(useAuth((s) => s.user?.role), "AUDITOR");
  const q = useQuery({ queryKey: ["schedules"], queryFn: () => listSchedules(), refetchInterval: 15000 });
  const assets = useQuery({ queryKey: ["assets", "all"], queryFn: () => listAssets({ page: 1, page_size: 100, status: "ACTIVE" }) });
  const name = (id: string) => assets.data?.items.find((a) => a.asset_id === id)?.name ?? id;
  const [note, setNote] = useState("");
  const refresh = () => void qc.invalidateQueries({ queryKey: ["schedules"] });
  const toggle = useMutation({ mutationFn: (v: { id: string; enabled: boolean }) => patchSchedule(v.id, { enabled: v.enabled }), onSuccess: refresh });
  const del = useMutation({ mutationFn: (id: string) => deleteSchedule(id), onSuccess: refresh });
  const run = useMutation({
    mutationFn: (id: string) => runSchedule(id),
    onSuccess: () => { setNote("Audit queued - see Background jobs."); refresh(); },
    onError: (e) => setNote(toMessage(e)),
  });
  const items = q.data ?? [];

  return (
    <div>
      <PageHeader title="Recurring audits" sub={<>Re-audit devices automatically and see what changed since the last run. <Hint term="drift" /></>} />
      {canEdit && <div className="mb-4"><Form /></div>}
      <div className="mb-4"><Changes /></div>
      <Card title="Schedules">
        {note && <p className="mb-2 rounded-lg border border-line bg-surface2 p-2 text-xs text-ink2">{note}</p>}
        {q.isLoading ? <Loader /> : q.isError ? <ErrorState message={toMessage(q.error)} onRetry={() => q.refetch()} /> :
          !items.length ? <Empty label="No schedules yet." /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase tracking-wider text-ink3">
                  <tr><th className="py-2 pr-3">Schedule</th><th className="pr-3">Runs</th><th className="pr-3">Next / last</th><th className="pr-3">Last result</th><th /></tr>
                </thead>
                <tbody>
                  {items.map((s) => (
                    <tr key={s.schedule_id} className="border-t border-line align-top">
                      <td className="py-2 pr-3">
                        <div className="font-medium text-ink">{s.name}</div>
                        <Link className="text-xs text-primary hover:underline" to={`/assets/${s.asset_id}`}>{name(s.asset_id)}</Link>
                      </td>
                      <td className="pr-3 text-xs text-ink2">{every(s.interval_minutes)}<div className="text-ink3">{s.frameworks.join(", ")}{s.run_cve ? " + CVE" : ""}</div></td>
                      <td className="pr-3 text-xs text-ink2">{s.enabled ? `next ${when(s.next_run_at)}` : <Badge value="PAUSED" />}<div className="text-ink3">last {when(s.last_run_at)}</div></td>
                      <td className="pr-3 text-xs">{s.last_status ? <Badge value={s.last_status} /> : "—"}</td>
                      <td className="space-x-1 text-right">
                        {canEdit && <>
                          <button className={btnGhost} onClick={() => run.mutate(s.schedule_id)}>Run now</button>
                          <button className={btnGhost} onClick={() => toggle.mutate({ id: s.schedule_id, enabled: !s.enabled })}>{s.enabled ? "Pause" : "Resume"}</button>
                          <button className={btnGhost} onClick={() => { if (confirm(`Delete schedule "${s.name}"?`)) del.mutate(s.schedule_id); }}>Delete</button>
                        </>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </Card>
    </div>
  );
}
