import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Layers } from "lucide-react";
import { bulkAudit, cancelJob, getBatch, listJobs, retryJob, type Job } from "../api/jobs.api";
import { toMessage } from "../api/client";
import { Badge, Card, Empty, ErrorState, Field, Loader, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";
import { useAuth } from "../stores/auth";
import { hasRole } from "../utils/roles";

const FRAMEWORKS = ["CIS", "NIST", "STIG", "ISO27001", "CERTIN"];
const ACTIVE = new Set(["QUEUED", "RUNNING"]);

function Bar({ value }: { value: number }) {
  return (
    <div className="h-1.5 w-28 overflow-hidden rounded-full bg-surface2">
      <div className="h-full rounded-full bg-primary" style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
    </div>
  );
}

function BulkAudit({ onStarted }: { onStarted: (batchId: string) => void }) {
  const canRun = hasRole(useAuth((s) => s.user?.role), "AUDITOR");
  const [files, setFiles] = useState<File[]>([]);
  const [fw, setFw] = useState<string[]>(["CIS", "NIST", "STIG", "ISO27001"]);
  const [crit, setCrit] = useState("MEDIUM");
  const [cve, setCve] = useState(true);
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");

  const run = useMutation({
    mutationFn: () => bulkAudit(files, { frameworks: fw, criticality: crit, runCve: cve }),
    onSuccess: (d) => {
      setErr("");
      setNote(`${d.accepted} audit(s) queued${d.rejected.length ? `, ${d.rejected.length} file(s) rejected: ${d.rejected.map((r) => `${r.filename} (${r.reason})`).join("; ")}` : ""}.`);
      setFiles([]);
      onStarted(d.batch_id);
    },
    onError: (e) => { setNote(""); setErr(toMessage(e)); },
  });

  return (
    <Card title="Audit a fleet in the background"
      sub="Drop many device configs. Each becomes an asset (named from its hostname) and a queued audit - no request time-outs.">
      <div className="grid gap-3 md:grid-cols-2">
        <Field label="Configuration files">
          <input className={inputCls} type="file" multiple accept=".txt,.cfg,.conf,.log,.text,.json,.xml"
            onChange={(e) => setFiles(Array.from(e.target.files ?? []))} />
          <span className="mt-1 block text-[11px] text-ink3">{files.length ? `${files.length} file(s) selected` : "Up to 500 files per batch, 5 MB each."}</span>
        </Field>
        <div className="grid gap-3">
          <Field label="Frameworks">
            <div className="flex flex-wrap gap-3 text-xs text-ink2">
              {FRAMEWORKS.map((f) => (
                <label key={f} className="flex items-center gap-1">
                  <input type="checkbox" checked={fw.includes(f)} onChange={(e) => setFw(e.target.checked ? [...fw, f] : fw.filter((x) => x !== f))} /> {f}
                </label>
              ))}
            </div>
          </Field>
          <div className="flex items-end gap-3">
            <Field label="Asset criticality">
              <select className={inputCls} value={crit} onChange={(e) => setCrit(e.target.value)}>
                {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((c) => <option key={c}>{c}</option>)}
              </select>
            </Field>
            <label className="mb-2 flex items-center gap-1 text-xs text-ink2">
              <input type="checkbox" checked={cve} onChange={(e) => setCve(e.target.checked)} /> Include CVE matching
            </label>
          </div>
        </div>
      </div>
      <div className="mt-3 flex items-center gap-3">
        <button className={`${btnPrimary} flex items-center gap-2`} disabled={!canRun || !files.length || !fw.length || run.isPending}
          title={canRun ? undefined : "Requires the AUDITOR role"} onClick={() => run.mutate()}>
          <Layers size={15} /> {run.isPending ? "Uploading…" : `Queue ${files.length || ""} audit${files.length === 1 ? "" : "s"}`}
        </button>
      </div>
      {note && <p className="mt-3 rounded-lg border border-ok/30 bg-okbg p-2.5 text-xs text-ok">{note}</p>}
      {err && <p role="alert" className="mt-3 rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}
    </Card>
  );
}

function BatchBanner({ batchId }: { batchId: string }) {
  const q = useQuery({
    queryKey: ["batch", batchId], queryFn: () => getBatch(batchId),
    refetchInterval: (query) => (query.state.data && query.state.data.state !== "RUNNING" ? false : 2500),
  });
  if (!q.data) return null;
  const b = q.data;
  const tone = b.state === "COMPLETED" ? "border-ok/30 bg-okbg text-ok" : b.state === "RUNNING" ? "border-line bg-surface text-ink2" : "border-warn/30 bg-warnbg text-warn";
  return (
    <p className={`mb-4 rounded-lg border p-2.5 text-xs ${tone}`}>
      <b>Batch {b.batch_id}</b> - {b.finished}/{b.total} finished ({b.progress_pct}%) ·{" "}
      {Object.entries(b.counts).map(([k, v]) => `${v} ${k.toLowerCase()}`).join(", ")}
    </p>
  );
}

export default function Jobs() {
  const qc = useQueryClient();
  const canRun = hasRole(useAuth((s) => s.user?.role), "AUDITOR");
  const [status, setStatus] = useState("");
  const [batchId, setBatchId] = useState("");
  const q = useQuery({
    queryKey: ["jobs", status, batchId], queryFn: () => listJobs({ status: status || undefined, batch_id: batchId || undefined, limit: 100 }),
    refetchInterval: (query) => ((query.state.data ?? []).some((j) => ACTIVE.has(j.status)) ? 2500 : 15000),
  });
  const act = useMutation({
    mutationFn: (v: { id: string; op: "cancel" | "retry" }) => (v.op === "cancel" ? cancelJob(v.id) : retryJob(v.id)),
    onSettled: () => void qc.invalidateQueries({ queryKey: ["jobs"] }),
  });
  const items = q.data ?? [];

  return (
    <div>
      <PageHeader title="Background jobs" sub="Audits and reports run in the queue so large fleets never time out"
        actions={
          <select className={`${inputCls} w-40`} aria-label="Filter by status" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            {["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"].map((s) => <option key={s}>{s}</option>)}
          </select>
        } />
      <div className="mb-4"><BulkAudit onStarted={(id) => { setBatchId(id); void qc.invalidateQueries({ queryKey: ["jobs"] }); }} /></div>
      {batchId && <BatchBanner batchId={batchId} />}
      <Card title="Jobs" sub={batchId ? `Filtered to batch ${batchId}` : "Most recent first"}
        right={batchId ? <button className={btnGhost} onClick={() => setBatchId("")}>Show all</button> : undefined}>
        {q.isLoading ? <Loader /> : q.isError ? <ErrorState message={toMessage(q.error)} onRetry={() => q.refetch()} /> :
          !items.length ? <Empty label="No jobs yet." /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase tracking-wider text-ink3">
                  <tr><th className="py-2 pr-3">Job</th><th className="pr-3">Status</th><th className="pr-3">Progress</th><th className="pr-3">Result</th><th /></tr>
                </thead>
                <tbody>
                  {items.map((j: Job) => (
                    <tr key={j.job_id} className="border-t border-line align-top">
                      <td className="py-2 pr-3">
                        <div className="font-mono text-xs text-ink">{j.job_id}</div>
                        <div className="text-[11px] text-ink3">{j.kind}{j.created_by ? ` · ${j.created_by}` : ""}{j.attempts > 1 ? ` · attempt ${j.attempts}/${j.max_attempts}` : ""}</div>
                      </td>
                      <td className="pr-3"><Badge value={j.status} /></td>
                      <td className="pr-3"><Bar value={j.progress} /></td>
                      <td className="pr-3 text-xs text-ink2">
                        {j.status === "COMPLETED" && j.kind === "audit" && j.result.audit_id ? (
                          <Link className="text-primary hover:underline" to={`/audits/${String(j.result.audit_id)}/results`}>
                            Open audit · {j.result.compliance_score != null ? `${j.result.compliance_score}%` : ""}
                          </Link>
                        ) : j.status === "COMPLETED" && j.kind === "report" && j.result.download_url ? (
                          <span>Report {String(j.result.report_id)} ready (Reports page)</span>
                        ) : j.error ? <span className="text-danger">{j.error}</span> : ""}
                      </td>
                      <td className="text-right">
                        {canRun && ACTIVE.has(j.status) && <button className={btnGhost} onClick={() => act.mutate({ id: j.job_id, op: "cancel" })}>Cancel</button>}
                        {canRun && (j.status === "FAILED" || j.status === "CANCELLED") && <button className={btnGhost} onClick={() => act.mutate({ id: j.job_id, op: "retry" })}>Retry</button>}
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
