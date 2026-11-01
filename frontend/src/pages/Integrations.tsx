import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, toMessage, unwrap } from "../api/client";
import { Badge, Card, Empty, ErrorState, Field, Loader, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";

interface Hook {
  webhook_id: string;
  name: string;
  url: string;
  events: string[];
  format: string;
  enabled: boolean;
  consecutive_failures: number;
  disabled_reason?: string | null;
  last_status?: string | null;
  last_delivery_at?: number | null;
  secret?: string;
  has_auth_header?: boolean;
}
interface Delivery { delivery_id: string; event: string; status: string; http_status?: number | null; error?: string | null; attempt: number; duration_ms?: number; created_at: number }

const EVENTS = [
  ["audit.completed", "An audit finished"],
  ["finding.new_critical_high", "New critical/high finding vs the previous run"],
  ["job.failed", "A background job failed"],
];
const get = async <T,>(u: string) => unwrap<T>((await api.get(u)).data);

function Deliveries({ id }: { id: string }) {
  const q = useQuery({ queryKey: ["deliveries", id], queryFn: () => get<{ items: Delivery[] }>(`/integrations/webhooks/${id}/deliveries`), refetchInterval: 8000 });
  if (q.isLoading) return <Loader />;
  const items = q.data?.items ?? [];
  if (!items.length) return <p className="text-xs text-ink3">No deliveries yet - use “Send test”.</p>;
  return (
    <ul className="space-y-1 text-xs">
      {items.slice(0, 10).map((d) => (
        <li key={d.delivery_id} className="flex flex-wrap items-center gap-2 rounded bg-surface2 px-2 py-1">
          <Badge value={d.status} /> <span className="font-mono">{d.event}</span>
          <span className="text-ink3">{d.http_status ? `HTTP ${d.http_status}` : ""} {d.error ?? ""}</span>
          <span className="ml-auto text-ink3">{new Date(d.created_at * 1000).toLocaleString()} · {d.duration_ms ?? 0} ms · try {d.attempt}</span>
        </li>
      ))}
    </ul>
  );
}

export default function Integrations() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["webhooks"], queryFn: () => get<{ items: Hook[] }>("/integrations/webhooks") });
  const [f, setF] = useState({ name: "", url: "", format: "json", auth_header: "", events: EVENTS.map((e) => e[0]) });
  const [err, setErr] = useState("");
  const [secret, setSecret] = useState<{ id: string; value: string } | null>(null);
  const [open, setOpen] = useState<string>("");
  const refresh = () => void qc.invalidateQueries({ queryKey: ["webhooks"] });

  const create = useMutation({
    mutationFn: async () => unwrap<Hook>((await api.post("/integrations/webhooks", { ...f, auth_header: f.auth_header || undefined })).data),
    onSuccess: (h) => { setErr(""); setSecret({ id: h.webhook_id, value: h.secret ?? "" }); setF({ ...f, name: "", url: "", auth_header: "" }); refresh(); },
    onError: (e) => setErr(toMessage(e)),
  });
  const act = useMutation({
    mutationFn: async (v: { id: string; op: "test" | "toggle" | "delete" | "rotate"; enabled?: boolean }) => {
      if (v.op === "test") return api.post(`/integrations/webhooks/${v.id}/test`);
      if (v.op === "delete") return api.delete(`/integrations/webhooks/${v.id}`);
      if (v.op === "rotate") {
        const r = unwrap<{ secret: string }>((await api.post(`/integrations/webhooks/${v.id}/rotate-secret`)).data);
        setSecret({ id: v.id, value: r.secret });
        return r;
      }
      return api.patch(`/integrations/webhooks/${v.id}`, { enabled: v.enabled });
    },
    onSuccess: refresh,
    onError: (e) => setErr(toMessage(e)),
  });
  const hooks = q.data?.items ?? [];

  return (
    <div>
      <PageHeader title="Integrations" sub="Push audit results to your SIEM, chat or ticketing gateway - signed, retried and logged" />
      <div className="mb-4">
        <Card title="Add a webhook" sub="Payloads contain summaries and ids only - never configuration text or secrets.">
          <form className="grid gap-3 md:grid-cols-4" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
            <Field label="Name"><input className={inputCls} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required /></Field>
            <div className="md:col-span-2"><Field label="HTTPS URL"><input className={inputCls} value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder="https://siem.example.com/hooks/nsca" required /></Field></div>
            <Field label="Format">
              <select className={inputCls} value={f.format} onChange={(e) => setF({ ...f, format: e.target.value })}>
                <option value="json">JSON (signed)</option><option value="slack">Slack</option><option value="teams">Microsoft Teams</option>
                <option value="cef">CEF (Splunk / ArcSight)</option><option value="jira">Jira issue</option><option value="servicenow">ServiceNow incident</option>
              </select>
            </Field>
            {["jira", "servicenow", "cef"].includes(f.format) && (
              <div className="md:col-span-4">
                <Field label="Auth header (optional, stored encrypted, never shown again)">
                  <input className={inputCls} type="password" autoComplete="off" value={f.auth_header} onChange={(e) => setF({ ...f, auth_header: e.target.value })} placeholder="Authorization: Basic ...   or   X-Api-Key: ..." />
                </Field>
                <p className="mt-1 text-[11px] text-ink3">Jira: POST .../rest/api/2/issue (project from WEBHOOK_JIRA_PROJECT). ServiceNow: POST .../api/now/table/incident. CEF is sent as one text/plain line.</p>
              </div>
            )}
            <div className="flex flex-wrap items-center gap-4 text-xs text-ink2 md:col-span-3">
              {EVENTS.map(([k, label]) => (
                <label key={k} className="flex items-center gap-1" title={label}>
                  <input type="checkbox" checked={f.events.includes(k)} onChange={(e) => setF({ ...f, events: e.target.checked ? [...f.events, k] : f.events.filter((x) => x !== k) })} /> {k}
                </label>
              ))}
            </div>
            <button className={btnPrimary} disabled={create.isPending || !f.events.length}>{create.isPending ? "Adding…" : "Add webhook"}</button>
          </form>
          {err && <p role="alert" className="mt-2 rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}
          {secret && (
            <p className="mt-2 rounded-lg border border-warn/30 bg-warnbg p-2.5 text-xs text-warn">
              <b>Signing secret for {secret.id} - copy it now, it will not be shown again:</b>{" "}
              <code className="select-all font-mono text-ink">{secret.value}</code>
              <span className="mt-1 block text-ink3">Verify each delivery: <code>X-Signature-256 = sha256=HMAC_SHA256(secret, X-Timestamp + "." + raw_body)</code>, and reject timestamps older than 5 minutes.</span>
            </p>
          )}
        </Card>
      </div>
      <Card title="Webhooks">
        {q.isLoading ? <Loader /> : q.isError ? <ErrorState message={toMessage(q.error)} onRetry={() => q.refetch()} /> :
          !hooks.length ? <Empty label="No webhooks yet." /> : (
            <ul className="space-y-3">
              {hooks.map((h) => (
                <li key={h.webhook_id} className="rounded-lg border border-line p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-ink">{h.name}</span>
                    <Badge value={h.enabled ? "ENABLED" : "DISABLED"} />
                    {h.last_status && <Badge value={h.last_status} />}
                    <span className="truncate text-xs text-ink3" title={h.url}>{h.url}</span>
                    <span className="ml-auto flex gap-1">
                      <button className={btnGhost} onClick={() => act.mutate({ id: h.webhook_id, op: "test" })}>Send test</button>
                      <button className={btnGhost} onClick={() => act.mutate({ id: h.webhook_id, op: "toggle", enabled: !h.enabled })}>{h.enabled ? "Disable" : "Enable"}</button>
                      <button className={btnGhost} onClick={() => act.mutate({ id: h.webhook_id, op: "rotate" })}>Rotate secret</button>
                      <button className={btnGhost} onClick={() => { if (confirm(`Delete webhook "${h.name}"?`)) act.mutate({ id: h.webhook_id, op: "delete" }); }}>Delete</button>
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-ink3">{h.format} · {h.events.join(", ")}{h.has_auth_header ? " · auth header set" : ""}</p>
                  {h.disabled_reason && <p className="mt-1 text-xs text-danger">{h.disabled_reason} ({h.consecutive_failures} failures) - fix the receiver, then enable it again.</p>}
                  <button className="mt-1 text-xs font-semibold text-primary hover:underline" onClick={() => setOpen(open === h.webhook_id ? "" : h.webhook_id)}>
                    {open === h.webhook_id ? "Hide" : "Show"} delivery log
                  </button>
                  {open === h.webhook_id && <div className="mt-2"><Deliveries id={h.webhook_id} /></div>}
                </li>
              ))}
            </ul>
          )}
      </Card>
    </div>
  );
}
