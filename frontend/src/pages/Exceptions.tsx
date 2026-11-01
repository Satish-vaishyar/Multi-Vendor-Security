import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listAssets } from "../api/assets.api";
import { decideException, listExceptions, requestException, type RiskException } from "../api/exceptions.api";
import { toMessage } from "../api/client";
import { Badge, Card, Empty, ErrorState, Field, Hint, Loader, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";
import { useAuth } from "../stores/auth";
import { hasRole } from "../utils/roles";

const when = (t?: number | null) => (t ? new Date(t * 1000).toLocaleDateString() : "—");

export default function Exceptions() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const canDecide = hasRole(user?.role, "APPROVER");
  const canRequest = hasRole(user?.role, "AUDITOR");
  const q = useQuery({ queryKey: ["exceptions"], queryFn: () => listExceptions() });
  const assets = useQuery({ queryKey: ["assets", "all"], queryFn: () => listAssets({ page: 1, page_size: 100, status: "ACTIVE" }) });
  const [f, setF] = useState({ asset_id: "", finding_key: "", reason: "", days: 30 });
  const [err, setErr] = useState("");
  const refresh = () => void qc.invalidateQueries({ queryKey: ["exceptions"] });
  const create = useMutation({
    mutationFn: () => requestException(f),
    onSuccess: () => { setErr(""); setF({ ...f, finding_key: "", reason: "" }); refresh(); },
    onError: (e) => setErr(toMessage(e)),
  });
  const act = useMutation({
    mutationFn: (v: { id: string; op: "approve" | "reject" | "revoke" }) => {
      const comment = v.op === "approve" ? "" : (window.prompt(`Comment for ${v.op} (optional)`) ?? "");
      return decideException(v.id, v.op, comment);
    },
    onSuccess: refresh,
    onError: (e) => setErr(toMessage(e)),
  });
  const items: RiskException[] = q.data?.items ?? [];
  const max = q.data?.max_days ?? 180;

  return (
    <div>
      <PageHeader title="Risk acceptance" sub={<>Formally accept a finding until a date. Needs a second person's approval, always expires, and the finding stays visible in every report. <Hint term="risk acceptance" /></>} />
      {canRequest && (
        <div className="mb-4">
          <Card title="Request an exception" sub="Use the control id (e.g. CIS-1.1.1) or CVE id shown on the finding.">
            <form className="grid gap-3 md:grid-cols-4" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
              <Field label="Asset">
                <select className={inputCls} value={f.asset_id} onChange={(e) => setF({ ...f, asset_id: e.target.value })} required>
                  <option value="">Select…</option>
                  {(assets.data?.items ?? []).map((a) => <option key={a.asset_id} value={a.asset_id}>{a.name}</option>)}
                </select>
              </Field>
              <Field label="Control / CVE id"><input className={inputCls} value={f.finding_key} onChange={(e) => setF({ ...f, finding_key: e.target.value })} required /></Field>
              <Field label={`Valid for (days, max ${max})`}><input type="number" min={1} max={max} className={inputCls} value={f.days} onChange={(e) => setF({ ...f, days: Number(e.target.value) })} /></Field>
              <div className="md:col-span-3"><Field label="Business reason (min 10 characters)"><input className={inputCls} value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })} required minLength={10} /></Field></div>
              <button className={btnPrimary} disabled={create.isPending}>{create.isPending ? "Sending…" : "Request"}</button>
            </form>
          </Card>
        </div>
      )}
      {err && <p role="alert" className="mb-3 rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}
      <Card title="Exceptions">
        {q.isLoading ? <Loader /> : q.isError ? <ErrorState message={toMessage(q.error)} onRetry={() => q.refetch()} /> :
          !items.length ? <Empty label="No exceptions yet." /> : (
            <ul className="space-y-3">
              {items.map((x) => (
                <li key={x.exception_id} className="rounded-lg border border-line p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm text-ink">{x.finding_key}</span>
                    <span className="text-xs text-ink3">on {x.asset_id}</span>
                    <Badge value={x.active ? "ACTIVE" : x.status === "APPROVED" ? "EXPIRED" : x.status} />
                    <span className="ml-auto flex gap-1">
                      {canDecide && x.status === "PENDING" && <>
                        <button className={btnGhost} onClick={() => act.mutate({ id: x.exception_id, op: "approve" })}>Approve</button>
                        <button className={btnGhost} onClick={() => act.mutate({ id: x.exception_id, op: "reject" })}>Reject</button>
                      </>}
                      {canDecide && (x.status === "PENDING" || x.active) && <button className={btnGhost} onClick={() => act.mutate({ id: x.exception_id, op: "revoke" })}>Revoke</button>}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-ink2">{x.reason}</p>
                  <p className="mt-1 text-xs text-ink3">
                    Requested by {x.requested_by} · expires {when(x.expires_at)}
                    {x.decided_by ? ` · ${x.status.toLowerCase()} by ${x.decided_by}${x.decision_comment ? `: ${x.decision_comment}` : ""}` : ""}
                  </p>
                </li>
              ))}
            </ul>
          )}
      </Card>
    </div>
  );
}
