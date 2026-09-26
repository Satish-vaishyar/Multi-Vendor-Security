import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { fleetStatus, getAnalytics, startFleet } from "../api/analytics.api";
import { toMessage } from "../api/client";
import { fmtScore, useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Badge, Card, Empty, ErrorState, Field, Loader, PageHeader, btnPrimary, inputCls } from "../components/common";

export default function SecurityAnalytics() {
  const [auditId, select] = useSelectedAudit();
  const audits = useAuditOverviews();
  const [fleetIds, setFleetIds] = useState("");
  const [fleetJob, setFleetJob] = useState("");
  const [err, setErr] = useState("");
  const q = useQuery({ queryKey: ["analytics", auditId], queryFn: () => getAnalytics(auditId), enabled: !!auditId });
  const fleet = useQuery({ queryKey: ["fleet", fleetJob], queryFn: () => fleetStatus(fleetJob), enabled: !!fleetJob, refetchInterval: 3000 });
  const start = useMutation({
    mutationFn: () => startFleet(fleetIds.split(/[,\s]+/).filter(Boolean)),
    onSuccess: (d) => { setErr(""); setFleetJob(d.job_id); },
    onError: (e) => setErr(toMessage(e)),
  });
  const d = (q.data ?? {}) as Record<string, unknown>;
  const anomalies = (d.anomalies as Record<string, unknown>[] | undefined) ?? [];
  const patterns = (d.patterns as Record<string, unknown>[] | undefined) ?? [];

  return (
    <div>
      <PageHeader title="Security Analytics" sub="Risk, anomalies, fleet outliers — GET /analytics/{audit_id}" />
      <div className="mb-4">
        <AuditPicker
          overviews={audits.overviews} isLoading={audits.isLoading} isError={audits.isError} onRetry={audits.refetch}
          value={auditId} onSelect={select}
          renderBrief={(a) => <>Risk {fmtScore(a.risk_score, 0)} · {a.engines.SECURITY ?? 0} security findings</>}
        />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          {!auditId ? <Empty label="Select an audit above." /> : (
            <Card title={`Analytics detail — ${auditId}`}>
              {q.isLoading ? <Loader /> : q.isError ? <ErrorState message="Analytics unavailable." onRetry={() => q.refetch()} /> : (
                <>
                  <p className="mb-3 text-sm text-ink2">Overall security risk: <b className="text-ink">{String(d.risk_score ?? "—")}</b></p>
                  {!anomalies.length && !patterns.length ? <Empty label="No anomalies detected." /> : (
                    <ul className="space-y-2 text-sm">
                      {[...anomalies, ...patterns].map((a, i) => (
                        <li key={i} className="rounded-lg bg-surface2 p-3">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-semibold text-ink">{String(a.type ?? a.title ?? `anomaly-${i}`)}</span>
                            <Badge value={String(a.severity ?? "—")} kind="sev" />
                          </div>
                          <p className="mt-1 text-xs text-ink3">{String(a.description ?? a.property ?? "")}</p>
                        </li>
                      ))}
                    </ul>
                  )}
                </>
              )}
            </Card>
          )}
        </div>
        <Card title="Fleet Analysis" sub="Multi-device outlier detection">
          <Field label="Asset IDs (comma separated)">
            <input className={`${inputCls} mt-1 font-mono`} value={fleetIds} onChange={(e) => setFleetIds(e.target.value)} placeholder="AST-001, AST-002" />
          </Field>
          <button className={`${btnPrimary} mt-3`} disabled={!fleetIds || start.isPending} onClick={() => start.mutate()}>
            {start.isPending ? "Starting…" : "Start Fleet Job"}
          </button>
          {err && <p className="mt-2 text-xs text-danger">{err}</p>}
          {fleetJob && (
            <div className="mt-3 text-xs">
              <p className="text-ink3">Job <span className="font-mono text-ink2">{fleetJob}</span></p>
              {fleet.data ? <pre className="code-view mt-2 max-h-64 overflow-auto rounded-lg border border-line bg-surface2 p-3 text-ink2">{JSON.stringify(fleet.data, null, 2)}</pre> : <Loader label="Waiting for fleet job…" />}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
