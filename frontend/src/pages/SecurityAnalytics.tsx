import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { fleetStatus, getAnalytics, startFleet } from "../api/analytics.api";
import { toMessage } from "../api/client";
import { fmtScore, useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Badge, Card, Empty, ErrorState, Field, Loader, PageHeader, btnPrimary, inputCls } from "../components/common";

type Item = Record<string, unknown>;

function fmtVal(v: unknown): string {
  if (v === null || v === undefined) return "not observed";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function DetailRow({ k, v, mono = false }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-3 rounded-lg bg-surface px-3 py-2">
      <dt className="shrink-0 text-ink3">{k}</dt>
      <dd className={`break-all text-right text-ink ${mono ? "font-mono text-xs" : "text-sm"}`}>{v}</dd>
    </div>
  );
}

function AnomalyDetail({ a }: { a: Item }) {
  const risk = (a.risk ?? {}) as Record<string, unknown>;
  const fid = a.finding_id ? String(a.finding_id) : "";
  return (
    <div className="mt-3 border-t border-line pt-3">
      <p className="text-sm text-ink2"><span className="font-semibold text-ink">Why flagged: </span>{String(a.why ?? a.detail ?? "—")}</p>
      <dl className="mt-2 space-y-1.5 text-sm">
        <DetailRow k="Signal property" v={String(a.property ?? "—")} mono />
        <DetailRow k="Observed value" v={fmtVal(a.observed)} mono />
        <DetailRow k="Severity" v={String(a.severity ?? "—")} />
        <DetailRow k="Asset" v={String(a.asset_id ?? "—")} mono />
        <DetailRow k="Confidence" v={a.confidence !== undefined && a.confidence !== null ? String(a.confidence) : "—"} mono />
        <DetailRow k="Risk" v={`score ${fmtVal(risk.risk_score)} · priority ${fmtVal(risk.priority)}`} mono />
        {a.remediation_hint ? <DetailRow k="Recommended fix" v={String(a.remediation_hint)} /> : null}
      </dl>
      {fid ? (
        <div className="mt-2 flex flex-wrap gap-2 text-xs">
          <Link to={`/findings/${fid}`} className="font-mono text-primary hover:underline">Open finding {fid}</Link>
          <Link to={`/remediation/${fid}`} className="text-primary hover:underline">View remediation →</Link>
        </div>
      ) : (
        <p className="mt-2 text-xs text-ink3">No unified finding linked (finding may predate this enrichment).</p>
      )}
    </div>
  );
}

function PatternDetail({ p }: { p: Item }) {
  const contributors = (p.contributors ?? []) as unknown[];
  const observed = (p.observed ?? {}) as Record<string, unknown>;
  const related = (p.related_findings ?? []) as unknown[];
  return (
    <div className="mt-3 border-t border-line pt-3">
      <p className="text-sm text-ink2"><span className="font-semibold text-ink">Why flagged: </span>{String(p.why ?? p.detail ?? "—")}</p>
      {!!contributors.length && (
        <dl className="mt-2 space-y-1.5 text-sm">
          {contributors.map((c) => (
            <DetailRow key={String(c)} k={String(c)} v={fmtVal(observed[String(c)])} mono />
          ))}
        </dl>
      )}
      {p.remediation_hint ? <p className="mt-2 text-sm text-ink2"><span className="font-semibold text-ink">Recommended fix: </span>{String(p.remediation_hint)}</p> : null}
      {!!related.length && (
        <div className="mt-2 flex flex-wrap gap-2 text-xs">
          {related.map((f) => (
            <Link key={String(f)} to={`/findings/${String(f)}`} className="font-mono text-primary hover:underline">{String(f)}</Link>
          ))}
        </div>
      )}
    </div>
  );
}

export default function SecurityAnalytics() {
  const [auditId, select] = useSelectedAudit();
  const audits = useAuditOverviews();
  const [fleetIds, setFleetIds] = useState("");
  const [fleetJob, setFleetJob] = useState("");
  const [err, setErr] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["analytics", auditId], queryFn: () => getAnalytics(auditId), enabled: !!auditId });
  const fleet = useQuery({ queryKey: ["fleet", fleetJob], queryFn: () => fleetStatus(fleetJob), enabled: !!fleetJob, refetchInterval: 3000 });
  const start = useMutation({
    mutationFn: () => startFleet(fleetIds.split(/[,\s]+/).filter(Boolean)),
    onSuccess: (d) => { setErr(""); setFleetJob(d.job_id); },
    onError: (e) => setErr(toMessage(e)),
  });
  const d = (q.data ?? {}) as Record<string, unknown>;
  const anomalies = (d.anomalies as Item[] | undefined) ?? [];
  const patterns = (d.patterns as Item[] | undefined) ?? [];
  const items: { key: string; kind: "anomaly" | "pattern"; row: Item }[] = [
    ...anomalies.map((a, i) => ({ key: `a-${String(a.type)}-${String(a.property)}-${i}`, kind: "anomaly" as const, row: a })),
    ...patterns.map((p, i) => ({ key: `p-${String(p.pattern ?? p.type)}-${i}`, kind: "pattern" as const, row: p })),
  ];

  return (
    <div>
      <PageHeader title="Security Analytics" sub="Risk, anomalies, fleet outliers — GET /analytics/{audit_id}" />
      <div className="mb-4">
        <AuditPicker
          overviews={audits.overviews} isLoading={audits.isLoading} isError={audits.isError} onRetry={audits.refetch}
          value={auditId} onSelect={(id) => { setOpen(null); select(id); }}
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
                  {!items.length ? <Empty label="No anomalies detected." /> : (
                    <>
                      <p className="mb-2 text-xs text-ink3">Select an item to see why it was flagged.</p>
                      <ul className="space-y-2 text-sm">
                        {items.map(({ key, kind, row: a }) => {
                          const expanded = open === key;
                          return (
                            <li key={key} className="rounded-lg bg-surface2 p-3">
                              <button
                                type="button"
                                aria-expanded={expanded}
                                onClick={() => setOpen(expanded ? null : key)}
                                className="flex w-full items-center justify-between gap-2 text-left"
                              >
                                <span className="font-semibold text-ink">
                                  {kind === "pattern" ? `Pattern: ${String(a.pattern ?? a.type ?? key)}` : String(a.type ?? a.title ?? key)}
                                </span>
                                <span className="flex shrink-0 items-center gap-2">
                                  <Badge value={String(a.severity ?? "—")} kind="sev" />
                                  <span className="text-ink3" aria-hidden>{expanded ? "▾" : "▸"}</span>
                                </span>
                              </button>
                              <p className="mt-1 text-xs text-ink3">{String(a.description ?? a.detail ?? a.property ?? "")}</p>
                              {expanded && (kind === "pattern" ? <PatternDetail p={a} /> : <AnomalyDetail a={a} />)}
                            </li>
                          );
                        })}
                      </ul>
                    </>
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
