import { Suspense, lazy, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ArrowRight, Rocket } from "lucide-react";
import { trend as getTrend } from "../api/history.api";
import { getSummary } from "../api/dashboard.api";
import { useAuth } from "../stores/auth";
import { hasRole } from "../utils/roles";
import { Badge, Card, Empty, ErrorState, Hint, KpiSkeleton, Loader, PageHeader, btnGhost, btnPrimary } from "../components/common";
import { fmtNum } from "../utils/format";

const DashboardCharts = lazy(() => import("./DashboardCharts"));

const SEV_BARS = [
  { key: "critical", label: "Critical", bar: "bg-danger" },
  { key: "high", label: "High", bar: "bg-high" },
  { key: "medium", label: "Medium", bar: "bg-warn" },
  { key: "low", label: "Low", bar: "bg-info" },
] as const;

function Kpi({ label, value, to, hint }: { label: string; value: string; to: string; hint?: string }) {
  return (
    <Link to={to} className="group rounded-xl border border-line bg-surface p-4 transition-colors hover:border-linestrong">
      <p className="text-2xl font-semibold tracking-tight text-ink">{value}</p>
      <p className="mt-1 flex items-center gap-1 text-xs text-ink3 group-hover:text-ink2">{label}{hint && <Hint term={hint} />}</p>
    </Link>
  );
}

export default function Dashboard() {
  const role = useAuth((s) => s.user?.role);
  const canUpload = hasRole(role, "AUDITOR");
  const q = useQuery({ queryKey: ["dashboard"], queryFn: getSummary, refetchInterval: 60_000 });
  const tr = useQuery({ queryKey: ["trend", 90], queryFn: () => getTrend(90), refetchInterval: 5 * 60_000 });
  const [stamp] = useState(() => new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));

  const header = (
    <PageHeader
      title="Security Overview"
      sub={`How your devices are doing across every audit. Updated ${stamp}.`}
      actions={canUpload ? <Link to="/quick-audit" className={btnPrimary}>Run new audit</Link> : undefined}
    />
  );

  if (q.isLoading) return <div>{header}<p className="sr-only">Loading security overview…</p><KpiSkeleton count={6} /><div className="mt-4"><Loader label="Loading charts…" /></div></div>;
  if (q.isError) return <div>{header}<ErrorState message={(q.error as Error)?.message ?? "Failed"} onRetry={() => q.refetch()} /></div>;
  const d = q.data ?? {};
  const empty = (d.assets?.total ?? 0) === 0 && (d.totals?.findings ?? 0) === 0;

  const sev = SEV_BARS.map((s) => ({ ...s, value: Number(d.findings?.[s.key] ?? 0) }));
  const sevMax = Math.max(1, ...sev.map((s) => s.value));
  const fw = d.frameworks ? Object.entries(d.frameworks as Record<string, { score?: number }>) : [];

  return (
    <div>
      {header}

      {empty && (
        <div className="mb-6 flex flex-col items-start gap-4 rounded-xl border border-primary/30 bg-primarylight/60 p-5 sm:flex-row sm:items-center">
          <span className="rounded-full bg-primary p-3 text-onprimary"><Rocket size={20} aria-hidden="true" /></span>
          <div className="min-w-0 flex-1">
            <h2 className="text-base font-semibold text-ink">Welcome. Let&apos;s audit your first device.</h2>
            <p className="mt-1 text-sm text-ink2">Drop in a router, firewall or switch config. In about a minute you get a compliance score, the issues found and the commands to fix them.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {canUpload && <Link to="/quick-audit" className={btnPrimary}>Upload a config</Link>}
            {canUpload && <Link to="/quick-audit?sample=1" className={btnGhost}>Try a sample</Link>}
            <Link to="/get-started" className={btnGhost}>See the 5 steps</Link>
          </div>
        </div>
      )}

      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Devices" value={String(d.assets?.total ?? "—")} to="/assets" />
        <Kpi label="Devices at risk" value={String(d.assets?.at_risk ?? "—")} to="/assets" />
        <Kpi label="Compliance Score" value={d.compliance?.overall != null ? `${fmtNum(d.compliance.overall)}%` : "—"} to="/compliance" hint="compliance" />
        <Kpi label="Critical Findings" value={String(d.findings?.critical ?? "—")} to="/findings" />
        <Kpi label="High Findings" value={String(d.findings?.high ?? "—")} to="/findings" />
        <Kpi label="Critical CVEs" value={String(d.cve?.critical ?? "—")} to="/vulnerabilities" hint="CVE" />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Findings by severity" sub="Issues from every check, across all devices">
          {sev.every((s) => !s.value) ? <Empty label="No findings yet." hint="Run an audit to see issues here." action={canUpload ? <Link to="/quick-audit" className={btnPrimary}>Upload & audit</Link> : undefined} /> : (
            <ul className="space-y-3">
              {sev.map((s) => (
                <li key={s.key} className="grid grid-cols-[6rem_1fr_3rem] items-center gap-3 text-sm">
                  <span className="text-ink2">{s.label}</span>
                  <span className="h-2 overflow-hidden rounded-full bg-surface2" aria-hidden="true">
                    <span className={`block h-full rounded-full ${s.bar}`} style={{ width: `${Math.max(2, (s.value / sevMax) * 100)}%` }} />
                  </span>
                  <span className="text-right font-medium tabular-nums text-ink">{s.value}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Compliance by framework" sub="Average score per standard">
          {fw.length === 0 ? <Empty label="Framework scores appear after the first audit." /> : (
            <ul className="space-y-3">
              {fw.map(([k, v]) => {
                const score = Math.max(0, Math.min(100, Number(v?.score ?? 0)));
                return (
                  <li key={k} className="grid grid-cols-[6rem_1fr_3rem] items-center gap-3 text-sm">
                    <span className="flex items-center gap-0.5 whitespace-nowrap text-ink2">{k}<Hint term={k} /></span>
                    <span className="h-2 overflow-hidden rounded-full bg-surface2" aria-hidden="true">
                      <span className="block h-full rounded-full bg-primary" style={{ width: `${score}%` }} />
                    </span>
                    <span className="text-right font-medium tabular-nums text-ink">{fmtNum(score, 0)}%</span>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>

      <div className="mt-4">
        <Suspense fallback={<Loader label="Loading charts…" rows={6} />}>
          <DashboardCharts d={d} trend={tr.data ?? []} />
        </Suspense>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card title="Top failing controls" sub="Most frequent failures across the fleet">
          {(d.top_failing_controls ?? []).length === 0 ? <Empty label="No failing controls." /> : (
            <div className="tbl-flat">
              <table className="text-left text-sm">
                <thead><tr>
                  <th className="py-2 pr-3">Control</th><th className="py-2 pr-3">Failures</th><th className="py-2 pr-3">Devices</th>
                </tr></thead>
                <tbody>
                  {(d.top_failing_controls ?? []).map((c) => (
                    <tr key={c.control_id} className="border-b border-line">
                      <td className="py-2.5 pr-3"><span className="font-mono text-xs text-ink3">{c.control_id}</span>{" "}
                        <span className="text-ink2">{c.title ?? ""}</span></td>
                      <td className="py-2.5 pr-3 tabular-nums text-ink2">{c.failures}</td>
                      <td className="py-2.5 pr-3 tabular-nums text-ink2">{c.assets}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="By check type and vendor" sub="Failed findings">
          <div className="flex flex-wrap gap-2">
            {Object.entries(d.by_engine ?? {}).map(([e, v]) => <Badge key={e} value={`${e.toUpperCase()}: ${v.fail}`} />)}
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {Object.entries(d.by_vendor ?? {}).map(([v, x]) => <Badge key={v} value={`${v}: ${x.assets} devices / ${x.failed_findings} failed`} />)}
          </div>
          {!Object.keys(d.by_engine ?? {}).length && !Object.keys(d.by_vendor ?? {}).length && <Empty label="Nothing to break down yet." />}
        </Card>
        <Card title={<span className="inline-flex items-center gap-1">Vulnerability overview<Hint term="CVE" /></span>} sub="Known software vulnerabilities in your devices">
          <div className="flex flex-wrap gap-2">
            <Badge value={`CRITICAL: ${d.cve?.critical ?? 0}`} kind="sev" />
            <Badge value={`HIGH: ${d.cve?.high ?? 0}`} kind="sev" />
          </div>
          <Link to="/vulnerabilities" className="mt-4 inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline">
            Open vulnerabilities <ArrowRight size={12} aria-hidden="true" />
          </Link>
        </Card>
        <Card title="AI training queue" sub="Config lines the system did not recognise">
          <p className="text-sm text-ink2">{d.training?.pending ?? 0} unknown mappings pending review</p>
          <Link to="/training" className="mt-4 inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline">
            Open training queue <ArrowRight size={12} aria-hidden="true" />
          </Link>
        </Card>
      </div>
    </div>
  );
}
