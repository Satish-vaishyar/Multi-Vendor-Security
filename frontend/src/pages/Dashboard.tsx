import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getSummary } from "../api/dashboard.api";
import { useUi } from "../stores/ui";
import { Badge, Card, Empty, ErrorState, Loader, PageHeader } from "../components/common";
import { btnPrimary } from "../components/common";
import { chartVars, fmtNum } from "../utils/format";

export default function Dashboard() {
  const q = useQuery({ queryKey: ["dashboard"], queryFn: getSummary, refetchInterval: 30000 });
  const resolved = useUi((s) => s.resolved);
  // Re-resolve palette whenever the theme changes (light ↔ dark).
  const pal = useMemo(() => chartVars(), [resolved]);

  if (q.isLoading) return <Loader label="Loading security overview…" />;
  if (q.isError) return <ErrorState message={(q.error as Error)?.message ?? "Failed"} onRetry={() => q.refetch()} />;
  const d = q.data ?? {};

  const kpis: [string, string][] = [
    ["Total Assets", String(d.assets?.total ?? "—")],
    ["Assets At Risk", String(d.assets?.at_risk ?? "—")],
    ["Compliance Score", d.compliance?.overall != null ? `${fmtNum(d.compliance.overall)}%` : "—"],
    ["Critical Findings", String(d.findings?.critical ?? "—")],
    ["High Findings", String(d.findings?.high ?? "—")],
    ["Critical CVEs", String(d.cve?.critical ?? "—")],
    ["PQC Audits", String(d.pqc?.audits ?? "—")],
    ["Pending AI Mappings", String(d.training?.pending ?? "—")],
  ];

  const sevData = [
    { name: "Critical", value: d.findings?.critical ?? 0 },
    { name: "High", value: d.findings?.high ?? 0 },
    { name: "Medium", value: d.findings?.medium ?? 0 },
    { name: "Low", value: d.findings?.low ?? 0 },
  ];
  const fwEntries = d.frameworks ? Object.entries(d.frameworks as Record<string, { score?: number }>) : [];
  const fwData = fwEntries.map(([k, v], i) => ({ name: k, score: Number(v?.score ?? 0), fill: pal.charts[i % pal.charts.length] }));
  const tip = { background: pal.surface, border: `1px solid ${pal.border}`, borderRadius: 8, color: pal.ink };

  return (
    <div>
      <PageHeader
        title="Security Overview"
        sub={`Last updated: ${new Date().toLocaleTimeString()}`}
        actions={<Link to="/configurations/upload" className={btnPrimary}>Run New Audit</Link>}
      />
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-4">
        {kpis.map(([k, v]) => (
          <Card key={k}>
            <p className="text-2xl font-semibold text-ink">{v}</p>
            <p className="mt-1 text-xs text-ink3">{k}</p>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Findings by Severity" sub="Unified findings across all engines">
          {sevData.every((s) => !s.value) ? <Empty label="No findings yet — run an audit." /> : (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={2} stroke={pal.surface} strokeWidth={2}>
                  {sevData.map((_, i) => <Cell key={i} fill={pal.sev[i % pal.sev.length]} />)}
                </Pie>
                <Tooltip contentStyle={tip} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Card>
        <Card title="Compliance by Framework" sub="Per-framework scores">
          {fwData.length === 0 ? <Empty label="Framework scores appear after the first audit." /> : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={fwData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke={pal.border} />
                <XAxis type="number" domain={[0, 100]} stroke={pal.muted} fontSize={11} tickLine={false} />
                <YAxis type="category" dataKey="name" stroke={pal.muted} fontSize={11} width={80} tickLine={false} />
                <Tooltip contentStyle={tip} />
                <Bar dataKey="score" radius={[0, 4, 4, 0]}>
                  {fwData.map((f, i) => <Cell key={i} fill={f.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card title="Vulnerability Overview" sub="CVE exposure">
          <div className="flex flex-wrap gap-2">
            <Badge value={`CRITICAL: ${d.cve?.critical ?? 0}`} kind="sev" />
            <Badge value={`HIGH: ${d.cve?.high ?? 0}`} kind="sev" />
          </div>
          <Link to="/vulnerabilities" className="mt-3 inline-block text-xs font-semibold text-primary hover:underline">
            Open vulnerabilities →
          </Link>
        </Card>
        <Card title="AI Training Queue" sub="Adaptive learning loop">
          <p className="text-sm text-ink2">{d.training?.pending ?? 0} unknown mappings pending review</p>
          <Link to="/training" className="mt-3 inline-block text-xs font-semibold text-primary hover:underline">
            Open training queue →
          </Link>
        </Card>
      </div>
    </div>
  );
}
