import { memo } from "react";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useUi } from "../stores/ui";
import { Card, Empty } from "../components/common";
import { chartVars } from "../utils/format";
import type { DashboardSummary } from "../types";

interface TrendPoint { day: string; score?: number; critical?: number; high?: number }

/** All recharts usage for the dashboard lives here so the library loads lazily, after the KPIs have rendered. */
function DashboardCharts({ d, trend }: { d: DashboardSummary; trend: TrendPoint[] }) {
  const resolved = useUi((s) => s.resolved);
  // Re-resolve palette whenever the theme changes (light and dark).
  void resolved;
  const pal = chartVars();
  const tip = { background: pal.surface, border: `1px solid ${pal.border}`, borderRadius: 8, color: pal.ink, fontSize: 12 };
  const tick = { fontSize: 11, fill: pal.muted };
  const recent = (d.trend ?? []).map((t, i) => ({ n: i + 1, score: t.compliance_score ?? null }));

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="lg:col-span-2">
        <Card title="Compliance trend (90 days)" sub="Average score of each device's latest audit per day, with failed critical and high findings">
          {trend.length < 2 ? <Empty label="The trend appears once devices have been audited on two different days." hint="Schedule recurring audits to build it automatically." /> : (
            <div role="img" aria-label="Line chart of compliance score and critical/high failures over 90 days">
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={trend} margin={{ top: 4, right: 8, bottom: 0, left: -18 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={pal.border} vertical={false} />
                  <XAxis dataKey="day" tick={tick} tickLine={false} axisLine={false} minTickGap={24} />
                  <YAxis yAxisId="s" domain={[0, 100]} tick={tick} tickLine={false} axisLine={false} />
                  <YAxis yAxisId="c" orientation="right" allowDecimals={false} tick={tick} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={tip} />
                  <Line yAxisId="s" type="monotone" dataKey="score" name="Compliance %" stroke={pal.charts[0]} strokeWidth={2} dot={false} />
                  <Line yAxisId="c" type="monotone" dataKey="critical" name="Critical" stroke={pal.sev[0]} strokeWidth={1.5} dot={false} />
                  <Line yAxisId="c" type="monotone" dataKey="high" name="High" stroke={pal.sev[1]} strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
      </div>

      <Card title="Compliance score distribution" sub="Latest audit per device">
        {(d.score_distribution ?? []).every((b) => !b.count) ? <Empty label="Appears after the first audit." /> : (
          <div role="img" aria-label="Bar chart: number of devices per compliance score range">
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={d.score_distribution} margin={{ top: 4, right: 8, bottom: 0, left: -18 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={pal.border} vertical={false} />
                <XAxis dataKey="range" tick={tick} tickLine={false} axisLine={false} />
                <YAxis allowDecimals={false} tick={tick} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tip} cursor={{ fill: pal.border, opacity: 0.4 }} />
                <Bar dataKey="count" name="Devices" fill={pal.charts[0]} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </Card>

      <Card title="Recent audits" sub="Compliance score of the last audits">
        {recent.length < 2 ? <Empty label="At least two audits are needed." /> : (
          <div role="img" aria-label="Line chart of compliance score across recent audits">
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={recent} margin={{ top: 4, right: 8, bottom: 0, left: -18 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={pal.border} vertical={false} />
                <XAxis dataKey="n" tick={tick} tickLine={false} axisLine={false} />
                <YAxis domain={[0, 100]} tick={tick} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tip} />
                <Line type="monotone" dataKey="score" name="Compliance %" stroke={pal.charts[0]} strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </Card>
    </div>
  );
}

export default memo(DashboardCharts);
