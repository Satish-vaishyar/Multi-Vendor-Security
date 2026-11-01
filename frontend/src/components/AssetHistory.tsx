import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { assetHistory, compareRuns, configDiff, type FindingChange, type Snapshot } from "../api/history.api";
import { toMessage } from "../api/client";
import { Badge, Card, Empty, ErrorState, Loader } from "../components/common";

const when = (t: number) => new Date(t * 1000).toLocaleString();

function Delta({ v }: { v?: number }) {
  if (v === undefined || v === null || v === 0) return <span className="text-ink3">±0</span>;
  return <span className={v > 0 ? "text-ok" : "text-danger"}>{v > 0 ? "+" : ""}{v}</span>;
}

function ChangeList({ title, items, tone }: { title: string; items: FindingChange[]; tone: string }) {
  if (!items.length) return null;
  return (
    <div>
      <p className={`mb-1 text-xs font-semibold ${tone}`}>{title} ({items.length})</p>
      <ul className="space-y-1">
        {items.slice(0, 40).map((x) => (
          <li key={x.k} className="flex items-center gap-2 rounded bg-surface2 px-2 py-1 text-xs">
            <Badge value={x.sev} kind="sev" />
            <span className="min-w-0 flex-1 truncate text-ink" title={x.k}>{x.t || x.k}</span>
            {x.age_days !== undefined && x.age_days > 0 && <span className="shrink-0 text-ink3">open {x.age_days} d</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

function Compare({ assetId, from, to }: { assetId: string; from: string; to: string }) {
  const q = useQuery({ queryKey: ["compare", assetId, from, to], queryFn: () => compareRuns(assetId, from, to) });
  const [showDiff, setShowDiff] = useState(false);
  const d = useQuery({ queryKey: ["cfgdiff", assetId, from, to], queryFn: () => configDiff(assetId, from, to), enabled: showDiff });
  if (q.isLoading) return <Loader label="Comparing runs…" />;
  if (q.isError || !q.data) return <ErrorState message={toMessage(q.error)} />;
  const c = q.data;
  return (
    <div className="space-y-3 rounded-lg border border-line bg-surface p-3">
      <p className="text-sm text-ink">
        {when(c.from.created_at)} → {when(c.to.created_at)} · score {c.from.compliance_score}% → {c.to.compliance_score}% (<Delta v={c.score_delta} />)
      </p>
      <p className="text-xs text-ink2">
        {c.config_changed ? "The configuration changed between these runs." : "The configuration is identical."}{" "}
        {c.knowledge_changed.length > 0 && <>Knowledge updated: <b>{c.knowledge_changed.join(", ")}</b> - findings can change without any config change.</>}
      </p>
      <div className="grid gap-3 md:grid-cols-2">
        <ChangeList title="New findings" items={c.new} tone="text-danger" />
        <ChangeList title="Resolved" items={c.resolved} tone="text-ok" />
        <ChangeList title="Got worse" items={c.severity_increased} tone="text-warn" />
        <ChangeList title="Still open (oldest first)" items={c.persisting} tone="text-ink2" />
      </div>
      {!c.new.length && !c.resolved.length && !c.severity_increased.length && <p className="text-xs text-ink3">No finding changed between these runs.</p>}
      {c.from.configuration_id && c.to.configuration_id && c.config_changed && (
        <div>
          <button className="text-xs font-semibold text-primary hover:underline" onClick={() => setShowDiff((v) => !v)}>
            {showDiff ? "Hide" : "Show"} configuration diff
          </button>
          {showDiff && (d.isLoading ? <Loader label="Diffing…" /> : d.data && (
            <div className="mt-2">
              <p className="mb-1 text-[11px] text-ink3">
                +{d.data.added} / −{d.data.removed} lines{d.data.secret_lines_changed > 0 && <> · <b className="text-warn">{d.data.secret_lines_changed} secret value(s) changed</b> (values never shown)</>}
                {d.data.truncated && " · truncated"}
              </p>
              <pre className="max-h-72 overflow-auto rounded bg-surface2 p-2 font-mono text-[11px] leading-snug">
                {d.data.diff.map((l, i) => (
                  <div key={i} className={l.startsWith("+") && !l.startsWith("+++") ? "text-ok" : l.startsWith("-") && !l.startsWith("---") ? "text-danger" : "text-ink3"}>{l}</div>
                ))}
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AssetHistory({ assetId }: { assetId: string }) {
  const q = useQuery({ queryKey: ["history", assetId], queryFn: () => assetHistory(assetId) });
  const [pair, setPair] = useState<{ from: string; to: string } | null>(null);
  if (q.isLoading) return <Loader label="Loading history…" />;
  if (q.isError) return <ErrorState message={toMessage(q.error)} onRetry={() => q.refetch()} />;
  const snaps = q.data ?? [];
  if (!snaps.length) return <Card title="Audit history"><Empty label="No audit has been run for this asset yet." /></Card>;
  const chart = [...snaps].reverse().map((s) => ({ t: new Date(s.created_at * 1000).toLocaleDateString(), score: s.compliance_score ?? 0, failed: Number(s.counts.failed ?? 0) }));
  const pick = (s: Snapshot, i: number) => {
    const prev = snaps[i + 1];
    if (prev) setPair({ from: prev.snapshot_id, to: s.snapshot_id });
  };
  return (
    <Card title="Audit history & drift" sub="Every run is kept. Compare any run with the one before it to see what changed and why.">
      {snaps.length > 1 && (
        <div className="mb-3 h-40">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chart} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" />
              <XAxis dataKey="t" tick={{ fontSize: 10 }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} />
              <Tooltip />
              <Line type="monotone" dataKey="score" name="Compliance %" stroke="var(--primary)" strokeWidth={2} dot={{ r: 2 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="uppercase tracking-wider text-ink3">
            <tr><th className="py-1.5 pr-3">Run</th><th className="pr-3">Score</th><th className="pr-3">Changes vs previous</th><th className="pr-3">Trigger</th><th /></tr>
          </thead>
          <tbody>
            {snaps.slice(0, 30).map((s, i) => {
              const ch = s.changes;
              return (
                <tr key={s.snapshot_id} className="border-t border-line align-top">
                  <td className="py-1.5 pr-3 text-ink">{when(s.created_at)}<div className="font-mono text-[10px] text-ink3">{s.audit_id}</div></td>
                  <td className="pr-3">{s.compliance_score ?? "—"}% {ch.score_delta !== undefined && <Delta v={ch.score_delta} />}</td>
                  <td className="pr-3 text-ink2">
                    {ch.previous_snapshot_id ? (
                      <>
                        <span className="text-danger">{ch.new ?? 0} new</span> · <span className="text-ok">{ch.resolved ?? 0} resolved</span>
                        {!!ch.severity_increased && <> · <span className="text-warn">{ch.severity_increased} worse</span></>}
                        <div className="text-[10px] text-ink3">
                          {ch.config_changed ? "config changed" : "same config"}{ch.knowledge_changed?.length ? ` · ${ch.knowledge_changed.join(", ")} updated` : ""}
                        </div>
                      </>
                    ) : <span className="text-ink3">first run</span>}
                  </td>
                  <td className="pr-3"><Badge value={s.trigger.toUpperCase()} /></td>
                  <td className="text-right">
                    {snaps[i + 1] && <button className="font-semibold text-primary hover:underline" onClick={() => pick(s, i)}>Compare</button>}
                    {" "}<Link className="text-ink3 hover:underline" to={`/audits/${s.audit_id}/results`}>Open</Link>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {pair && <div className="mt-3"><Compare assetId={assetId} from={pair.from} to={pair.to} /></div>}
    </Card>
  );
}
