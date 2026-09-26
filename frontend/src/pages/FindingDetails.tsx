import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getFinding } from "../api/findings.api";
import { Badge, Card, ErrorState, Loader, PageHeader, btnGhost } from "../components/common";

export default function FindingDetails() {
  const { findingId = "" } = useParams();
  const q = useQuery({ queryKey: ["finding", findingId], queryFn: () => getFinding(findingId) });
  if (q.isLoading) return <Loader />;
  if (q.isError || !q.data) return <ErrorState message="Finding not found." onRetry={() => q.refetch()} />;
  const d = q.data as unknown as Record<string, unknown>;
  const ev = (d.evidence ?? {}) as Record<string, unknown>;

  return (
    <div>
      <PageHeader
        title={String(d.title ?? findingId)}
        sub={`Severity ${d.severity ?? "—"} · Risk ${String((d.risk as Record<string, unknown> | undefined)?.score ?? "—")}`}
        actions={<Link to={`/remediation/${findingId}`} className={btnGhost}>View Remediation</Link>}
      />
      <div className="mb-4 flex flex-wrap gap-2">
        <Badge value={String(d.severity ?? "?")} kind="sev" />
        <Badge value={String(d.status ?? "—")} />
        <Badge value={String(d.type ?? d.engine ?? "—")} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Why was this finding generated?" sub="Explainability chain">
          <dl className="space-y-2 text-sm">
            {[["Observed", JSON.stringify(ev.observed ?? ev.observed_value ?? d.observed ?? "—")],
              ["Expected", JSON.stringify(ev.expected ?? ev.expected_value ?? d.expected ?? "—")],
              ["Rule", String(ev.rule ?? ev.control_id ?? d.control_id ?? "—")],
              ["Result", String(d.status ?? "—")],
              ["Asset", JSON.stringify(d.asset ?? d.asset_id ?? "—")],
              ["Source", JSON.stringify(d.source ?? "—")]].map(([k, v]) => (
              <div key={k} className="flex justify-between gap-3 rounded-lg bg-surface2 px-3 py-2">
                <dt className="text-ink3">{k}</dt><dd className="break-all font-mono text-xs text-ink">{v}</dd>
              </div>
            ))}
          </dl>
        </Card>
        <Card title="Evidence & Remediation" sub="Raw backend payload">
          <pre className="code-view max-h-[50vh] overflow-auto rounded-lg border border-line bg-surface2 p-3 text-ink2">{JSON.stringify(d, null, 2)}</pre>
        </Card>
      </div>
    </div>
  );
}
