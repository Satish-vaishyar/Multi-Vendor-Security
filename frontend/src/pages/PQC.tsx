import { useQuery } from "@tanstack/react-query";
import { getPqc } from "../api/pqc.api";
import { fmtScore, useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Card, Empty, ErrorState, Loader, PageHeader, PqcBadge } from "../components/common";

export default function PQC() {
  const [auditId, select] = useSelectedAudit();
  const audits = useAuditOverviews();
  const q = useQuery({ queryKey: ["pqc", auditId], queryFn: () => getPqc(auditId), enabled: !!auditId });
  const d = (q.data ?? {}) as Record<string, unknown>;
  const algos = (d.algorithms as Record<string, unknown>[] | undefined) ?? [];
  const recs = (d.migration_recommendations as Record<string, unknown>[] | undefined) ?? [];

  return (
    <div>
      <PageHeader title="PQC Security" sub="Post-quantum readiness — GET /pqc/{audit_id}" />
      <div className="mb-4">
        <AuditPicker
          overviews={audits.overviews} isLoading={audits.isLoading} isError={audits.isError} onRetry={audits.refetch}
          value={auditId} onSelect={select}
          renderBrief={(a) => <>PQC readiness {fmtScore(a.pqc_readiness)}{a.pqc_readiness != null ? "%" : ""} · {a.engines.PQC ?? 0} PQC findings</>}
        />
      </div>
      {!auditId ? <Empty label="Select an audit above to inspect PQC readiness." /> : (
        <Card title={`PQC detail — ${auditId}`}>
          {q.isLoading ? <Loader /> : q.isError ? <ErrorState message="PQC data unavailable." onRetry={() => q.refetch()} /> : (
            <>
              <div className="mb-4 rounded-[10px] bg-pqcbg p-4 text-center">
                <p className="text-3xl font-semibold text-pqc">{String(d.readiness_score ?? d.readiness ?? "—")}{d.readiness_score != null ? "%" : ""}</p>
                <p className="text-xs text-pqc">PQC Readiness</p>
              </div>
              {!algos.length ? <Empty label="No algorithm inventory." /> : (
                <div className="grid gap-2 md:grid-cols-2">
                  {algos.map((a, i) => (
                    <div key={i} className="rounded-lg bg-surface2 p-3 text-sm">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-semibold text-ink">{String(a.algorithm ?? a.name ?? `algo-${i}`)}{a.key_size ? `-${String(a.key_size)}` : ""}</span>
                        <PqcBadge value={String(a.status ?? "UNKNOWN")} />
                      </div>
                      <p className="mt-1 text-xs text-ink3">Protocol: {String(a.protocol ?? a.usage ?? "—")} · Location: {String(a.location ?? "—")}</p>
                    </div>
                  ))}
                </div>
              )}
              {!!recs.length && (
                <div className="mt-4">
                  <h3 className="mb-2 text-sm font-semibold text-ink">Migration recommendations (from backend — never invented)</h3>
                  <pre className="code-view max-h-72 overflow-auto rounded-lg border border-line bg-surface2 p-3 text-ink2">{JSON.stringify(recs, null, 2)}</pre>
                </div>
              )}
            </>
          )}
        </Card>
      )}
    </div>
  );
}
