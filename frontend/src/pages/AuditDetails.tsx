import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { getAudit } from "../api/audits.api";
import { Badge, Card, ErrorState, Loader, PageHeader } from "../components/common";
import { btnPrimary } from "../components/common";

export default function AuditDetails() {
  const { auditId = "" } = useParams();
  const q = useQuery({
    queryKey: ["audit", auditId],
    queryFn: () => getAudit(auditId),
    // Poll every 2–3s while running; stop on terminal states (frontend.md §20)
    refetchInterval: (query) => {
      const s = String(query.state.data?.status ?? "").toUpperCase();
      return ["QUEUED", "RUNNING"].includes(s) ? 2500 : false;
    },
  });

  if (q.isLoading) return <Loader label="Loading audit…" />;
  if (q.isError || !q.data) return <ErrorState message="Audit not found. It may have been deleted or you lack access." onRetry={() => q.refetch()} />;
  const a = q.data;
  const stages = (a.stages ?? {}) as Record<string, string>;

  return (
    <div>
      <PageHeader
        title={`Audit ${auditId}`}
        sub={`Status: ${a.status} · Progress: ${a.progress ?? "—"}%`}
        actions={<Link to={`/audits/${auditId}/results`} className={btnPrimary}>View Results</Link>}
      />
      <Card title="Progress Timeline" sub="Polls every 2.5s while QUEUED / RUNNING">
        <ol className="space-y-2">
          {[["Configuration Ingestion", stages.ingestion], ["Vendor Detection", stages.detection ?? stages.vendor], ["Configuration Normalization", stages.normalization],
            ["Compliance Analysis", stages.compliance], ["CVE Correlation", stages.cve], ["PQC Analysis", stages.pqc],
            ["Security Analytics", stages.security], ["Risk Calculation", stages.risk], ["Report Generation", stages.report],
          ].map(([label, st]) => (
            <li key={label as string} className="flex items-center gap-3 rounded-lg bg-surface2 p-2.5 text-sm">
              <span className="text-base">{String(st ?? "PENDING").toUpperCase() === "COMPLETED" ? <span className="text-ok">✓</span> : String(st ?? "").toUpperCase() === "RUNNING" ? <span className="text-primary">●</span> : <span className="text-ink3">○</span>}</span>
              <span className="flex-1 text-ink2">{label as string}</span>
              <Badge value={String(st ?? "PENDING")} />
            </li>
          ))}
        </ol>
        {String(a.status).toUpperCase() === "FAILED" && (
          <p className="mt-3 rounded-lg border border-danger/30 bg-dangerbg p-3 text-xs text-danger">Audit failed. Check the configuration and retry.</p>
        )}
      </Card>
    </div>
  );
}
