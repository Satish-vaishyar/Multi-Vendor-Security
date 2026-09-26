import { Link } from "react-router-dom";
import { useAuditOverviews } from "../hooks/useAuditOverviews";
import { Badge, Card, Empty, ErrorState, Loader, PageHeader } from "../components/common";

export default function Audits() {
  const audits = useAuditOverviews();

  return (
    <div>
      <PageHeader title="Audits" sub="Recent audit runs with status and finding briefs" />
      <Card>
        {audits.isLoading ? <Loader label="Loading audits…" /> :
          audits.isError ? <ErrorState message="Unable to load audits." onRetry={() => audits.refetch()} /> :
            !audits.overviews.length ? <Empty label="No audits yet. Upload a configuration and start an audit." /> : (
              <>
                <ul className="space-y-2">
                  {audits.overviews.map((a) => (
                    <li key={a.audit_id} className="rounded-lg border border-line bg-surface p-3 text-sm hover:bg-surface2">
                      <span className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono font-semibold text-primary">{a.audit_id}</span>
                        <Badge value={a.status} />
                      </span>
                      <span className="mt-1 block text-xs text-ink2">
                        {a.total} findings · {a.critical} critical · {a.high} high
                        {a.compliance_score != null && !Number.isNaN(a.compliance_score) ? ` · Compliance ${a.compliance_score.toFixed(1)}%` : ""}
                      </span>
                      <span className="mt-2 flex gap-2">
                        <Link to={`/audits/${a.audit_id}`} className="rounded-lg border border-linestrong bg-surface px-3 py-1.5 text-xs font-semibold text-ink2 hover:bg-surface2">Progress</Link>
                        <Link to={`/audits/${a.audit_id}/results`} className="rounded-lg bg-primary px-3 py-1.5 text-xs font-semibold text-onprimary hover:bg-primaryhover">Results</Link>
                      </span>
                    </li>
                  ))}
                </ul>
                <p className="mt-3 flex items-center gap-2 text-xs text-ink3">Status legend: <Badge value="COMPLETED" /> <Badge value="RUNNING" /> <Badge value="FAILED" /></p>
              </>
            )}
      </Card>
    </div>
  );
}
