import { Link } from "react-router-dom";
import { useAuth } from "../stores/auth";
import { hasRole } from "../utils/roles";
import { useAuditOverviews } from "../hooks/useAuditOverviews";
import { Badge, Card, Empty, ErrorState, Loader, PageHeader, btnGhost, btnPrimary } from "../components/common";

export default function Audits() {
  const audits = useAuditOverviews();
  const canUpload = hasRole(useAuth((s) => s.user?.role), "AUDITOR");

  return (
    <div>
      <PageHeader title="Audit results" sub="Every audit run, newest first. Open one for its score, findings and fix commands." actions={canUpload ? <Link to="/quick-audit" className={btnPrimary}>Upload & audit</Link> : undefined} />
      <Card>
        {audits.isLoading ? <Loader label="Loading audits…" /> :
          audits.isError ? <ErrorState message="Unable to load audits." onRetry={() => audits.refetch()} /> :
            !audits.overviews.length ? <Empty label="No audits yet." hint="Upload a configuration file and the audit runs straight away." action={canUpload ? <><Link to="/quick-audit" className={btnPrimary}>Upload & audit</Link><Link to="/quick-audit?sample=1" className={btnGhost}>Try a sample</Link></> : undefined} /> : (
              <>
                <ul className="space-y-2">
                  {audits.overviews.map((a) => (
                    <li key={a.audit_id} className="rounded-lg border border-line bg-surface p-3 text-sm transition-colors hover:border-linestrong">
                      <span className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono font-semibold text-primary">{a.audit_id}</span>
                        <Badge value={a.status} />
                      </span>
                      <span className="mt-1 block text-xs text-ink2">
                        {a.total} findings · {a.critical} critical · {a.high} high
                        {a.compliance_score != null && !Number.isNaN(a.compliance_score) ? ` · Compliance ${a.compliance_score.toFixed(1)}%` : ""}
                      </span>
                      <span className="mt-3 flex gap-2">
                        <Link to={`/audits/${a.audit_id}`} className={`${btnGhost} !min-h-8 !px-3 !py-1.5 !text-xs`}>Progress</Link>
                        <Link to={`/audits/${a.audit_id}/results`} className={`${btnPrimary} !min-h-8 !px-3 !py-1.5 !text-xs`}>Results</Link>
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
