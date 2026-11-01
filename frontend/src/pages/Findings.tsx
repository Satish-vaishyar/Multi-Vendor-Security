import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { memo, useEffect } from "react";
import { Link } from "react-router-dom";
import { markMilestone } from "../utils/progress";
import { listFindings } from "../api/findings.api";
import { useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Badge, Card, ErrorState, Loader, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";
import { Empty } from "../components/common";
import { PageControls } from "../components/PageControls";

const PAGE_SIZE = 25;

type FindingItem = NonNullable<Awaited<ReturnType<typeof listFindings>>["items"]>[number];

/** Memoised so typing in the filter boxes does not re-render every table row. */
const FindingRows = memo(function FindingRows({ items }: { items: FindingItem[] }) {
  return (
    <>
      {items.map((x) => (
        <tr key={x.finding_id} className="border-b border-line hover:bg-surface2">
          <td className="py-2.5 pr-3"><Link to={`/findings/${x.finding_id}`} className="text-primary hover:underline">{x.title ?? x.finding_id}</Link></td>
          <td className="py-2.5 pr-3 text-ink2">{String(x.type ?? "—")}</td>
          <td className="py-2.5 pr-3 font-mono text-xs text-ink3">{x.asset_id ?? "—"}</td>
          <td className="py-2.5 pr-3"><Badge value={String(x.severity ?? "?")} kind="sev" /></td>
          <td className="py-2.5 pr-3"><Badge value={String(x.status ?? "—")} /></td>
        </tr>
      ))}
    </>
  );
});

export default function Findings() {
  const [pickedAudit, pickAudit] = useSelectedAudit();
  useEffect(() => { markMilestone("findings"); }, []);
  const audits = useAuditOverviews();
  const [f, setF] = useState({ severity: "", type: "", asset_id: "", status: "", audit_id: pickedAudit, engine: "" });
  const [applied, setApplied] = useState({ severity: "", type: "", asset_id: "", status: "", audit_id: pickedAudit, engine: "" });
  const [page, setPage] = useState(1);
  const q = useQuery({
    queryKey: ["findings", applied, page],
    queryFn: () => listFindings({ ...applied, page, page_size: PAGE_SIZE }),
    placeholderData: (prev) => prev,
  });

  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setF((p) => ({ ...p, [k]: e.target.value }));

  const fromPicker = (id: string) => {
    pickAudit(id);
    const next = { ...f, audit_id: id };
    setF(next);
    setApplied(next);
    setPage(1);
  };

  return (
    <div>
      <PageHeader title="Findings" sub="Everything the audits found: failed controls, known CVEs, weak encryption and risky settings. Start with Critical and High." />
      <div className="mb-4">
        <AuditPicker
          overviews={audits.overviews} isLoading={audits.isLoading} isError={audits.isError} onRetry={audits.refetch}
          value={applied.audit_id} onSelect={fromPicker}
          renderBrief={(a) => <>{a.total} findings · {a.critical} critical · {a.high} high · {a.medium} medium · {a.low} low</>}
        />
      </div>
      <Card title={applied.audit_id ? `Finding detail — ${applied.audit_id}` : "All findings"}>
        <div className="mb-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-6">
          <select className={inputCls} aria-label="Severity" value={f.severity} onChange={set("severity")}>
            <option value="">Any severity</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className={inputCls} aria-label="Type" value={f.type} onChange={set("type")}>
            <option value="">Any type</option>{["COMPLIANCE", "CVE", "VULNERABILITY", "PQC", "SECURITY", "CONFIGURATION"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <input className={inputCls} aria-label="Device ID" placeholder="Device ID" value={f.asset_id} onChange={set("asset_id")} />
          <input className={inputCls} aria-label="Audit ID" placeholder="Audit ID" value={f.audit_id} onChange={set("audit_id")} />
          <select className={inputCls} aria-label="Status" value={f.status} onChange={set("status")}>
            <option value="">Any status</option>{["OPEN", "FAIL", "PASS", "UNKNOWN"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <button className={btnPrimary} onClick={() => { setApplied(f); setPage(1); }}>Apply</button>
        </div>
        {q.isLoading ? <Loader label="Loading findings…" rows={6} /> : q.isError ? <ErrorState message="Unable to load findings." onRetry={() => q.refetch()} /> :
          !(q.data?.items?.length) ? <Empty label="No findings to show." hint="Either nothing matches these filters, or no audit has run yet." action={<><Link to="/quick-audit" className={btnPrimary}>Upload & audit</Link><button className={btnGhost} onClick={() => { const c = { severity: "", type: "", asset_id: "", status: "", audit_id: "", engine: "" }; setF(c); setApplied(c); setPage(1); }}>Clear filters</button></>} /> : (
            <>
              <p className="mb-2 text-xs text-ink3">{q.data?.total} findings</p>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead><tr className="border-b border-line text-xs uppercase text-ink3">
                    <th className="py-2 pr-3 font-medium">Finding</th><th className="py-2 pr-3 font-medium">Type</th>
                    <th className="py-2 pr-3 font-medium">Device</th><th className="py-2 pr-3 font-medium">Severity</th><th className="py-2 pr-3 font-medium">Status</th>
                  </tr></thead>
                  <tbody>
                    <FindingRows items={q.data?.items ?? []} />
                  </tbody>
                </table>
              </div>
              <PageControls page={q.data?.page ?? page} pageSize={q.data?.page_size ?? PAGE_SIZE} total={q.data?.total ?? 0} onPage={setPage} />
            </>
          )}
      </Card>
    </div>
  );
}
