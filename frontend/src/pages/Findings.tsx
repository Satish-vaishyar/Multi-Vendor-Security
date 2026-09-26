import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { listFindings } from "../api/findings.api";
import { useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Badge, Card, ErrorState, Loader, PageHeader, inputCls } from "../components/common";
import { Empty } from "../components/common";

export default function Findings() {
  const [pickedAudit, pickAudit] = useSelectedAudit();
  const audits = useAuditOverviews();
  const [f, setF] = useState({ severity: "", type: "", asset_id: "", status: "", audit_id: pickedAudit, engine: "" });
  const [applied, setApplied] = useState({ severity: "", type: "", asset_id: "", status: "", audit_id: pickedAudit, engine: "" });
  const q = useQuery({ queryKey: ["findings", applied], queryFn: () => listFindings(applied) });

  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setF((p) => ({ ...p, [k]: e.target.value }));

  const fromPicker = (id: string) => {
    pickAudit(id);
    const next = { ...f, audit_id: id };
    setF(next);
    setApplied(next);
  };

  return (
    <div>
      <PageHeader title="Findings" sub="Unified view: compliance + CVE + PQC + security" />
      <div className="mb-4">
        <AuditPicker
          overviews={audits.overviews} isLoading={audits.isLoading} isError={audits.isError} onRetry={audits.refetch}
          value={applied.audit_id} onSelect={fromPicker}
          renderBrief={(a) => <>{a.total} findings · {a.critical} critical · {a.high} high · {a.medium} medium · {a.low} low</>}
        />
      </div>
      <Card title={applied.audit_id ? `Finding detail — ${applied.audit_id}` : "All findings"}>
        <div className="mb-3 grid gap-2 md:grid-cols-3 lg:grid-cols-6">
          <select className={inputCls} value={f.severity} onChange={set("severity")}>
            <option value="">Severity</option>{["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className={inputCls} value={f.type} onChange={set("type")}>
            <option value="">Type</option>{["COMPLIANCE", "CVE", "VULNERABILITY", "PQC", "SECURITY", "CONFIGURATION"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <input className={inputCls} placeholder="Asset ID" value={f.asset_id} onChange={set("asset_id")} />
          <input className={inputCls} placeholder="Audit ID" value={f.audit_id} onChange={set("audit_id")} />
          <select className={inputCls} value={f.status} onChange={set("status")}>
            <option value="">Status</option>{["OPEN", "FAIL", "PASS"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <button className="rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-onprimary hover:bg-primaryhover" onClick={() => setApplied(f)}>Apply</button>
        </div>
        {q.isLoading ? <Loader /> : q.isError ? <ErrorState message="Unable to load findings." onRetry={() => q.refetch()} /> :
          !(q.data?.items?.length) ? <Empty label="No findings match these filters." /> : (
            <>
              <p className="mb-2 text-xs text-ink3">{q.data?.total} findings</p>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead><tr className="border-b border-line text-xs uppercase text-ink3">
                    <th className="py-2 pr-3 font-medium">Finding</th><th className="py-2 pr-3 font-medium">Type</th>
                    <th className="py-2 pr-3 font-medium">Asset</th><th className="py-2 pr-3 font-medium">Severity</th><th className="py-2 pr-3 font-medium">Status</th>
                  </tr></thead>
                  <tbody>
                    {(q.data?.items ?? []).map((x) => (
                      <tr key={x.finding_id} className="border-b border-line/60 hover:bg-surface2">
                        <td className="py-2 pr-3"><Link to={`/findings/${x.finding_id}`} className="text-primary hover:underline">{x.title ?? x.finding_id}</Link></td>
                        <td className="py-2 pr-3 text-ink2">{String(x.type ?? "—")}</td>
                        <td className="py-2 pr-3 font-mono text-xs text-ink3">{x.asset_id ?? "—"}</td>
                        <td className="py-2 pr-3"><Badge value={String(x.severity ?? "?")} kind="sev" /></td>
                        <td className="py-2 pr-3"><Badge value={String(x.status ?? "—")} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
      </Card>
    </div>
  );
}
