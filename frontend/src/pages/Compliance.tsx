import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { getComplianceControls, getComplianceFramework, getComplianceOverall, getFrameworks } from "../api/compliance.api";
import { FRAMEWORK_LABELS } from "../constants";
import { fmtScore, useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Badge, Card, Empty, ErrorState, Loader, PageHeader, inputCls } from "../components/common";

export default function Compliance() {
  const [sp, setSp] = useSearchParams();
  const [selected, select] = useSelectedAudit();
  const id = selected;
  const [fw, setFw] = useState(sp.get("fw") ?? "NIST");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const audits = useAuditOverviews();

  const overall = useQuery({ queryKey: ["comp", id], queryFn: () => getComplianceOverall(id), enabled: !!id });
  const detail = useQuery({ queryKey: ["comp-fw", id, fw], queryFn: () => getComplianceFramework(id, fw), enabled: !!id });
  const controls = useQuery({ queryKey: ["comp-ctl", id], queryFn: () => getComplianceControls(id), enabled: !!id });
  const fwList = useQuery({ queryKey: ["fw-list"], queryFn: getFrameworks, enabled: !!id });

  const pickFw = (f: string) => {
    setFw(f);
    setSp((prev) => {
      const n = new URLSearchParams(prev);
      n.set("fw", f);
      return n;
    });
  };

  const items = ((controls.data as { items?: Record<string, unknown>[] } | undefined)?.items ?? []) as Record<string, unknown>[];
  const filtered = items.filter((c) => {
    const hay = `${c.control_id ?? ""} ${c.title ?? ""}`.toLowerCase();
    if (q && !hay.includes(q.toLowerCase())) return false;
    if (status && String(c.status ?? "").toUpperCase() !== status) return false;
    return true;
  });
  const frameworks: string[] = Array.isArray((fwList.data as unknown as { frameworks?: { id?: string }[] })?.frameworks)
    ? ((fwList.data as unknown as { frameworks: { id: string }[] }).frameworks.map((f) => f.id))
    : ["CIS", "NIST", "STIG", "ISO27001"];

  return (
    <div>
      <PageHeader title="Compliance" sub="Multi-framework control results — GET /compliance/{audit_id}" />
      <div className="mb-4">
        <AuditPicker
          overviews={audits.overviews} isLoading={audits.isLoading} isError={audits.isError} onRetry={audits.refetch}
          value={id} onSelect={select}
          renderBrief={(a) => <>Compliance {fmtScore(a.compliance_score)}% · {a.total} findings ({a.critical} critical, {a.high} high)</>}
        />
      </div>
      {!id ? <Empty label="Select an audit above to inspect compliance." /> : (
        <Card title={`Compliance detail — ${id}`}>
          {overall.isLoading ? <Loader /> : overall.isError ? <ErrorState message="Compliance data unavailable." onRetry={() => overall.refetch()} /> : (
            <>
              <div className="mb-3 grid grid-cols-2 gap-2 md:grid-cols-4">
                {Object.entries(((overall.data as Record<string, unknown>)?.frameworks ?? overall.data ?? {}) as Record<string, { score?: number }>).slice(0, 8).map(([k, v]) => (
                  typeof v === "object" ? (
                    <div key={k} className="rounded-lg bg-surface2 p-3">
                      <p className="text-xs font-medium text-ink2">{FRAMEWORK_LABELS[k] ?? k}</p>
                      <p className="mt-0.5 text-lg font-semibold text-ink">{Number(v.score ?? 0).toFixed(0)}%</p>
                      <div className="mt-2 h-2 overflow-hidden rounded-full bg-line/60">
                        <div className="h-full rounded-full bg-primary" style={{ width: `${Math.min(100, Number(v.score ?? 0))}%` }} />
                      </div>
                    </div>
                  ) : null
                ))}
              </div>
              <div className="mb-3 flex flex-wrap gap-2">
                {frameworks.map((f) => (
                  <button key={f} onClick={() => pickFw(f)}
                    className={`rounded-lg border px-3 py-1.5 text-xs font-semibold ${fw === f ? "border-primary bg-primarylight text-primary" : "border-linestrong bg-surface text-ink2 hover:bg-surface2"}`}>{f}</button>
                ))}
              </div>
              {detail.data && (
                <pre className="code-view mb-3 max-h-48 overflow-auto rounded-lg border border-line bg-surface2 p-3 text-ink2">{JSON.stringify(detail.data, null, 2)}</pre>
              )}
              <div className="mb-3 grid gap-2 md:grid-cols-2">
                <input className={inputCls} placeholder="Search controls…" value={q} onChange={(e) => setQ(e.target.value)} />
                <select className={inputCls} value={status} onChange={(e) => setStatus(e.target.value)}>
                  <option value="">All statuses</option>
                  {["PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE", "UNKNOWN"].map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
                </select>
              </div>
              {!filtered.length ? <Empty label="No controls match." /> : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead><tr className="border-b border-line text-xs uppercase text-ink3">
                      <th className="py-2 pr-3 font-medium">Control</th><th className="py-2 pr-3 font-medium">Description</th>
                      <th className="py-2 pr-3 font-medium">Status</th><th className="py-2 pr-3 font-medium">Severity</th>
                    </tr></thead>
                    <tbody>
                      {filtered.map((c, i) => (
                        <tr key={String(c.control_id ?? i)} className="border-b border-line/60 hover:bg-surface2">
                          <td className="py-2 pr-3 font-mono text-primary">{String(c.control_id ?? "—")}</td>
                          <td className="py-2 pr-3 text-ink2">{String(c.title ?? c.description ?? "—")}</td>
                          <td className="py-2 pr-3"><Badge value={String(c.status ?? "UNKNOWN")} /></td>
                          <td className="py-2 pr-3"><Badge value={String(c.severity ?? "—")} kind="sev" /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </Card>
      )}
    </div>
  );
}
