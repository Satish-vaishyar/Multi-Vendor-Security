import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getVulnsForAudit } from "../api/vulnerabilities.api";
import { useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Badge, Card, Empty, ErrorState, Loader, PageHeader, inputCls } from "../components/common";

export default function Vulnerabilities() {
  const [auditId, select] = useSelectedAudit();
  const [sev, setSev] = useState("");
  const [q, setQ] = useState("");
  const audits = useAuditOverviews();
  const v = useQuery({ queryKey: ["vulns", auditId], queryFn: () => getVulnsForAudit(auditId), enabled: !!auditId });

  const items = ((v.data as { items?: Record<string, unknown>[] } | undefined)?.items ?? []) as Record<string, unknown>[];
  const summary = ((v.data as { summary?: Record<string, number> } | undefined)?.summary ?? {}) as Record<string, number>;
  /** Severity lives top-level (backend-enriched) with cvss.severity fallback. */
  const vulnSev = (x: Record<string, unknown>): string => {
    const top = String(x.severity ?? "").toUpperCase();
    if (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(top)) return top;
    const nested = String(((x.cvss ?? {}) as Record<string, unknown>).severity ?? "").toUpperCase();
    if (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(nested)) return nested;
    return "UNKNOWN";
  };
  const knownSev = (s: string) => ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(s);
  const unknownCount = items.filter((x) => !knownSev(vulnSev(x))).length;
  const filtered = items.filter((x) => {
    if (sev && vulnSev(x) !== sev) return false;
    if (q && !`${x.cve_id ?? ""} ${x.product ?? ""}`.toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  });

  return (
    <div>
      <PageHeader title="Vulnerabilities" sub="CVE findings per audit — GET /vulnerabilities/{audit_id}" />
      <div className="mb-4">
        <AuditPicker
          overviews={audits.overviews} isLoading={audits.isLoading} isError={audits.isError} onRetry={audits.refetch}
          value={auditId} onSelect={select}
          renderBrief={(a) => <>{a.engines.CVE ?? 0} CVE findings · {a.critical + a.high} critical/high overall</>}
        />
      </div>
      {!auditId ? <Empty label="Select an audit above to list CVEs." /> : (
        <Card title={`Vulnerability detail — ${auditId}`}>
          {v.isLoading ? <Loader /> : v.isError ? <ErrorState message="Vulnerability data unavailable." onRetry={() => v.refetch()} /> : (
            <>
              <p className="mb-2 text-sm font-medium text-ink2">{summary.total ?? filtered.length} Open Vulnerabilities</p>
              <div className="mb-4 grid grid-cols-2 gap-2 md:grid-cols-5">
                {[["Critical", summary.critical, "text-danger"], ["High", summary.high, "text-high"], ["Medium", summary.medium, "text-warn"], ["Low", summary.low, "text-info"], ["Unknown", unknownCount, "text-ink3"]].map(([k, n, cls]) => (
                  <div key={k as string} className="rounded-lg bg-surface2 px-3 py-2.5 text-center">
                    <p className={`text-xl font-semibold ${cls}`}>{String(n ?? 0)}</p>
                    <p className="text-xs text-ink3">{k}</p>
                  </div>
                ))}
              </div>
              <div className="mb-3 grid gap-2 md:grid-cols-2">
                <input className={inputCls} placeholder="Filter by CVE ID / product…" value={q} onChange={(e) => setQ(e.target.value)} />
                <select className={inputCls} value={sev} onChange={(e) => setSev(e.target.value)}>
                  <option value="">All severities</option>
                  {["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              {!filtered.length ? <Empty label="No vulnerabilities found." /> : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead><tr className="border-b border-line text-xs uppercase text-ink3">
                      <th className="py-2 pr-3 font-medium">CVE</th><th className="py-2 pr-3 font-medium">Product</th><th className="py-2 pr-3 font-medium">Version</th>
                      <th className="py-2 pr-3 font-medium">Severity</th><th className="py-2 pr-3 font-medium">Status</th><th className="py-2 pr-3 font-medium">Fixed</th>
                    </tr></thead>
                    <tbody>
                      {filtered.map((x, i) => (
                        <tr key={String(x.finding_id ?? x.cve_id ?? i)} className="border-b border-line/60 hover:bg-surface2">
                          <td className="py-2 pr-3">{String(x.finding_id ?? "") ? (
                            <Link to={`/audits/${auditId}/vulnerabilities/${String(x.finding_id ?? "")}`} className="font-mono text-primary hover:underline">{String(x.cve_id ?? x.finding_id ?? "—")}</Link>
                          ) : (
                            <span className="font-mono text-ink2">{String(x.cve_id ?? "—")}</span>
                          )}</td>
                          <td className="py-2 pr-3 text-ink2">{String(x.product ?? "—")}</td>
                          <td className="py-2 pr-3 text-ink2">{String(x.installed_version ?? x.version ?? "—")}</td>
                          <td className="py-2 pr-3"><Badge value={vulnSev(x)} kind="sev" /></td>
                          <td className="py-2 pr-3"><Badge value={String(x.status ?? "UNKNOWN")} /></td>
                          <td className="py-2 pr-3 text-ink2">{String(x.fixed_version ?? "—")}</td>
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
