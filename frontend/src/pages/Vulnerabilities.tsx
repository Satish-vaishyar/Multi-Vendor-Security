import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getVulnsForAudit, kbStatus, syncCves } from "../api/vulnerabilities.api";
import { toMessage } from "../api/client";
import { useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Badge, Card, Empty, ErrorState, Loader, PageHeader, btnPrimary, inputCls } from "../components/common";

export default function Vulnerabilities() {
  const [auditId, select] = useSelectedAudit();
  const [sev, setSev] = useState("");
  const [q, setQ] = useState("");
  const audits = useAuditOverviews();
  const v = useQuery({ queryKey: ["vulns", auditId], queryFn: () => getVulnsForAudit(auditId), enabled: !!auditId });
  const kb = useQuery({ queryKey: ["kb-status"], queryFn: kbStatus, staleTime: 30000 });
  const [kw, setKw] = useState("cisco ios xe, juniper junos, fortinet fortios, openssh");
  const [dropSeeds, setDropSeeds] = useState(false);
  const [syncMsg, setSyncMsg] = useState("");
  const sync = useMutation({
    mutationFn: () => syncCves({
      products: kw.split(",").map((s) => s.trim()).filter(Boolean),
      pages: 1, results_per_page: 200, drop_seeds: dropSeeds,
    }),
    onSuccess: (d) => {
      const r = d as Record<string, unknown>;
      setSyncMsg(`Synced: +${String(r.added ?? "?")} new, ${String(r.updated ?? "?")} updated, ${String(r.total ?? "?")} total records.`);
      kb.refetch(); v.refetch();
    },
    onError: (e) => setSyncMsg(toMessage(e)),
  });

  const items = ((v.data as { items?: Record<string, unknown>[] } | undefined)?.items ?? []) as Record<string, unknown>[];
  const summary = ((v.data as { summary?: Record<string, number> } | undefined)?.summary ?? {}) as Record<string, number>;
  const unresolved = ((v.data as { unresolved?: Record<string, unknown>[] } | undefined)?.unresolved ?? []) as Record<string, unknown>[];
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
          renderBrief={(a) => {
            const cveSev = a.engineSev.CVE ?? {};
            const cveCh = Number(cveSev.CRITICAL ?? 0) + Number(cveSev.HIGH ?? 0);
            return <>{a.engines.CVE ?? 0} CVE findings · {cveCh} critical/high (CVE)</>;
          }}
        />
      </div>
      <div className="mb-4">
        <Card title="Threat intelligence" sub="Local CVE knowledge base (NVD)">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Badge value={kb.data?.real_world ? "REAL-WORLD" : "SETUP NEEDED"} />
            <span className="text-ink2">
              {kb.isLoading ? "Loading…" : `${kb.data?.nvd_records ?? 0} real NVD records · ${kb.data?.seed_records ?? 0} offline fixtures (never matched)`}
            </span>
          </div>
          <div className="mt-2 flex flex-col gap-2 md:flex-row">
            <input className={inputCls} value={kw} onChange={(e) => setKw(e.target.value)} placeholder="Products, comma-separated…" />
            <button className={btnPrimary} disabled={sync.isPending || !kw.trim()} onClick={() => sync.mutate()}>
              {sync.isPending ? "Syncing NVD…" : "Sync real-world data"}
            </button>
          </div>
          <label className="mt-2 flex cursor-pointer items-center gap-1.5 text-xs text-ink2">
            <input type="checkbox" className="accent-primary" checked={dropSeeds} onChange={(e) => setDropSeeds(e.target.checked)} />
            Also delete offline fixture records from the KB file
          </label>
          {syncMsg && <p className="mt-2 text-xs text-ink2">{syncMsg}</p>}
        </Card>
      </div>
      {!auditId ? <Empty label="Select an audit above to list CVEs." /> : (
        <Card title={`Vulnerability detail — ${auditId}`}>
          {v.isLoading ? <Loader /> : v.isError ? <ErrorState message="Vulnerability data unavailable." onRetry={() => v.refetch()} /> : (
            <>
              <p className="mb-2 text-sm font-medium text-ink2">{summary.total ?? filtered.length} Open Vulnerabilities</p>
              <div className="mb-4 grid grid-cols-2 gap-2 md:grid-cols-5">
                {[["Critical", summary.critical, "text-danger"], ["High", summary.high, "text-high"], ["Medium", summary.medium, "text-warn"], ["Low", summary.low, "text-info"], ["Unknown", summary.unknown ?? unknownCount, "text-ink3"]].map(([k, n, cls]) => (
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
              {!!unresolved.length && (
                <div className="mb-3 rounded-lg border border-line bg-surface2 px-3 py-2 text-xs text-ink2">
                  <p className="font-semibold text-ink">Couldn’t assess {unresolved.length} component{unresolved.length === 1 ? "" : "s"} — no authoritative version/CVE mapping, so {unresolved.length === 1 ? "it is" : "they are"} not listed as {unresolved.length === 1 ? "a vulnerability" : "vulnerabilities"}.</p>
                  <ul className="mt-1 space-y-0.5">
                    {unresolved.map((u, i) => (
                      <li key={i} className="font-mono">{String(u.product ?? "unknown")}{u.installed_version ? ` ${String(u.installed_version)}` : ""} — {String(u.reason ?? "")}</li>
                    ))}
                  </ul>
                </div>
              )}
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
