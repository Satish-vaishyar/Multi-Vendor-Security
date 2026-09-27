import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { getAuditEvidence, getAuditResults } from "../api/audits.api";
import { getAnalytics } from "../api/analytics.api";
import { getComplianceControls } from "../api/compliance.api";
import { getVulnsForAudit } from "../api/vulnerabilities.api";
import { getPqc } from "../api/pqc.api";
import { createReport } from "../api/reports.api";
import { toMessage } from "../api/client";
import { REPORT_SECTIONS } from "../constants";
import { Badge, Card, Empty, ErrorState, Loader, PageHeader, btnGhost, btnPrimary } from "../components/common";
import { fmtNum } from "../utils/format";

const TABS = ["Overview", "Compliance", "Vulnerabilities", "PQC", "Security", "Findings", "Evidence", "Details"] as const;
type Tab = (typeof TABS)[number];

const tabCls = (active: boolean) =>
  `rounded-lg border px-3 py-1.5 text-xs font-semibold ${active ? "border-primary bg-primarylight text-primary" : "border-linestrong bg-surface text-ink2 hover:bg-surface2"}`;

type AnyRec = Record<string, any>;

/* Backend security engine reports a POSTURE score (security.py: 100 = clean,
   points subtracted per anomaly) — the opposite of a risk score. Convert to
   exposure (higher = riskier) before banding so a clean audit never renders
   as "Critical". */
function exposureBand(exposure: number): [string, string, string] {
  if (exposure >= 61) return ["Critical", "bg-danger", "text-danger"];
  if (exposure >= 41) return ["High", "bg-high", "text-high"];
  if (exposure >= 21) return ["Moderate", "bg-warn", "text-warn"];
  return ["Low", "bg-primary", "text-primary"];
}

function verdict(compliance: number, openCritical: number, openHigh: number, exposure: number, unverified: number): { label: string; detail: string; cls: string } {
  if (openCritical > 0 || compliance < 50)
    return { label: "Needs immediate attention", detail: `${openCritical} critical finding(s) failed${unverified ? `, ${unverified} control(s) could not be verified` : ""} — fix failures before release and confirm the unverified settings.`, cls: "text-danger" };
  if (openHigh > 0 || compliance < 80 || exposure >= 41)
    return { label: "Needs attention", detail: `${openHigh} high-severity failure(s)${unverified ? ` plus ${unverified} unverified control(s)` : ""} — schedule fixes this sprint.`, cls: "text-high" };
  if (unverified > 0)
    return { label: "Mostly healthy — verify gaps", detail: `${unverified} control(s) could not be verified from the uploaded config (missing settings or unmapped lines). Confirm them in the Compliance tab.`, cls: "text-warn" };
  if (compliance < 95)
    return { label: "Mostly healthy", detail: "Only low/medium items remain — clear them opportunistically.", cls: "text-warn" };
  return { label: "Healthy", detail: "No critical or high findings. Keep monitoring on re-upload.", cls: "text-ok" };
}

function Bar({ value, cls = "bg-primary" }: { value: number; cls?: string }) {
  return (
    <div className="mt-2 h-2 overflow-hidden rounded-full bg-surface2">
      <div className={`h-full rounded-full ${cls}`} style={{ width: `${Math.min(100, Math.max(0, Number(value) || 0))}%` }} />
    </div>
  );
}

export default function AuditResults() {
  const { auditId = "" } = useParams();
  const [tab, setTab] = useState<Tab>("Overview");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [sevFilter, setSevFilter] = useState("ALL");
  const [engFilter, setEngFilter] = useState("ALL");
  const [query, setQuery] = useState("");
  const [ctlFilter, setCtlFilter] = useState("ALL");

  // Sub-queries stay always-enabled (small JSON): KPI cards and the executive
  // summary read them on every tab, so gating them on `tab` would render 0s.
  const r = useQuery({ queryKey: ["results", auditId], queryFn: () => getAuditResults(auditId) });
  const an = useQuery({ queryKey: ["analytics", auditId], queryFn: () => getAnalytics(auditId) });
  const ctl = useQuery({ queryKey: ["controls", auditId], queryFn: () => getComplianceControls(auditId) });
  const vulns = useQuery({ queryKey: ["vulns", auditId], queryFn: () => getVulnsForAudit(auditId) });
  const pqc = useQuery({ queryKey: ["pqc", auditId], queryFn: () => getPqc(auditId) });
  const ev = useQuery({ queryKey: ["evidence", auditId], queryFn: () => getAuditEvidence(auditId), enabled: tab === "Evidence" });

  const rep = useMutation({
    mutationFn: () => createReport({ audit_id: auditId, format: "PDF", sections: [...REPORT_SECTIONS] }),
    onSuccess: () => { setErr(""); setMsg("Report generation started — see the Reports page."); },
    onError: (e) => { setMsg(""); setErr(toMessage(e)); },
  });

  const d = (r.data ?? {}) as AnyRec;
  const s = (d.summary ?? {}) as AnyRec;
  const rawFindings: AnyRec[] = (d.findings as AnyRec[] | undefined) ?? [];
  const findings: AnyRec[] = rawFindings.map((f: AnyRec) => ({ ...f, engine: String(f.engine ?? f.type ?? "UNKNOWN") }));
  const counts = (d.counts ?? {}) as AnyRec;
  const bySev = (counts.by_severity ?? {}) as AnyRec;
  const byEng = (counts.by_engine ?? {}) as AnyRec;
  const byStatus = (counts.by_status ?? {}) as AnyRec;

  // Posture (backend): 100 = clean. Exposure (displayed): 100 - posture.
  const posture = Number((an.data as AnyRec)?.risk_score ?? s.security_risk ?? (d.security as AnyRec)?.risk_score ?? 0) || 0;
  const exposure = Math.min(100, Math.max(0, 100 - posture));
  const compliance = Number(s.compliance_score ?? 0) || 0;
  // Severity totals across ALL statuses (fail + unverified) — the summary's
  // critical/high cover FAIL verdicts only and read 0 on UNKNOWN-heavy audits.
  const sevTotal = (k: string) => Number(bySev[k] ?? 0) || 0;
  const failSev = (k: string) => findings.filter((f) => String(f.status).toUpperCase() === "FAIL" && String(f.severity).toUpperCase() === k).length;
  const critical = sevTotal("CRITICAL");
  const high = sevTotal("HIGH");
  const openCritical = failSev("CRITICAL");
  const openHigh = failSev("HIGH");
  const unverified = Number(byStatus.UNKNOWN ?? 0) || 0;
  const pqcReadiness = Number((pqc.data as AnyRec)?.readiness_score ?? (d.pqc as AnyRec)?.readiness_score ?? s.pqc_readiness ?? 0) || 0;
  const cveVuln = Number((vulns.data as AnyRec)?.summary?.vulnerable ?? (d.cve as AnyRec)?.vulnerable ?? 0) || 0;
  const [band, barCls, textCls] = exposureBand(exposure);
  const v = verdict(compliance, openCritical, openHigh, exposure, unverified);

  // Highest-priority items: failed first, then unverified (both need action).
  const topRisks = useMemo(
    () =>
      findings
        .filter((f) => ["FAIL", "UNKNOWN"].includes(String(f.status).toUpperCase()))
        .sort((a, b) => statusRank(String(a.status)) - statusRank(String(b.status)) || sevRank(String(a.severity)) - sevRank(String(b.severity)))
        .slice(0, 5),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [r.data]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter((f) => {
      if (sevFilter !== "ALL" && String(f.severity).toUpperCase() !== sevFilter) return false;
      if (engFilter !== "ALL" && String(f.engine).toUpperCase() !== engFilter) return false;
      if (q && !`${f.title ?? ""} ${f.finding_id ?? ""} ${f.control_id ?? ""}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [findings, sevFilter, engFilter, query]);

  if (r.isLoading) return <Loader label="Loading audit results…" />;
  if (r.isError || !r.data) return <ErrorState message="Results unavailable for this audit." onRetry={() => r.refetch()} />;

  return (
    <div>
      <PageHeader
        title="Audit Results"
        sub={`Audit ${auditId}${d.asset_id ? ` · Asset ${d.asset_id}` : ""}${d.configuration_id ? ` · Config ${d.configuration_id}` : ""}`}
        actions={<><Link to={`/audits/${auditId}`} className={btnGhost}>Progress</Link>
          <button className={btnPrimary} disabled={rep.isPending} onClick={() => rep.mutate()}>{rep.isPending ? "Generating…" : "Generate PDF Report"}</button></>}
      />
      {msg && <p className="mb-3 rounded-lg border border-ok/30 bg-okbg p-2.5 text-xs text-ok">{msg}</p>}
      {err && <p className="mb-3 rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}

      {/* 1 — Executive summary (manager view) */}
      <Card
        title="Executive summary"
        sub="What does this audit mean, and what should happen next?"
        right={<span className={`text-sm font-bold ${v.cls}`}>{v.label}</span>}
      >
        <p className="text-sm text-ink2">
          Compliance <b className="text-ink">{fmtNum(compliance)}%</b> · Security posture <b className="text-ink">{posture}/100</b> (exposure {band.toLowerCase()}) ·{" "}
          <b className="text-ink">{openCritical}</b> failed critical, <b className="text-ink">{openHigh}</b> failed high
          {unverified > 0 && <>, <b className="text-ink">{unverified}</b> unverified</>} ·{" "}
          <b className="text-ink">{cveVuln}</b> vulnerable software match(es), PQC readiness{" "}
          <b className="text-ink">{fmtNum(pqcReadiness, 0)}%</b>. {v.detail}
        </p>
        <ol className="mt-3 list-decimal space-y-1 pl-5 text-xs text-ink2">
          <li>Fix critical/high compliance failures first (Compliance tab — each item shows why it failed and the exact fix commands).</li>
          <li>Patch vulnerable software (Vulnerabilities tab — upgrade to the listed fixed version, then re-run the audit).</li>
          <li>Plan crypto migration for items flagged in the PQC tab; low/medium hardening can follow.</li>
        </ol>
      </Card>

      {/* 2 — KPI cards */}
      <div className="mb-4 mt-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Card><p className="text-xl font-semibold text-ink">{fmtNum(compliance)}%</p><p className="mt-0.5 text-xs text-ink3">Compliance score</p><Bar value={compliance} /></Card>
        <Card>
          <p className="text-xl font-semibold text-ink">{an.isLoading ? "…" : posture} <span className="text-sm font-normal text-ink3">/ 100</span></p>
          <p className={`mt-0.5 text-xs font-semibold ${textCls}`}>{an.isLoading ? "LOADING" : `${band.toUpperCase()} EXPOSURE`}</p>
          <p className="mt-0.5 text-[11px] text-ink3">Posture score — higher is better</p>
          <Bar value={exposure} cls={barCls} />
        </Card>
        <Card><p className="text-xl font-semibold text-danger">{critical}</p><p className="mt-0.5 text-xs text-ink3">Critical (all statuses)</p><p className="mt-1 text-xs text-ink3">Failed: <b className="text-ink">{openCritical}</b> · High: <b className="text-ink">{high}</b> (failed {openHigh})</p></Card>
        <Card><p className="text-xl font-semibold text-ink">{byStatus.FAIL ?? 0} <span className="text-sm font-normal text-ink3">fail</span></p><p className="mt-0.5 text-xs text-ink3">Pass: {byStatus.PASS ?? 0} · Unknown: {byStatus.UNKNOWN ?? 0}</p><p className="mt-1 text-xs text-ink3">Total: {counts.total_findings ?? findings.length}</p></Card>
        <Card><p className="text-xl font-semibold text-ink">{fmtNum(pqcReadiness, 0)}%</p><p className="mt-0.5 text-xs text-ink3">PQC readiness</p><Bar value={pqcReadiness} cls="bg-pqc" /></Card>
        <Card><p className="text-xl font-semibold text-ink">{cveVuln}</p><p className="mt-0.5 text-xs text-ink3">Vulnerable (CVE)</p><p className="mt-1 text-xs text-ink3">Not affected: {(d.cve as AnyRec)?.not_affected ?? "—"}</p></Card>
      </div>

      <div className="mb-4 flex flex-wrap gap-2">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)} className={tabCls(tab === t)}>{t === "Vulnerabilities" ? "Vulnerabilities (CVE)" : t}</button>
        ))}
      </div>

      {tab === "Overview" && (
        <div className="grid gap-3 lg:grid-cols-2">
          <Card title="Compliance by framework" sub="Score = % of controls passing. Open a framework in the Compliance section for per-control detail.">
            {!d.frameworks || !Object.keys(d.frameworks).length ? <Empty /> : (
              <table className="w-full text-xs">
                <thead><tr className="text-left text-ink3"><th className="py-1">Framework</th><th>Score</th><th>Passed</th><th>Failed</th><th>Unknown</th></tr></thead>
                <tbody>
                  {Object.entries(d.frameworks as AnyRec).map(([k, fv]: [string, any]) => (
                    <tr key={k} className="border-t border-line">
                      <td className="py-2 font-semibold text-ink">{k}</td>
                      <td className="py-2"><span className="font-semibold">{fmtNum(fv.score ?? fv.compliance_score, 0)}%</span><Bar value={Number(fv.score ?? fv.compliance_score ?? 0)} /></td>
                      <td className="py-2 text-ok">{fv.passed ?? "—"}/{fv.total ?? "—"}</td>
                      <td className="py-2 text-danger">{fv.failed ?? "—"}</td>
                      <td className="py-2 text-ink3">{fv.unknown ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
          <div className="space-y-3">
            <Card title="Findings distribution" sub="Where are the problems coming from?">
              <p className="text-xs font-semibold text-ink3">BY SEVERITY (failed + all)</p>
              <div className="mt-1 flex flex-wrap gap-2">{["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((sv) => (
                <span key={sv} className="rounded-md border border-line bg-surface2 px-2 py-1 text-xs"><b>{bySev[sv] ?? 0}</b> {sv.toLowerCase()}</span>
              ))}</div>
              <p className="mt-3 text-xs font-semibold text-ink3">BY ENGINE</p>
              <div className="mt-1 flex flex-wrap gap-2">{Object.keys(byEng).length ? Object.entries(byEng).map(([e, n]) => (
                <span key={e} className="rounded-md border border-line bg-surface2 px-2 py-1 text-xs"><b>{String(n)}</b> {e.toLowerCase()}</span>
              )) : <span className="text-xs text-ink3">—</span>}</div>
            </Card>
            <Card title="Top risks to fix first" sub="Failed findings first, then unverified controls">
              {!topRisks.length ? <Empty label="No failed or unverified findings — nothing urgent." /> : (
                <ul className="space-y-2 text-sm">
                  {topRisks.map((f: AnyRec) => (
                    <li key={f.finding_id} className="flex items-center justify-between gap-2 rounded-lg bg-surface2 p-2.5">
                      <div className="min-w-0"><Link to={`/findings/${f.finding_id}`} className="block truncate text-primary hover:underline">{f.title ?? f.finding_id}</Link>
                        <p className="truncate text-[11px] text-ink3">{f.finding_id} · {String(f.engine).toLowerCase()} · {f.status}</p></div>
                      <div className="flex shrink-0 gap-1.5"><Badge value={String(f.severity ?? "?")} kind="sev" /><Badge value={String(f.status ?? "?")} /></div>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
        </div>
      )}

      {tab === "Compliance" && (
        <Card
          title="Compliance controls"
          sub="What was checked, why it matters, and how to fix it. UNKNOWN = no evidence in the config, not a pass."
          right={
            <select value={ctlFilter} onChange={(e) => setCtlFilter(e.target.value)} className="rounded-lg border border-linestrong bg-surface px-2 py-1 text-xs">
              {["ALL", "FAIL", "UNKNOWN", "PASS"].map((o) => <option key={o} value={o}>{o}</option>)}
            </select>
          }
        >
          {ctl.isLoading ? <Loader /> : ctl.isError ? <ErrorState message="Could not load control detail." onRetry={() => ctl.refetch()} /> : (
            (() => {
              const items = (((ctl.data as AnyRec)?.items ?? []) as AnyRec[]);
              const base = items.length ? items : findings.filter((f) => String(f.engine).toUpperCase().includes("COMPLIANCE"));
              const nFail = base.filter((c: AnyRec) => String(c.status).toUpperCase() === "FAIL").length;
              const nUnk = base.filter((c: AnyRec) => String(c.status).toUpperCase() === "UNKNOWN").length;
              const nPass = base.filter((c: AnyRec) => String(c.status).toUpperCase() === "PASS").length;
              const list = ctlFilter === "ALL" ? base : base.filter((c: AnyRec) => String(c.status).toUpperCase() === ctlFilter);
              if (!list.length) return <Empty label={base.length ? `No ${ctlFilter.toLowerCase()} controls — try another filter.` : "No compliance findings."} />;
              return (
                <div>
                  <p className="mb-2 text-xs text-ink3">{base.length} controls — <b className="text-danger">{nFail} failed</b>, <b className="text-warn">{nUnk} unverified</b>, <b className="text-ok">{nPass} passing</b>.</p>
                  <ul className="space-y-2 text-sm">
                    {list.slice(0, 200).map((c: AnyRec, i: number) => (
                      <li key={c.finding_id ?? i} className="rounded-lg bg-surface2 p-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <Link to={`/findings/${c.finding_id}`} className="font-semibold text-primary hover:underline">{c.title ?? c.control_id ?? c.finding_id}</Link>
                          <div className="flex gap-1.5"><Badge value={String(c.severity ?? "?")} kind="sev" /><Badge value={String(c.status ?? "?")} /></div>
                        </div>
                        <p className="mt-1 text-xs text-ink3">{c.control_id ?? c.finding_id}{c.evidence_display ? ` · ${c.evidence_display.property}: observed ${c.evidence_display.observed}, expected ${c.evidence_display.expected}` : ""}</p>
                        {c.why_explanation && <p className="mt-1 text-xs text-ink2"><b>Why:</b> {c.why_explanation}</p>}
                        {c.impact_statement && <p className="mt-1 text-xs text-ink2"><b>Impact:</b> {c.impact_statement}</p>}
                        {(c.fix?.commands?.length || (c.remediation as AnyRec)?.detail) && (
                          <p className="mt-1 font-mono text-[11px] text-ink3">Fix: {(c.fix?.commands ?? []).slice(0, 3).join(" · ") || "see finding detail"}</p>
                        )}
                      </li>
                    ))}
                  </ul>
                  {list.length > 200 && <p className="mt-2 text-xs text-ink3">Showing first 200 — filter by status to narrow down.</p>}
                </div>
              );
            })()
          )}
        </Card>
      )}

      {tab === "Vulnerabilities" && (
        <Card title="Vulnerabilities (CVE)" sub="Which installed software versions are affected, and what to upgrade to.">
          {vulns.isLoading ? <Loader /> : vulns.isError ? <ErrorState message="Could not load CVE data." onRetry={() => vulns.refetch()} /> : (
            (() => {
              const vd = (vulns.data ?? {}) as AnyRec;
              const sum = (vd.summary ?? {}) as AnyRec;
              let items = ((vd.items ?? []) as AnyRec[]);
              // Fallback: unified CVE findings when the match table is empty
              // (e.g. inventory without an authoritative CPE mapping).
              if (!items.length) {
                items = findings
                  .filter((f) => String(f.engine).toUpperCase().includes("CVE"))
                  .map((f: AnyRec) => ({
                    cve_id: (f.source as AnyRec)?.cve ?? null,
                    product: (f.evidence as AnyRec)?.cpe ?? f.title ?? "—",
                    installed_version: (f.evidence as AnyRec)?.observed ?? "",
                    severity: f.severity, status: f.status,
                    fixed_version: (f.remediation as AnyRec)?.fixed_version ?? null,
                    finding_id: f.finding_id, reason: f.title,
                  }));
              }
              return (
                <div>
                  <div className="mb-3 flex flex-wrap gap-2 text-xs">
                    <span className="rounded-md border border-line bg-surface2 px-2 py-1"><b>{sum.total ?? items.length}</b> total</span>
                    <span className="rounded-md border border-danger/30 bg-dangerbg px-2 py-1"><b>{sum.critical ?? 0}</b> critical</span>
                    <span className="rounded-md border border-high/30 bg-highbg px-2 py-1"><b>{sum.high ?? 0}</b> high</span>
                    <span className="rounded-md border border-warn/30 bg-warnbg px-2 py-1"><b>{sum.medium ?? 0}</b> medium</span>
                    <span className="rounded-md border border-line bg-surface2 px-2 py-1"><b>{sum.unknown ?? sum.UNKNOWN ?? 0}</b> unknown</span>
                  </div>
                  {!items.length ? <Empty label="No CVE matches — software inventory shows no known vulnerabilities." /> : (
                    <div className="overflow-x-auto"><table className="w-full text-xs">
                      <thead><tr className="text-left text-ink3"><th className="py-1 pr-2">CVE</th><th className="pr-2">Product</th><th className="pr-2">Installed</th><th className="pr-2">Severity</th><th className="pr-2">Status</th><th>Fixed in</th></tr></thead>
                      <tbody>
                        {items.slice(0, 100).map((m: AnyRec, i: number) => (
                          <tr key={m.finding_id ?? i} className="border-t border-line">
                            <td className="py-2 pr-2">{m.finding_id
                              ? <Link to={`/vulnerabilities/${auditId}/${m.finding_id}`} className="font-mono text-primary hover:underline">{m.cve_id ?? m.finding_id}</Link>
                              : <span className="font-mono">{m.cve_id ?? "unresolved"}</span>}
                              {!m.cve_id && m.reason && <p className="max-w-64 truncate text-[11px] text-ink3">{String(m.reason).slice(0, 90)}</p>}</td>
                            <td className="py-2 pr-2">{m.product ?? "—"}</td>
                            <td className="py-2 pr-2 font-mono">{m.installed_version || "not detected"}</td>
                            <td className="py-2 pr-2"><Badge value={String(m.severity ?? "?")} kind="sev" /></td>
                            <td className="py-2 pr-2"><Badge value={String(m.status ?? "?")} /></td>
                            <td className="py-2 font-mono">{m.fixed_version ?? "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table></div>
                  )}
                  {(vd.unresolved as AnyRec[] | undefined)?.length ? (
                    <p className="mt-2 text-xs text-ink3">Unresolved inventory: {((vd.unresolved as AnyRec[]).length)} component(s) could not be matched — confirm versions manually.</p>
                  ) : null}
                </div>
              );
            })()
          )}
        </Card>
      )}

      {tab === "PQC" && (
        <Card title="Post-quantum readiness (PQC)" sub="Which crypto must migrate before quantum breaks it.">
          {pqc.isLoading ? <Loader /> : pqc.isError ? <ErrorState message="Could not load PQC data." onRetry={() => pqc.refetch()} /> : (
            (() => {
              const pd = (pqc.data ?? d.pqc ?? {}) as AnyRec;
              const algos = ((pd.algorithms ?? []) as AnyRec[]);
              const weak = ((pd.weak_algorithms ?? algos.filter((a: AnyRec) => a.pqc_status === "MIGRATION_REQUIRED")) as AnyRec[]);
              const recs = ((pd.migration_recommendations ?? (d.pqc as AnyRec)?.migration_recommendations ?? []) as AnyRec[]);
              // Fallback: unified PQC findings when the inventory is unavailable.
              const pqcFindings = findings.filter((f) => String(f.engine).toUpperCase().includes("PQC"));
              return (
                <div>
                  <p className="text-sm text-ink2">Readiness <b className="text-ink">{fmtNum(pd.readiness_score ?? pd.readiness ?? 0, 0)}%</b> — {String(pd.readiness_label ?? "—")}</p>
                  <Bar value={Number(pd.readiness_score ?? pd.readiness ?? 0)} cls="bg-pqc" />
                  {pd.counts && Object.keys(pd.counts).length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-2 text-xs">{Object.entries(pd.counts).map(([k, n]) => (
                      <span key={k} className="rounded-md border border-line bg-surface2 px-2 py-1"><b>{String(n)}</b> {k.replace(/_/g, " ").toLowerCase()}</span>
                    ))}</div>
                  )}
                  <h4 className="mt-4 text-xs font-semibold text-ink">Crypto inventory ({algos.length || pqcFindings.length})</h4>
                  {algos.length ? (
                    <ul className="mt-2 space-y-1.5 text-xs">{algos.slice(0, 50).map((a: AnyRec, i: number) => (
                      <li key={i} className="rounded-lg bg-surface2 p-2.5 text-ink2">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <b className="text-ink">{a.algorithm ?? "unknown"}</b>
                          <Badge value={String(a.pqc_status ?? "?")} />
                        </div>
                        <p className="mt-0.5 text-ink3">{a.protocol ?? "—"}{a.version ? ` · version ${a.version}` : " · version not detected"}</p>
                        {a.summary && <p className="mt-1 text-ink2">{a.summary}</p>}
                        {(a.recommended || a.migration) && <p className="mt-1 text-ink2"><b>Next:</b> {String(a.recommended ?? a.migration)}</p>}
                      </li>
                    ))}</ul>
                  ) : pqcFindings.length ? (
                    <ul className="mt-2 space-y-1.5 text-xs">{pqcFindings.slice(0, 50).map((f: AnyRec) => (
                      <li key={f.finding_id} className="flex items-center justify-between gap-2 rounded-lg bg-surface2 p-2.5">
                        <Link to={`/findings/${f.finding_id}`} className="truncate text-primary hover:underline">{f.title ?? f.finding_id}</Link>
                        <Badge value={String(f.severity ?? "?")} kind="sev" />
                      </li>
                    ))}</ul>
                  ) : (
                    <p className="mt-1 text-xs text-ink3">No crypto inventory — the config mentioned no TLS/SSH/IKE/keys or software versions to assess. weak: {weak.length}.</p>
                  )}
                  {!!weak.length && (
                    <p className="mt-2 text-xs text-danger">{weak.length} algorithm(s) require migration now (broken or deprecated today) — see inventory above.</p>
                  )}
                  {!!recs.length && (
                    <div className="mt-3"><h4 className="text-xs font-semibold text-ink">Migration recommendations</h4>
                      <ul className="mt-1 list-disc space-y-1 pl-5 text-xs text-ink2">{recs.slice(0, 10).map((x: any, i: number) => (
                        <li key={i}>{typeof x === "string" ? x : (x.summary ?? x.recommended_direction ?? x.migration ?? JSON.stringify(x))}</li>
                      ))}</ul></div>
                  )}
                </div>
              );
            })()
          )}
        </Card>
      )}

      {tab === "Security" && (
        <Card title="Security analytics" sub="Posture checks: weak auth, exposure, permissive access, legacy services, logging gaps.">
          {an.isLoading ? <Loader /> : an.isError ? <ErrorState message="Could not load analytics." onRetry={() => an.refetch()} /> : (
            (() => {
              const ad = (an.data ?? {}) as AnyRec;
              const adPosture = Number(ad.risk_score ?? posture) || 0;
              const adExposure = Math.min(100, Math.max(0, 100 - adPosture));
              const [adBand, adBar, adText] = exposureBand(adExposure);
              const anomalies = ((ad.anomalies ?? []) as AnyRec[]);
              const patterns = ((ad.patterns ?? (d.security as AnyRec)?.patterns ?? []) as AnyRec[]);
              // Fallback: unified security findings carry the same signal when
              // the analytics engine recorded no anomalies (e.g. clean posture).
              const secFindings = findings.filter((f) => ["SECURITY", "SECUR", "ANALYT"].some((k) => String(f.engine).toUpperCase().includes(k)));
              return (
                <div>
                  <p className="text-sm text-ink2">Posture <b className="text-ink">{adPosture}/100</b> — exposure <b className={adText}>{adBand}</b> (higher posture is better; {anomalies.length} anomalie(s){patterns.length ? `, ${patterns.length} attack pattern(s)` : ""}).</p>
                  <Bar value={adExposure} cls={adBar} />
                  {!!patterns.length && (
                    <div className="mt-3"><h4 className="text-xs font-semibold text-danger">Attack patterns ({patterns.length})</h4>
                      <ul className="mt-1.5 space-y-1.5 text-xs">{patterns.map((a: AnyRec, i: number) => (
                        <li key={i} className="rounded-lg border border-danger/30 bg-dangerbg p-2.5">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <b className="text-ink">{a.pattern ?? a.type ?? "pattern"}</b>
                            <Badge value={String(a.severity ?? "?")} kind="sev" />
                          </div>
                          {a.detail && <p className="mt-0.5 text-ink2">{a.detail}</p>}
                          {Array.isArray(a.contributors) && <p className="mt-0.5 text-ink3">Contributors: {a.contributors.join(", ")}</p>}
                        </li>
                      ))}</ul></div>
                  )}
                  <h4 className="mt-3 text-xs font-semibold text-ink">Anomalies ({anomalies.length})</h4>
                  {!anomalies.length ? <p className="mt-1 text-xs text-ink3">No anomalies — all posture checks passed. A posture of 100/100 with zero anomalies means clean, not critical.</p> : (
                    <ul className="mt-1.5 space-y-1.5 text-xs">{anomalies.map((a: AnyRec, i: number) => (
                      <li key={i} className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-surface2 p-2.5">
                        <div><b className="text-ink">{a.type ?? "anomaly"}</b> <span className="text-ink3">· {a.property ?? ""}</span>
                          <p className="mt-0.5 text-ink2">{a.detail ?? ""}</p></div>
                        <Badge value={String(a.severity ?? "?")} kind="sev" />
                      </li>
                    ))}</ul>
                  )}
                  {!!secFindings.length && (
                    <div className="mt-3"><h4 className="text-xs font-semibold text-ink">Related security findings ({secFindings.length})</h4>
                      <ul className="mt-1.5 space-y-1.5 text-xs">{secFindings.slice(0, 50).map((f: AnyRec) => (
                        <li key={f.finding_id} className="flex items-center justify-between gap-2 rounded-lg bg-surface2 p-2.5">
                          <Link to={`/findings/${f.finding_id}`} className="truncate text-primary hover:underline">{f.title ?? f.finding_id}</Link>
                          <div className="flex shrink-0 gap-1.5"><Badge value={String(f.severity ?? "?")} kind="sev" /><Badge value={String(f.status ?? "?")} /></div>
                        </li>
                      ))}</ul></div>
                  )}
                </div>
              );
            })()
          )}
        </Card>
      )}

      {tab === "Findings" && (
        <Card
          title={`${filtered.length} of ${findings.length} findings`}
          sub="Search and filter everything in one place. Open a row for evidence, risk and remediation."
          right={
            <div className="flex flex-wrap gap-1.5">
              <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} className="rounded-lg border border-linestrong bg-surface px-2 py-1 text-xs">
                {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
              <select value={engFilter} onChange={(e) => setEngFilter(e.target.value)} className="rounded-lg border border-linestrong bg-surface px-2 py-1 text-xs">
                {["ALL", "COMPLIANCE", "CVE", "PQC", "SECURITY"].map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search title or ID…" className="rounded-lg border border-linestrong bg-surface px-2 py-1 text-xs" />
            </div>
          }
        >
          {!filtered.length ? <Empty label="No findings match these filters." /> : (
            <ul className="space-y-1.5 text-sm">
              {filtered.slice(0, 200).map((f: AnyRec) => (
                <li key={f.finding_id} className="flex items-center justify-between gap-2 rounded-lg bg-surface2 p-2.5">
                  <div className="min-w-0">
                    <Link to={`/findings/${f.finding_id}`} className="block truncate text-primary hover:underline">{f.title ?? f.finding_id}</Link>
                    <p className="truncate text-[11px] text-ink3">{f.finding_id} · {String(f.engine).toLowerCase()} · {f.status}</p>
                  </div>
                  <div className="flex shrink-0 gap-1.5"><Badge value={String(f.severity ?? "?")} kind="sev" /><Badge value={String(f.status ?? "?")} /></div>
                </li>
              ))}
            </ul>
          )}
          {filtered.length > 200 && <p className="mt-2 text-xs text-ink3">Showing first 200 — narrow the filters to see more.</p>}
        </Card>
      )}

      {tab === "Evidence" && (
        <Card title="Evidence chain" sub="Why was each finding generated? Observed vs expected, with config source.">
          {ev.isLoading ? <Loader /> : ev.isError ? <ErrorState message="Could not load evidence." onRetry={() => ev.refetch()} /> : (
            (() => {
              const items = (((ev.data as AnyRec)?.items ?? []) as AnyRec[]);
              if (!items.length) return <Empty label="No evidence items." />;
              return (
                <ul className="space-y-2 text-xs">
                  {items.slice(0, 100).map((e: AnyRec, i: number) => (
                    <li key={i} className="rounded-lg bg-surface2 p-3 text-ink2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-mono font-semibold text-primary">{String(e.control_id ?? e.property ?? `item-${i}`)}</span>
                        {e.source?.line_no != null && <span className="text-ink3">config line {String(e.source.line_no)}{e.source.line ? `: ${String(e.source.line).slice(0, 80)}` : ""}</span>}
                      </div>
                      <p className="mt-1">Property <b className="text-ink">{String(e.property ?? "—")}</b> · observed <b className="text-ink">{fmtVal(e.observed_value ?? (e as AnyRec).observed)}</b> · expected <b className="text-ink">{fmtVal(e.expected_value ?? (e as AnyRec).expected)}</b></p>
                      <details className="mt-1 text-ink3"><summary className="cursor-pointer hover:underline">Raw record</summary>
                        <pre className="code-view mt-1 whitespace-pre-wrap">{JSON.stringify(e, null, 2)}</pre></details>
                    </li>
                  ))}
                </ul>
              );
            })()
          )}
        </Card>
      )}

      {tab === "Details" && (
        <div className="grid gap-3 lg:grid-cols-2">
          <Card title="Provenance & reproducibility" sub="How to reproduce this exact audit.">
            <dl className="space-y-1.5 text-xs text-ink2">
              <div className="flex justify-between gap-3"><dt className="text-ink3">Config SHA-256</dt><dd className="truncate font-mono">{d.config_sha256 ?? "—"}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-ink3">Asset / Configuration</dt><dd>{`${d.asset_id ?? "—"} / ${d.configuration_id ?? "—"}`}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-ink3">Vendor detection</dt><dd>{JSON.stringify((d.vendor as AnyRec)?.vendor_id ?? d.vendor ?? "—")}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-ink3">IR valid</dt><dd>{String((d.ir_validation as AnyRec)?.valid ?? "—")}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-ink3">LLM offline</dt><dd>{String(d.llm_offline ?? "—")}</dd></div>
            </dl>
            <h4 className="mt-3 text-xs font-semibold text-ink">Knowledge versions</h4>
            {!d.versions ? <p className="text-xs text-ink3">—</p> : (
              <dl className="mt-1 space-y-1 text-xs">{Object.entries(d.versions as AnyRec).map(([k, n]) => (
                <div key={k} className="flex justify-between gap-3"><dt className="text-ink3">{k}</dt><dd className="truncate font-mono text-ink2">{String(n)}</dd></div>
              ))}</dl>
            )}
          </Card>
          <Card title="Parser coverage" sub="Lines the parser could not map — unmapped config stays visible instead of silently ignored.">
            {!(d.unknown_lines as AnyRec[] | undefined)?.length
              ? <Empty label="No unknown lines — full parser coverage." />
              : <ul className="max-h-64 space-y-1 overflow-auto font-mono text-[11px] text-ink2">{((d.unknown_lines ?? []) as string[]).slice(0, 100).map((l, i) => (
                <li key={i} className="rounded bg-surface2 px-2 py-1">{l}</li>
              ))}</ul>}
            <p className="mt-2 text-[11px] text-ink3">Canonical IR holds {Object.keys((d.canonical_ir ?? {}) as object).length} top-level sections. Full IR is available via the API for debugging.</p>
          </Card>
        </div>
      )}
    </div>
  );
}

function sevRank(s: string): number {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
  const i = order.indexOf(s.toUpperCase());
  return i === -1 ? 99 : i;
}

function statusRank(s: string): number {
  const order = ["FAIL", "UNKNOWN", "PASS"];
  const i = order.indexOf(s.toUpperCase());
  return i === -1 ? 99 : i;
}

function fmtVal(v: unknown): string {
  if (v === null || v === undefined || v === "") return "not set";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
