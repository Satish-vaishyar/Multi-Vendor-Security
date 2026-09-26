import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { getAuditEvidence, getAuditResults } from "../api/audits.api";
import { createReport } from "../api/reports.api";
import { toMessage } from "../api/client";
import { REPORT_SECTIONS } from "../constants";
import { Badge, Card, Empty, ErrorState, Loader, PageHeader, btnGhost, btnPrimary } from "../components/common";
import { fmtNum } from "../utils/format";

const TABS = ["Overview", "Compliance", "CVE", "PQC", "Security", "Findings", "Evidence", "Remediation"] as const;

const tabCls = (active: boolean) =>
  `rounded-lg border px-3 py-1.5 text-xs font-semibold ${active ? "border-primary bg-primarylight text-primary" : "border-linestrong bg-surface text-ink2 hover:bg-surface2"}`;

/** Risk band 0–30 Low, 31–60 Moderate, 61–80 High, 81–100 Critical. */
function riskBand(v: number): [string, string, string] {
  if (v >= 81) return ["Critical", "bg-danger", "text-danger"];
  if (v >= 61) return ["High", "bg-high", "text-high"];
  if (v >= 31) return ["Moderate", "bg-warn", "text-warn"];
  return ["Low", "bg-primary", "text-primary"];
}

export default function AuditResults() {
  const { auditId = "" } = useParams();
  const [tab, setTab] = useState<(typeof TABS)[number]>("Overview");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const r = useQuery({ queryKey: ["results", auditId], queryFn: () => getAuditResults(auditId) });
  const ev = useQuery({ queryKey: ["evidence", auditId], queryFn: () => getAuditEvidence(auditId), enabled: tab === "Evidence" });

  const rep = useMutation({
    mutationFn: () => createReport({ audit_id: auditId, format: "PDF", sections: [...REPORT_SECTIONS] }),
    onSuccess: () => { setErr(""); setMsg("Report generation started — see the Reports page."); },
    onError: (e) => { setMsg(""); setErr(toMessage(e)); },
  });

  if (r.isLoading) return <Loader label="Loading audit results…" />;
  if (r.isError || !r.data) return <ErrorState message="Results unavailable for this audit." onRetry={() => r.refetch()} />;
  const d = r.data;
  const s = d.summary ?? {};
  const findings = d.findings ?? [];
  const byType = (t: string) => findings.filter((f) => String(f.engine ?? f.type ?? "").toUpperCase().includes(t));
  const risk = Number((d as Record<string, unknown>).risk_score ?? 0);
  const [band, barCls, textCls] = riskBand(risk);

  return (
    <div>
      <PageHeader
        title="Audit Results"
        sub={`Audit ${auditId} · Compliance ${fmtNum(s.compliance_score)}%`}
        actions={<><Link to={`/audits/${auditId}`} className={btnGhost}>Progress</Link>
          <button className={btnPrimary} disabled={rep.isPending} onClick={() => rep.mutate()}>{rep.isPending ? "Generating…" : "Generate PDF Report"}</button></>}
      />
      {msg && <p className="mb-3 rounded-lg border border-ok/30 bg-okbg p-2.5 text-xs text-ok">{msg}</p>}
      {err && <p className="mb-3 rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
        <Card>
          <p className="text-xs text-ink3">Overall Risk</p>
          <p className="mt-1 text-xl font-semibold text-ink">{risk} <span className="text-sm font-normal text-ink3">/ 100</span></p>
          <p className={`mt-0.5 text-xs font-semibold ${textCls}`}>{band.toUpperCase()}</p>
          <div className="mt-2 h-2 overflow-hidden rounded-full bg-surface2">
            <div className={`h-full rounded-full ${barCls}`} style={{ width: `${Math.min(100, risk)}%` }} />
          </div>
        </Card>
        {[["Compliance", `${fmtNum(s.compliance_score)}%`],
          ["Critical", String(s.critical ?? 0)], ["High", String(s.high ?? 0)], ["Medium / Low", `${s.medium ?? 0} / ${s.low ?? 0}`]].map(([k, v]) => (
          <Card key={k}><p className="text-xl font-semibold text-ink">{v}</p><p className="mt-0.5 text-xs text-ink3">{k}</p></Card>
        ))}
      </div>

      <div className="mb-4 flex flex-wrap gap-2">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)} className={tabCls(tab === t)}>{t}</button>
        ))}
      </div>

      {tab === "Overview" && (
        <Card title="Framework Scores">
          {!d.frameworks ? <Empty /> : (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {Object.entries(d.frameworks).map(([k, v]) => (
                <div key={k} className="rounded-lg bg-surface2 p-3">
                  <p className="text-xs font-medium text-ink2">{k}</p>
                  <p className="mt-0.5 text-lg font-semibold text-ink">{fmtNum(v.score, 0)}%</p>
                  <div className="mt-2 h-2 overflow-hidden rounded-full bg-line/60">
                    <div className="h-full rounded-full bg-primary" style={{ width: `${Math.min(100, Number(v.score ?? 0))}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}
      {tab === "Compliance" && <FindingList items={byType("COMPLIANCE")} empty="No compliance findings." />}
      {tab === "CVE" && <FindingList items={byType("CVE")} empty="No CVE findings." />}
      {tab === "PQC" && <FindingList items={byType("PQC")} empty="No PQC findings." />}
      {tab === "Security" && <FindingList items={byType("SECUR").length ? byType("SECUR") : byType("ANALYT")} empty="No security findings." />}
      {tab === "Findings" && <FindingList items={findings} empty="No findings." />}
      {tab === "Evidence" && (
        <Card title="Evidence Chain" sub="Why was each finding generated?">
          {ev.isLoading ? <Loader /> : !ev.data?.items?.length ? <Empty label="No evidence items." /> : (
            <ul className="space-y-2 text-xs">
              {(ev.data.items as Record<string, unknown>[]).map((e, i) => (
                <li key={i} className="rounded-lg bg-surface2 p-3 text-ink2">
                  <span className="font-mono text-primary">{String(e.control_id ?? e.property ?? `item-${i}`)}</span>
                  <pre className="code-view mt-1 whitespace-pre-wrap text-ink3">{JSON.stringify(e, null, 2)}</pre>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}
      {tab === "Remediation" && (
        <Card title="Remediation" sub="Per-finding vendor-specific fixes">
          <p className="text-sm text-ink2">Open a finding to view its remediation plan (commands, validation, rollback, approval).</p>
          <Link to="/findings" className="mt-2 inline-block text-xs font-semibold text-primary hover:underline">Browse findings →</Link>
        </Card>
      )}
    </div>
  );
}

function FindingList({ items, empty }: { items: { finding_id: string; title?: string; severity?: string }[]; empty: string }) {
  if (!items.length) return <Empty label={empty} />;
  return (
    <Card title={`${items.length} findings`}>
      <ul className="space-y-2 text-sm">
        {items.map((f) => (
          <li key={f.finding_id} className="flex items-center justify-between gap-2 rounded-lg bg-surface2 p-2.5">
            <Link to={`/findings/${f.finding_id}`} className="truncate text-primary hover:underline">{f.title ?? f.finding_id}</Link>
            <Badge value={String(f.severity ?? "?")} kind="sev" />
          </li>
        ))}
      </ul>
    </Card>
  );
}
