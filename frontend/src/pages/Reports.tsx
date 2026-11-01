import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createReport, downloadEvidencePack, downloadFleet, downloadReport, getReport, listSignoffs, signReport } from "../api/reports.api";
import { useAuth } from "../stores/auth";
import { hasRole } from "../utils/roles";
import { toMessage } from "../api/client";
import { markMilestone } from "../utils/progress";
import { REPORT_SECTIONS } from "../constants";
import { fmtScore, useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Badge, Card, Empty, Field, Loader, Notice, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";

export default function Reports() {
  const [picked, pick] = useSelectedAudit();
  const audits = useAuditOverviews();
  const [auditId, setAuditId] = useState(picked);
  const [sections, setSections] = useState<string[]>([...REPORT_SECTIONS]);
  const [reportId, setReportId] = useState("");
  const [err, setErr] = useState("");
  const [fw, setFw] = useState("CIS");
  const [comment, setComment] = useState("");
  const qc = useQueryClient();
  const user = useAuth((s) => s.user);
  const canSign = hasRole(user?.role, "APPROVER");
  const run = (p: Promise<unknown>) => void p.catch((e) => setErr(toMessage(e)));

  const fromPicker = (id: string) => {
    pick(id);
    setAuditId(id);
  };

  const create = useMutation({
    mutationFn: () => createReport({ audit_id: auditId, format: "PDF", sections }),
    onSuccess: (d) => { setErr(""); setReportId(d.report_id); markMilestone("report"); },
    onError: (e) => setErr(toMessage(e)),
  });
  // Poll report status until COMPLETED (frontend.md §40)
  const status = useQuery({
    queryKey: ["report", reportId],
    queryFn: () => getReport(reportId),
    enabled: !!reportId,
    refetchInterval: (q) => (String(q.state.data?.status ?? "").toUpperCase() === "COMPLETED" ? false : 2500),
  });
  const [dlBusy, setDlBusy] = useState(false);
  const dl = async () => {
    setDlBusy(true);
    try {
      const blob = await downloadReport(reportId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `${reportId}.pdf`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setErr(toMessage(e));
    } finally {
      setDlBusy(false);
    }
  };

  const sigs = useQuery({ queryKey: ["signoffs", reportId], queryFn: () => listSignoffs(reportId), enabled: !!reportId });
  const sign = useMutation({
    mutationFn: () => signReport(reportId, comment),
    onSuccess: () => { setErr(""); setComment(""); void qc.invalidateQueries({ queryKey: ["signoffs", reportId] }); },
    onError: (e) => setErr(toMessage(e)),
  });

  const toggle = (s: string) => setSections((p) => (p.includes(s) ? p.filter((x) => x !== s) : [...p, s]));
  const done = String(status.data?.status ?? "").toUpperCase() === "COMPLETED";

  return (
    <div>
      <PageHeader title="Reports" sub="Create a PDF for your team or an auditor. Pick an audit, choose what to include, then download."
        actions={<>
          <button className={btnGhost} onClick={() => run(downloadFleet("pdf"))}>Fleet summary PDF</button>
          <button className={btnGhost} onClick={() => run(downloadFleet("csv"))}>Fleet CSV</button>
          <button className={btnGhost} onClick={() => run(downloadFleet("json"))}>Fleet JSON</button>
        </>} />
      <div className="mb-4">
        <AuditPicker
          overviews={audits.overviews} isLoading={audits.isLoading} isError={audits.isError} onRetry={audits.refetch}
          value={picked} onSelect={fromPicker}
          renderBrief={(a) => <>Compliance {fmtScore(a.compliance_score)}% · {a.total} findings · {a.critical} critical</>}
        />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Generate report">
          <Field label="Audit ID"><input data-testid="report-audit-id" className={`${inputCls} mt-1 font-mono`} value={auditId} onChange={(e) => setAuditId(e.target.value)} placeholder="AUD-…" /></Field>
          <p className="mb-1.5 mt-3 text-xs font-medium text-ink2">Sections</p>
          <div className="flex flex-wrap gap-2">
            {REPORT_SECTIONS.map((s) => (
              <label key={s} className={`cursor-pointer rounded-lg border px-3 py-1.5 text-xs font-semibold ${sections.includes(s) ? "border-primary bg-primarylight text-primary" : "border-linestrong bg-surface text-ink2"}`}>
                <input type="checkbox" className="mr-1.5 accent-primary" checked={sections.includes(s)} onChange={() => toggle(s)} />{s.replace(/_/g, " ").toLowerCase().replace(/^./, (c) => c.toUpperCase()).replace(/\b(cve|pqc)\b/i, (m) => m.toUpperCase())}
              </label>
            ))}
          </div>
          <button data-testid="report-generate" className={`${btnPrimary} mt-4`} disabled={!auditId || !sections.length || create.isPending} onClick={() => create.mutate()}>
            {create.isPending ? "Generating…" : "Generate PDF report"}
          </button>
          <p className="mb-1.5 mt-5 text-xs font-medium text-ink2">Evidence pack for one framework (for auditor sign-off)</p>
          <div className="flex flex-wrap items-center gap-2">
            <select className={`${inputCls} w-40`} aria-label="Framework for the evidence pack" value={fw} onChange={(e) => setFw(e.target.value)}>
              {["CIS", "NIST", "STIG", "ISO27001"].map((x) => <option key={x}>{x}</option>)}
            </select>
            <button className={btnGhost} disabled={!auditId} onClick={() => run(downloadEvidencePack(auditId, fw, "csv"))}>Evidence CSV</button>
            <button className={btnGhost} disabled={!auditId} onClick={() => run(downloadEvidencePack(auditId, fw, "json"))}>Evidence JSON</button>
          </div>
          {err && <div className="mt-3"><Notice kind="error" testId="report-error">{err}</Notice></div>}
        </Card>
        <Card title="Report status" sub={reportId ? `Report ${reportId}` : "No report requested yet"}>
          {!reportId ? <Empty label="No report yet." hint="Choose an audit on the left and press Generate PDF report." /> :
            status.isLoading ? <Loader label="Generating report…" /> : (
              <>
                <Badge value={String(status.data?.status ?? "—")} />
                
                {done ? (
                  <button className={`${btnPrimary} mt-3`} disabled={dlBusy} onClick={dl}>{dlBusy ? "Downloading…" : "Download PDF"}</button>
                ) : (
                  <p className="mt-3 text-xs text-ink3">Generating report… (polling status)</p>
                )}
                {done && (
                  <div className="mt-4 border-t border-line pt-3">
                    <p className="mb-1.5 text-xs font-medium text-ink2">Sign-off</p>
                    {(sigs.data ?? []).length === 0 ? <p className="text-xs text-ink3">Not signed off yet.</p> : (
                      <ul className="space-y-1 text-xs">
                        {(sigs.data ?? []).map((s) => (
                          <li key={s.signoff_id} className="rounded bg-surface2 px-2 py-1">
                            <b>{s.signed_by}</b> ({s.role}) · {new Date(s.signed_at * 1000).toLocaleString()}
                            {s.comment && <span className="text-ink2"> — {s.comment}</span>}
                            <span className="block break-all font-mono text-[10px] text-ink3">sha256 {s.report_sha256}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                    {canSign ? (
                      <div className="mt-2 flex gap-2">
                        <input className={inputCls} value={comment} maxLength={1000} onChange={(e) => setComment(e.target.value)} placeholder="Comment (optional)" />
                        <button className={btnPrimary} disabled={sign.isPending} onClick={() => sign.mutate()}>{sign.isPending ? "Signing…" : "Sign off"}</button>
                      </div>
                    ) : <p className="mt-2 text-xs text-ink3">Sign-off requires the APPROVER role.</p>}
                  </div>
                )}
              </>
            )}
        </Card>
      </div>
    </div>
  );
}
