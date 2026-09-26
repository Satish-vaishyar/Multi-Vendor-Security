import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { createReport, downloadReport, getReport } from "../api/reports.api";
import { toMessage } from "../api/client";
import { REPORT_SECTIONS } from "../constants";
import { fmtScore, useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Badge, Card, Empty, Field, Loader, PageHeader, btnPrimary, inputCls } from "../components/common";

export default function Reports() {
  const [picked, pick] = useSelectedAudit();
  const audits = useAuditOverviews();
  const [auditId, setAuditId] = useState(picked);
  const [sections, setSections] = useState<string[]>([...REPORT_SECTIONS]);
  const [reportId, setReportId] = useState("");
  const [err, setErr] = useState("");

  const fromPicker = (id: string) => {
    pick(id);
    setAuditId(id);
  };

  const create = useMutation({
    mutationFn: () => createReport({ audit_id: auditId, format: "PDF", sections }),
    onSuccess: (d) => { setErr(""); setReportId(d.report_id); },
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

  const toggle = (s: string) => setSections((p) => (p.includes(s) ? p.filter((x) => x !== s) : [...p, s]));
  const done = String(status.data?.status ?? "").toUpperCase() === "COMPLETED";

  return (
    <div>
      <PageHeader title="Reports" sub="Backend-generated authoritative PDFs — POST /reports" />
      <div className="mb-4">
        <AuditPicker
          overviews={audits.overviews} isLoading={audits.isLoading} isError={audits.isError} onRetry={audits.refetch}
          value={picked} onSelect={fromPicker}
          renderBrief={(a) => <>Compliance {fmtScore(a.compliance_score)}% · {a.total} findings · {a.critical} critical</>}
        />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Generate Report">
          <Field label="Audit ID"><input className={`${inputCls} mt-1 font-mono`} value={auditId} onChange={(e) => setAuditId(e.target.value)} placeholder="AUD-…" /></Field>
          <p className="mb-1.5 mt-3 text-[11px] uppercase tracking-wider text-ink3">Sections</p>
          <div className="flex flex-wrap gap-2">
            {REPORT_SECTIONS.map((s) => (
              <label key={s} className={`cursor-pointer rounded-lg border px-3 py-1.5 text-xs font-semibold ${sections.includes(s) ? "border-primary bg-primarylight text-primary" : "border-linestrong bg-surface text-ink2"}`}>
                <input type="checkbox" className="mr-1.5 accent-primary" checked={sections.includes(s)} onChange={() => toggle(s)} />{s}
              </label>
            ))}
          </div>
          <button className={`${btnPrimary} mt-4`} disabled={!auditId || !sections.length || create.isPending} onClick={() => create.mutate()}>
            {create.isPending ? "Generating…" : "Generate PDF Report"}
          </button>
          {err && <p className="mt-3 rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}
        </Card>
        <Card title="Report Status" sub={reportId ? `Report ${reportId}` : "No report requested yet"}>
          {!reportId ? <Empty label="Generate a report to track its status here." /> :
            status.isLoading ? <Loader label="Generating report…" /> : (
              <>
                <Badge value={String(status.data?.status ?? "—")} />
                <p className="mt-2 break-all text-xs text-ink3">Download URL: {String(status.data?.download_url ?? "—")}</p>
                {done ? (
                  <button className={`${btnPrimary} mt-3`} disabled={dlBusy} onClick={dl}>{dlBusy ? "Downloading…" : "Download PDF"}</button>
                ) : (
                  <p className="mt-3 text-xs text-ink3">Generating report… (polling status)</p>
                )}
              </>
            )}
        </Card>
      </div>
    </div>
  );
}
