import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { ChevronDown, ChevronUp } from "lucide-react";
import { approveRemediation, applyRemediation, getRemediation } from "../api/remediation.api";
import { getFinding } from "../api/findings.api";
import { listFindings } from "../api/findings.api";
import { toMessage } from "../api/client";
import { useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Badge, Card, Empty, ErrorState, Field, Loader, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";

interface FixOption {
  id: string;
  title: string;
  tag: string;
  lines: string[];
}

function buildOptions(plan: Record<string, unknown>, finding: Record<string, unknown>): FixOption[] {
  const opts: FixOption[] = [];
  const steps = (plan.steps as { order?: number; command?: string }[] | undefined) ?? [];
  if (steps.length) {
    opts.push({
      id: "vendor",
      title: "Vendor recommended procedure",
      tag: "OKF vendor procedure",
      lines: steps.map((s) => String(s.command ?? "")),
    });
  }
  const rem = (finding.remediation ?? {}) as Record<string, unknown>;
  const fixed = String(rem.fixed_version ?? "");
  const eng = String(finding.engine ?? finding.type ?? "").toUpperCase();
  if ((eng.includes("CVE") || eng.includes("VULN")) && fixed) {
    opts.push({
      id: "upgrade",
      title: `Upgrade to ${fixed}`,
      tag: "CVE advisory",
      lines: [`Upgrade ${String(finding.asset_id ?? "device")} to vendor-validated version ${fixed}`, "Re-run audit to verify the CVE is resolved"],
    });
  }
  const validation = (plan.validation as unknown[] | undefined) ?? [];
  if (validation.length) {
    opts.push({
      id: "validate",
      title: "Validate & re-audit",
      tag: "Verification",
      lines: validation.map(String),
    });
  }
  return opts.slice(0, 3);
}

export default function Remediation() {
  const { findingId: paramId = "" } = useParams();
  const [auditId, selectAudit] = useSelectedAudit();
  const audits = useAuditOverviews();
  const [expanded, setExpanded] = useState(paramId);
  const [chosen, setChosen] = useState<{ fid: string; opt: string } | null>(paramId ? { fid: paramId, opt: "vendor" } : null);
  const [manual, setManual] = useState("");

  const auditFindings = useQuery({
    queryKey: ["findings", { audit: auditId }],
    queryFn: () => listFindings({ audit_id: auditId }),
    enabled: !!auditId,
  });

  return (
    <div>
      <PageHeader title="Remediation" sub="Suggested fixes per finding — choose the best fit, then dry-run" />
      <div className="mb-4">
        <AuditPicker
          overviews={audits.overviews} isLoading={audits.isLoading} isError={audits.isError} onRetry={audits.refetch}
          value={auditId} onSelect={selectAudit}
          renderBrief={(a) => <>{a.total} findings with suggested fixes</>}
        />
      </div>
      <div className="mb-4">
        <Card
          title={auditId ? `Findings in ${auditId}` : "Findings"}
          sub="Expand a finding to see its suggested fixes"
          right={
            <span className="flex gap-2">
              <input className={`${inputCls} w-44`} placeholder="…or finding ID" value={manual} onChange={(e) => setManual(e.target.value)} />
              <button
                className="rounded-lg bg-primary px-3 py-2 text-xs font-semibold text-onprimary hover:bg-primaryhover"
                onClick={() => { if (manual.trim()) { setExpanded(manual.trim()); setChosen({ fid: manual.trim(), opt: "vendor" }); } }}
              >Load</button>
            </span>
          }
        >
          {!auditId && !paramId ? <Empty label="Select an audit above to list its findings." /> :
            !auditId ? <FindingFix findingId={paramId} chosen={chosen} setChosen={setChosen} setExpanded={setExpanded} /> :
              auditFindings.isLoading ? <Loader label="Loading findings…" /> :
                auditFindings.isError ? <ErrorState message="Unable to load findings." onRetry={() => auditFindings.refetch()} /> :
                  !(auditFindings.data?.items?.length) ? <Empty label="No findings in this audit." /> : (
                    <ul className="max-h-96 space-y-2 overflow-auto">
                      {(auditFindings.data?.items ?? []).map((x) => (
                        <li key={x.finding_id} className="rounded-lg border border-line">
                          <button
                            onClick={() => setExpanded((e) => (e === x.finding_id ? "" : x.finding_id))}
                            className="flex w-full items-center justify-between gap-2 p-2.5 text-left text-sm hover:bg-surface2"
                          >
                            <span className="truncate text-ink2">{x.title ?? x.finding_id}</span>
                            <span className="flex shrink-0 items-center gap-2">
                              <Badge value={String(x.severity ?? "?")} kind="sev" />
                              {expanded === x.finding_id ? <ChevronUp size={14} className="text-ink3" /> : <ChevronDown size={14} className="text-ink3" />}
                            </span>
                          </button>
                          {expanded === x.finding_id && (
                            <div className="border-t border-line p-3">
                              <FindingFix findingId={x.finding_id} chosen={chosen} setChosen={setChosen} setExpanded={setExpanded} />
                            </div>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
        </Card>
      </div>
      {chosen?.fid && <ApplyPanel findingId={chosen.fid} optionId={chosen.opt} />}
    </div>
  );
}

function FindingFix({ findingId, chosen, setChosen, setExpanded }: {
  findingId: string;
  chosen: { fid: string; opt: string } | null;
  setChosen: (c: { fid: string; opt: string } | null) => void;
  setExpanded: (s: string) => void;
}) {
  const plan = useQuery({ queryKey: ["rem", findingId], queryFn: () => getRemediation(findingId) });
  const det = useQuery({ queryKey: ["finding", findingId], queryFn: () => getFinding(findingId) });

  if (plan.isLoading || det.isLoading) return <Loader label="Loading suggested fixes…" />;
  if (plan.isError || det.isError) return <ErrorState message="Suggested fixes unavailable." onRetry={() => { plan.refetch(); det.refetch(); }} />;
  const opts = buildOptions((plan.data ?? {}) as Record<string, unknown>, (det.data ?? {}) as unknown as Record<string, unknown>);
  if (!opts.length) return <Empty label="No fix options returned for this finding." />;

  return (
    <div>
      <p className="mb-2 text-xs text-ink3">Suggested fixes — pick the best fit for this environment</p>
      <div className="grid gap-2 md:grid-cols-3">
        {opts.map((o, i) => {
          const active = chosen?.fid === findingId && chosen?.opt === o.id;
          return (
            <div key={o.id} className={`rounded-lg border p-3 ${active ? "border-primary bg-primarylight" : "border-line bg-surface"}`}>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-ink3">Option {i + 1} · {o.tag}</p>
              <p className="mt-0.5 text-sm font-semibold text-ink">{o.title}</p>
              <ol className="mt-2 space-y-1">
                {o.lines.slice(0, 4).map((l, j) => (
                  <li key={j} className="rounded bg-surface2 px-2 py-1 font-mono text-[11px] text-ink2">{l}</li>
                ))}
                {o.lines.length > 4 && <li className="text-[11px] text-ink3">+{o.lines.length - 4} more steps</li>}
              </ol>
              <button
                onClick={() => { setChosen({ fid: findingId, opt: o.id }); setExpanded(findingId); }}
                className={`mt-2.5 w-full rounded-lg px-3 py-1.5 text-xs font-semibold ${active ? "bg-primary text-onprimary" : "border border-primary/40 bg-surface text-primary hover:bg-primarylight"}`}
              >
                {active ? "Selected ✓" : "Use this fix"}
              </button>
            </div>
          );
        })}
      </div>
      {(plan.data as Record<string, unknown> | undefined)?.rollback_available != null && (
        <p className="mt-2 text-[11px] text-ink3">
          Rollback: {String((plan.data as Record<string, unknown>).rollback_available) === "true" || (plan.data as Record<string, unknown>).rollback_available === true ? "available" : "not available"} · Vendor: {String((plan.data as Record<string, unknown>).vendor ?? "—")}
        </p>
      )}
    </div>
  );
}

function ApplyPanel({ findingId, optionId }: { findingId: string; optionId: string }) {
  const [approvedBy, setApprovedBy] = useState("admin");
  const [approvalId, setApprovalId] = useState("");
  const [newCfg, setNewCfg] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const ap = useMutation({
    mutationFn: () => approveRemediation(findingId, { approved_by: approvedBy, comment: `Reviewed in UI — chose option: ${optionId}` }),
    onSuccess: (r) => { setErr(""); setApprovalId((r as { id?: string }).id ?? ""); setMsg("Choice recorded — dry-run apply is now available."); },
    onError: (e) => { setMsg(""); setErr(toMessage(e)); },
  });
  const dry = useMutation({
    mutationFn: () => applyRemediation(findingId, { id: approvalId, updated_config_text: newCfg || "hostname Core-Router-01\nip ssh version 2\n" }),
    onSuccess: (r) => { setErr(""); setMsg(`Simulation complete. device_touched=${String((r as Record<string, unknown>).device_touched)} · verified_fixed=${String((r as Record<string, unknown>).verified_fixed ?? "—")}${(r as Record<string, unknown>).re_audit_id ? ` · re-audit ${(r as Record<string, unknown>).re_audit_id}` : ""}`); },
    onError: (e) => { setMsg(""); setErr(toMessage(e)); },
  });

  return (
    <Card title="Apply chosen fix" sub={`Finding ${findingId} · option "${optionId}" · simulation only — no device is touched`}>
      <div className="grid gap-2 md:grid-cols-2">
        <Field label="Approved by"><input className={inputCls} value={approvedBy} onChange={(e) => setApprovedBy(e.target.value)} /></Field>
        <Field label="Approval ID (from approve step)"><input className={inputCls} value={approvalId} onChange={(e) => setApprovalId(e.target.value)} placeholder="approve first" /></Field>
      </div>
      <Field label="Updated config text (for simulated re-audit)">
        <textarea className={`${inputCls} mt-1 h-24 font-mono`} value={newCfg} onChange={(e) => setNewCfg(e.target.value)} placeholder="Paste candidate fixed configuration…" />
      </Field>
      <div className="mt-3 flex gap-2">
        <button className={btnGhost} disabled={ap.isPending} onClick={() => ap.mutate()}>{ap.isPending ? "Recording…" : "Approve choice"}</button>
        <button className={btnPrimary} disabled={!approvalId || dry.isPending} onClick={() => dry.mutate()}>{dry.isPending ? "Simulating…" : "Apply (Dry Run)"}</button>
      </div>
      {msg && <p className="mt-3 rounded-lg border border-ok/30 bg-okbg p-2.5 text-xs text-ok">{msg}</p>}
      {err && <p className="mt-3 rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}
    </Card>
  );
}
