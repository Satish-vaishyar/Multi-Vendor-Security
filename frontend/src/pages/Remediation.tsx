import { useEffect, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { Check, ChevronDown, ChevronUp, Copy, ShieldAlert } from "lucide-react";
import {
  approveRemediation,
  applyRemediation,
  getRemediation,
  getRemediationHistory,
} from "../api/remediation.api";
import type { RemediationPlan } from "../api/remediation.api";
import { getFinding, listFindings } from "../api/findings.api";
import { toMessage } from "../api/client";
import { useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import {
  Badge,
  Card,
  Empty,
  ErrorState,
  Field,
  Loader,
  PageHeader,
  btnGhost,
  btnPrimary,
  inputCls,
} from "../components/common";

interface FixOption {
  id: string;
  title: string;
  tag: string;
  lines: string[];
}

const SOURCE_LABEL: Record<string, string> = {
  "okf-vendor": "OKF vendor procedure",
  "cve-advisory": "CVE advisory",
  "pqc-migration": "PQC migration guidance",
  "security-analytics": "Security analytics",
  generic: "Framework guidance",
};

function buildOptions(plan: RemediationPlan | Record<string, unknown>): FixOption[] {
  const p = plan as RemediationPlan;
  const opts: FixOption[] = [];
  const steps = (p.steps ?? []) as { order?: number; command?: string }[];
  if (steps.length) {
    opts.push({
      id: "vendor",
      title: p.fix_title || "Vendor recommended procedure",
      tag: SOURCE_LABEL[p.source] ?? "Recommended fix",
      lines: steps.map((s) => String(s.command ?? "")),
    });
  }
  const validation = (p.validation ?? []) as unknown[];
  if (validation.length) {
    opts.push({
      id: "validate",
      title: "Validate & re-audit",
      tag: "Verification",
      lines: validation.map(String),
    });
  }
  const rollback = (p.rollback ?? []) as unknown[];
  if (rollback.length) {
    opts.push({
      id: "rollback",
      title: "Rollback plan",
      tag: "Safety net",
      lines: rollback.map(String),
    });
  }
  return opts.slice(0, 3);
}

function riskScore(plan: RemediationPlan): string {
  const r = (plan.risk ?? {}) as Record<string, unknown>;
  const s = r.risk_score;
  return s === undefined || s === null ? "—" : String(s);
}

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      title="Copy command"
      className="rounded p-1 text-ink3 hover:bg-surface2 hover:text-ink"
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(
          () => {
            setDone(true);
            setTimeout(() => setDone(false), 1200);
          },
          () => undefined,
        );
      }}
    >
      {done ? <Check size={13} /> : <Copy size={13} />}
    </button>
  );
}

export default function Remediation() {
  const { findingId: paramId = "" } = useParams();
  const [auditId, selectAudit] = useSelectedAudit();
  const audits = useAuditOverviews();
  const [expanded, setExpanded] = useState(paramId);
  const [chosen, setChosen] = useState<{ fid: string; opt: string } | null>(
    paramId ? { fid: paramId, opt: "vendor" } : null,
  );
  const [manual, setManual] = useState("");

  // Keep state in sync when navigating directly between finding URLs.
  useEffect(() => {
    setExpanded(paramId);
    setChosen(paramId ? { fid: paramId, opt: "vendor" } : null);
  }, [paramId]);

  const auditFindings = useQuery({
    queryKey: ["findings", { audit: auditId }],
    queryFn: () => listFindings({ audit_id: auditId }),
    enabled: !!auditId,
  });

  const loadManual = () => {
    const id = manual.trim();
    if (!id) return;
    setExpanded(id);
    setChosen({ fid: id, opt: "vendor" });
  };

  return (
    <div>
      <PageHeader
        title="Remediation"
        sub="Review the vendor fix, record human approval, then dry-run apply — simulation only, no device is ever touched"
      />
      {!paramId && (
        <div className="mb-4">
          <AuditPicker
            overviews={audits.overviews}
            isLoading={audits.isLoading}
            isError={audits.isError}
            onRetry={audits.refetch}
            value={auditId}
            onSelect={selectAudit}
            renderBrief={(a) => <>{a.total} findings with suggested fixes</>}
          />
        </div>
      )}
      <div className="mb-4">
        <Card
          title={paramId ? `Finding ${paramId}` : auditId ? `Findings in ${auditId}` : "Findings"}
          sub={paramId ? "Fix plan for the linked finding" : "Expand a finding to see its fix plan"}
          right={
            !paramId ? (
              <span className="flex gap-2">
                <input
                  className={`${inputCls} w-44`}
                  placeholder="…or finding ID"
                  value={manual}
                  onChange={(e) => setManual(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") loadManual();
                  }}
                />
                <button
                  className="rounded-lg bg-primary px-3 py-2 text-xs font-semibold text-onprimary hover:bg-primaryhover"
                  onClick={loadManual}
                >
                  Load
                </button>
              </span>
            ) : undefined
          }
        >
          {paramId ? (
            <FindingFix findingId={paramId} chosen={chosen} setChosen={setChosen} setExpanded={setExpanded} />
          ) : !auditId ? (
            <Empty label="Select an audit above to list its findings, or paste a finding ID." />
          ) : auditFindings.isLoading ? (
            <Loader label="Loading findings…" />
          ) : auditFindings.isError ? (
            <ErrorState message="Unable to load findings." onRetry={() => auditFindings.refetch()} />
          ) : !(auditFindings.data?.items?.length) ? (
            <Empty label="No findings in this audit." />
          ) : (
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
                      {expanded === x.finding_id ? (
                        <ChevronUp size={14} className="text-ink3" />
                      ) : (
                        <ChevronDown size={14} className="text-ink3" />
                      )}
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

function FindingFix({
  findingId,
  chosen,
  setChosen,
  setExpanded,
}: {
  findingId: string;
  chosen: { fid: string; opt: string } | null;
  setChosen: (c: { fid: string; opt: string } | null) => void;
  setExpanded: Dispatch<SetStateAction<string>>;
}) {
  const plan = useQuery({ queryKey: ["rem", findingId], queryFn: () => getRemediation(findingId) });
  const det = useQuery({ queryKey: ["finding", findingId], queryFn: () => getFinding(findingId) });
  const hist = useQuery({
    queryKey: ["rem-history", findingId],
    queryFn: () => getRemediationHistory(findingId),
    enabled: plan.isSuccess,
  });

  if (plan.isLoading || det.isLoading) return <Loader label="Loading fix plan…" />;
  if (plan.isError || det.isError) {
    const msg =
      plan.isError ? toMessage(plan.error) : det.isError ? toMessage(det.error) : "Fix plan unavailable.";
    return <ErrorState message={msg} onRetry={() => { void plan.refetch(); void det.refetch(); }} />;
  }
  const p = (plan.data ?? {}) as RemediationPlan;
  const f = (det.data ?? {}) as unknown as Record<string, unknown>;
  const opts = buildOptions(p);
  if (!opts.length && !(p.steps ?? []).length) return <Empty label="No fix available for this finding yet." />;

  return (
    <div>
      {/* Finding context header */}
      <div className="mb-3 rounded-lg border border-line bg-surface p-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge value={String(p.severity ?? f.severity ?? "?")} kind="sev" />
          <Badge value={String(p.engine ?? (f.engine as string) ?? "")} />
          {p.control_id && <span className="font-mono text-[11px] text-ink3">{p.control_id}</span>}
          <span className="ml-auto text-[11px] text-ink3">
            Risk <span className="font-semibold text-ink">{riskScore(p)}</span>
            {p.vendor && p.vendor !== "unknown" && (
              <> · {p.vendor.toUpperCase()}{p.platform ? ` ${p.platform}` : ""}{p.vendor_version ? ` ${p.vendor_version}` : ""}</>
            )}
          </span>
        </div>
        <p className="mt-1.5 text-sm font-semibold text-ink">{p.fix_title || String(f.title ?? findingId)}</p>
        {p.source && (
          <p className="mt-0.5 text-[11px] text-ink3">
            Source: {SOURCE_LABEL[p.source] ?? p.source}
            {p.approval_required && (
              <span className="ml-2 inline-flex items-center gap-1 font-semibold text-warning">
                <ShieldAlert size={12} /> human approval required
              </span>
            )}
          </p>
        )}
      </div>

      <p className="mb-2 text-xs text-ink3">Fix steps — review, then approve below</p>
      <ol className="space-y-1.5">
        {(p.steps ?? []).map((s) => (
          <li
            key={s.order}
            className="flex items-center gap-2 rounded-lg border border-line bg-surface px-2.5 py-2"
          >
            <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primarylight text-[11px] font-bold text-primary">
              {s.order}
            </span>
            <code className="flex-1 font-mono text-xs text-ink">{s.command}</code>
            <CopyBtn text={s.command} />
          </li>
        ))}
      </ol>

      {!!(p.validation ?? []).length && (
        <div className="mt-3">
          <p className="mb-1.5 text-xs font-semibold text-ink">Validate after applying</p>
          <ul className="space-y-1">
            {(p.validation ?? []).map((v, i) => (
              <li key={i} className="flex items-center gap-2 rounded bg-surface2 px-2.5 py-1.5 font-mono text-[11px] text-ink2">
                <Check size={12} className="shrink-0 text-ok" /> <span className="flex-1">{String(v)}</span>
                <CopyBtn text={String(v)} />
              </li>
            ))}
          </ul>
        </div>
      )}

      {!!((p as unknown as { references?: unknown[] }).references ?? []).length && (
        <div className="mt-3">
          <p className="mb-1.5 text-xs font-semibold text-ink">Advisory references</p>
          <ul className="space-y-1">
            {((p as unknown as { references?: unknown[] }).references ?? []).slice(0, 5).map((u, i) => (
              <li key={i} className="truncate font-mono text-[11px]">
                <a href={String(u)} target="_blank" rel="noreferrer" className="text-primary hover:underline">{String(u)}</a>
              </li>
            ))}
          </ul>
        </div>
      )}

      <p className="mt-2.5 text-[11px] text-ink3">
        Rollback: {p.rollback_available ? `available (${(p.rollback ?? []).length} step${(p.rollback ?? []).length === 1 ? "" : "s"} — see plan)` : "not available for this fix"}
        {p.rollback_available && (p.rollback ?? []).length > 0 && (
          <span className="ml-1 font-mono">{(p.rollback ?? []).slice(0, 2).map(String).join(" · ")}</span>
        )}
      </p>

      {opts.length > 1 && (
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          {opts.filter((o) => o.id !== "vendor").map((o) => {
            const active = chosen?.fid === findingId && chosen?.opt === o.id;
            return (
              <div key={o.id} className={`rounded-lg border p-3 ${active ? "border-primary bg-primarylight" : "border-line bg-surface"}`}>
                <p className="text-[11px] font-semibold uppercase tracking-wider text-ink3">{o.tag}</p>
                <p className="mt-0.5 text-sm font-semibold text-ink">{o.title}</p>
                <ul className="mt-2 space-y-1">
                  {o.lines.slice(0, 4).map((l, j) => (
                    <li key={j} className="rounded bg-surface2 px-2 py-1 font-mono text-[11px] text-ink2">{l}</li>
                  ))}
                </ul>
                <button
                  onClick={() => { setChosen({ fid: findingId, opt: o.id }); setExpanded(findingId); }}
                  className={`mt-2.5 w-full rounded-lg px-3 py-1.5 text-xs font-semibold ${active ? "bg-primary text-onprimary" : "border border-primary/40 bg-surface text-primary hover:bg-primarylight"}`}
                >
                  {active ? "Selected ✓" : "Use this view"}
                </button>
              </div>
            );
          })}
        </div>
      )}

      {hist.data && hist.data.total > 0 && (
        <div className="mt-3 rounded-lg border border-line p-2.5">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-ink3">
            Approval history ({hist.data.total})
          </p>
          <ul className="mt-1.5 space-y-1">
            {hist.data.items.slice(0, 5).map((h) => (
              <li key={h.id} className="flex flex-wrap items-center gap-2 text-[11px] text-ink2">
                <Badge value={h.status} />
                <span className="font-mono">{h.id}</span>
                <span>by {h.approved_by}</span>
                {h.comment && <span className="truncate text-ink3">“{h.comment}”</span>}
              </li>
            ))}
          </ul>
        </div>
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
  const [result, setResult] = useState<Record<string, unknown> | null>(null);

  // A new finding means a new workflow — reset stale approval state.
  useEffect(() => {
    setApprovalId("");
    setMsg("");
    setErr("");
    setResult(null);
  }, [findingId]);

  const ap = useMutation({
    mutationFn: () =>
      approveRemediation(findingId, { approved_by: approvedBy.trim() || "admin", comment: `Reviewed in UI — chose option: ${optionId}` }),
    onSuccess: (r) => {
      setErr("");
      setResult(null);
      setApprovalId((r as { id?: string }).id ?? "");
      setMsg("Choice recorded — dry-run apply is now available.");
    },
    onError: (e) => { setMsg(""); setResult(null); setErr(toMessage(e)); },
  });
  const dry = useMutation({
    mutationFn: () => applyRemediation(findingId, { id: approvalId, updated_config_text: newCfg }),
    onSuccess: (r) => {
      setErr("");
      const rec = r as Record<string, unknown>;
      setResult(rec);
      const verified = String(rec.verified_fixed) === "true";
      setMsg(
        `Simulation complete — no device touched. Verified fixed: ${verified ? "YES ✓" : "NO"}` +
        (rec.re_audit_status ? ` · re-audit: ${String(rec.re_audit_status)}` : "") +
        (rec.resolved !== undefined ? ` · findings resolved: ${String(rec.resolved)} (${String(rec.fail_before ?? "?")} → ${String(rec.fail_after ?? "?")})` : ""),
      );
    },
    onError: (e) => { setMsg(""); setResult(null); setErr(toMessage(e)); },
  });

  return (
    <Card title="Apply chosen fix" sub={`Finding ${findingId} · option "${optionId}" · simulation only — no device is touched`}>
      <ol className="mb-3 flex flex-wrap gap-2 text-[11px]">
        <li className="rounded-full bg-surface2 px-2.5 py-1 text-ink2"><span className="font-bold text-primary">1</span> Review plan above</li>
        <li className={`rounded-full px-2.5 py-1 ${approvalId ? "bg-okbg text-ok" : "bg-surface2 text-ink2"}`}>
          <span className="font-bold">2</span> {approvalId ? "Approved ✓" : "Approve choice"}
        </li>
        <li className="rounded-full bg-surface2 px-2.5 py-1 text-ink2"><span className="font-bold text-primary">3</span> Dry-run with fixed config</li>
      </ol>
      <div className="grid gap-2 md:grid-cols-2">
        <Field label="Approved by">
          <input className={inputCls} value={approvedBy} onChange={(e) => setApprovedBy(e.target.value)} placeholder="reviewer id" />
        </Field>
        <Field label="Approval ID (auto-filled after approve)">
          <input className={inputCls} value={approvalId} onChange={(e) => setApprovalId(e.target.value)} placeholder="approve first" />
        </Field>
      </div>
      <Field label="Fixed config text (required for verification re-audit)">
        <textarea
          className={`${inputCls} mt-1 h-28 font-mono`}
          value={newCfg}
          onChange={(e) => setNewCfg(e.target.value)}
          placeholder="Paste the candidate fixed configuration — it is re-audited in simulation to prove the fix…"
        />
      </Field>
      <div className="mt-3 flex flex-wrap gap-2">
        <button className={btnGhost} disabled={ap.isPending} onClick={() => ap.mutate()}>
          {ap.isPending ? "Recording…" : approvalId ? "Re-approve choice" : "Approve choice"}
        </button>
        <button
          className={btnPrimary}
          disabled={!approvalId || !newCfg.trim() || dry.isPending}
          title={!approvalId ? "Approve first" : !newCfg.trim() ? "Paste the fixed config to verify" : "Run simulated apply"}
          onClick={() => dry.mutate()}
        >
          {dry.isPending ? "Simulating…" : "Apply (Dry Run)"}
        </button>
      </div>
      {msg && <p className="mt-3 rounded-lg border border-ok/30 bg-okbg p-2.5 text-xs text-ok">{msg}</p>}
      {err && <p className="mt-3 rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}
      {result && (
        <div className="mt-3 grid gap-2 rounded-lg border border-line bg-surface p-3 text-xs md:grid-cols-4">
          <div><p className="text-[10px] uppercase tracking-wider text-ink3">Device touched</p><p className="font-semibold text-ink">{String(result.device_touched)}</p></div>
          <div><p className="text-[10px] uppercase tracking-wider text-ink3">Re-audit</p><p className="font-semibold text-ink">{String(result.re_audit_status ?? "—")}</p></div>
          <div><p className="text-[10px] uppercase tracking-wider text-ink3">Verified fixed</p><p className={`font-semibold ${String(result.verified_fixed) === "true" ? "text-ok" : "text-warning"}`}>{String(result.verified_fixed ?? "—")}</p></div>
          <div><p className="text-[10px] uppercase tracking-wider text-ink3">Findings</p><p className="font-semibold text-ink">{result.fail_before !== undefined ? `${String(result.fail_before)} → ${String(result.fail_after)}` : "—"}</p></div>
        </div>
      )}
    </Card>
  );
}
