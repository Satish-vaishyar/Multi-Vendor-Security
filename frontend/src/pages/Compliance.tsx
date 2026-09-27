import { Fragment, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { ChevronDown, ChevronUp } from "lucide-react";
import { getComplianceControls, getComplianceFramework, getComplianceOverall, getFrameworks } from "../api/compliance.api";
import { FRAMEWORK_LABELS } from "../constants";
import { fmtScore, useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Badge, Card, Empty, ErrorState, Loader, PageHeader, inputCls } from "../components/common";

type Ctrl = Record<string, unknown>;

function str(v: unknown, fb = "—"): string {
  if (v === null || v === undefined || v === "") return fb;
  return typeof v === "string" ? v : JSON.stringify(v);
}

/** Presentation labels: UNKNOWN renders as GAP, NOT_APPLICABLE as N/A. */
function displayStatus(s: unknown): string {
  const u = String(s ?? "").toUpperCase();
  if (u === "UNKNOWN") return "GAP";
  if (u === "NOT_APPLICABLE") return "N/A";
  return str(s, "—");
}

/** Backend now ships normalised display fields (evidence_display / why_explanation /
 *  fix / impact_statement). The parsers below only cover legacy cached payloads. */
function evidenceParts(c: Ctrl): { property: string; observed: string; expected: string; operator: string; missing: boolean } {
  const ed = (c.evidence_display ?? {}) as Record<string, unknown>;
  if (ed.property !== undefined || ed.observed !== undefined) {
    return {
      property: str(ed.property, "—"),
      observed: str(ed.observed, "Not found in configuration"),
      expected: str(ed.expected, "—"),
      operator: str(ed.operator, "EQUALS"),
      missing: Boolean(ed.missing),
    };
  }
  const e = ((c.evidence ?? {}) as Record<string, unknown>);
  const noObservedValue = e.observed_value === null || e.observed_value === undefined || e.observed_value === "";
  const noObserved = e.observed === null || e.observed === undefined || e.observed === "";
  const missing = noObservedValue && noObserved;
  return {
    property: str(e.property ?? e.property_id ?? e.control_id ?? "", "—"),
    observed: str(e.observed_value ?? e.observed ?? "Not found in configuration"),
    expected: str(e.expected_value ?? e.expected ?? "—"),
    operator: str(e.operator ?? "EQUALS"),
    missing,
  };
}

function fixParts(c: Ctrl): { commands: string[]; validation: string[]; rollback: string[]; title: string } {
  const fx = (c.fix ?? {}) as Record<string, unknown>;
  const pick = (v: unknown): string[] =>
    Array.isArray(v) ? v.map((x) => String(typeof x === "string" ? x : JSON.stringify(x))) : [];
  if (fx.commands !== undefined || fx.title !== undefined) {
    return { commands: pick(fx.commands), validation: pick(fx.validation), rollback: pick(fx.rollback), title: str(fx.title, "") };
  }
  const r = ((c.remediation ?? {}) as Record<string, unknown>);
  const d = ((r.detail ?? r) as Record<string, unknown>);
  return {
    commands: pick(d.commands ?? r.commands),
    validation: pick(d.validation ?? r.validation),
    rollback: pick(d.rollback ?? r.rollback),
    title: str(d.title ?? r.title ?? "", ""),
  };
}

export default function Compliance() {
  const [sp, setSp] = useSearchParams();
  const [selected, select] = useSelectedAudit();
  const id = selected;
  const [fw, setFw] = useState(sp.get("fw") ?? "NIST");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("ATTENTION");
  const [expanded, setExpanded] = useState<string>("");
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

  const od = ((overall.data ?? {}) as Record<string, unknown>);
  // Backend returns {score:{...}, by_framework:{FW:{...}}} — never render raw envelope keys.
  const byFw = ((od.by_framework ?? od.frameworks ?? {}) as Record<string, { score?: number; compliance_score?: number }>);
  const overallScore = ((od.score ?? {}) as { compliance_score?: number }).compliance_score;
  const items = ((controls.data as { items?: Ctrl[] } | undefined)?.items ?? []) as Ctrl[];
  // Default view hides passing controls — only failed + gaps need attention.
  const filtered = items.filter((c) => {
    const hay = `${c.control_id ?? ""} ${c.title ?? ""}`.toLowerCase();
    if (q && !hay.includes(q.toLowerCase())) return false;
    const s = String(c.status ?? "").toUpperCase();
    if (status === "ATTENTION" && (s === "PASS" || s === "NOT_APPLICABLE")) return false;
    else if (status === "FAIL" && s !== "FAIL") return false;
    else if (status === "GAP" && s !== "UNKNOWN") return false;
    else if (status === "PASS" && s !== "PASS") return false;
    else if (status === "NA" && s !== "NOT_APPLICABLE") return false;
    return true;
  });
  const nPass = items.filter((c) => String(c.status ?? "").toUpperCase() === "PASS").length;
  const nFail = items.filter((c) => String(c.status ?? "").toUpperCase() === "FAIL").length;
  const nNa = items.filter((c) => String(c.status ?? "").toUpperCase() === "NOT_APPLICABLE").length;
  const nGap = items.length - nPass - nFail - nNa;
  const frameworks: string[] = Array.isArray((fwList.data as unknown as { frameworks?: { id?: string }[] })?.frameworks)
    ? ((fwList.data as unknown as { frameworks: { id: string }[] }).frameworks.map((f) => f.id))
    : ["CIS", "NIST", "STIG", "ISO27001"];

  const toggle = (key: string) => setExpanded((e) => (e === key ? "" : key));

  return (
    <div>
      <PageHeader title="Compliance" sub="Multi-framework control results — click any finding for why it was raised, the issue, the fix and the risk of ignoring it" />
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
                <div className="rounded-lg bg-surface2 p-3">
                  <p className="text-xs font-medium text-ink2">Overall</p>
                  <p className="mt-0.5 text-lg font-semibold text-ink">{Number(overallScore ?? 0).toFixed(0)}%</p>
                  <div className="mt-2 h-2 overflow-hidden rounded-full bg-line/60">
                    <div className="h-full rounded-full bg-primary" style={{ width: `${Math.min(100, Number(overallScore ?? 0))}%` }} />
                  </div>
                </div>
                {Object.entries(byFw).slice(0, 7).map(([k, v]) => {
                  const sc = Number(v?.score ?? v?.compliance_score ?? 0);
                  return (
                    <div key={k} className="rounded-lg bg-surface2 p-3">
                      <p className="text-xs font-medium text-ink2">{FRAMEWORK_LABELS[k] ?? k}</p>
                      <p className="mt-0.5 text-lg font-semibold text-ink">{sc.toFixed(0)}%</p>
                      <div className="mt-2 h-2 overflow-hidden rounded-full bg-line/60">
                        <div className="h-full rounded-full bg-primary" style={{ width: `${Math.min(100, sc)}%` }} />
                      </div>
                    </div>
                  );
                })}
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
                  <option value="ATTENTION">Needs attention (failed + gaps)</option>
                  <option value="FAIL">Failed</option>
                  <option value="GAP">Gap</option>
                  <option value="PASS">Passed</option>
                  <option value="NA">Not applicable</option>
                  <option value="">All</option>
                </select>
              </div>
              {!filtered.length ? <Empty label="No controls match." /> : (
                <>
                <p className="mb-2 text-xs text-ink3">
                  {filtered.length} of {items.length} controls · {nFail} failed · {nGap} gaps · {nPass} passing{nNa > 0 && ` · ${nNa} not applicable`}
                  {status === "ATTENTION" && (nPass > 0 || nNa > 0) && " (passing + N/A hidden)"}
                </p>
                <div className="mb-3 rounded-lg border border-line bg-surface2 p-2.5 text-[11px] leading-relaxed text-ink2">
                  Every control in the selected frameworks is evaluated against this device (SCAP model) — nothing is skipped silently.{" "}
                  <span className="font-semibold text-ink">FAIL</span> = violation found in your config ·{" "}
                  <span className="font-semibold text-ink">GAP</span> = applies to this device but no evidence was found — either absent or written in syntax the parser does not recognise yet. Not a confirmed failure: verify first, then fix or submit it under Training ·{" "}
                  <span className="font-semibold text-ink">N/A</span> = control cannot apply to this device's platform — skipped and excluded from the score ·{" "}
                  <span className="font-semibold text-ink">PASS</span> = verified compliant, hidden by default (choose Passed or All to show).
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead><tr className="border-b border-line text-xs uppercase text-ink3">
                      <th className="py-2 pr-3 font-medium">Control</th><th className="py-2 pr-3 font-medium">Description</th>
                      <th className="py-2 pr-3 font-medium">Status</th><th className="py-2 pr-3 font-medium">Severity</th>
                      <th className="py-2 pr-3 font-medium"><span className="sr-only">Expand</span></th>
                    </tr></thead>
                    <tbody>
                      {filtered.map((c, i) => {
                        const key = String(c.finding_id ?? c.control_id ?? i);
                        const open = expanded === key;
                        return (
                          <Fragment key={key}>
                            <tr
                              onClick={() => toggle(key)}
                              className={`cursor-pointer border-b border-line/60 hover:bg-surface2 ${open ? "bg-surface2" : ""}`}
                              title="Click for details: the issue, the evidence, the fix and the risk"
                            >
                              <td className="py-2 pr-3 font-mono text-primary">{String(c.control_id ?? "—")}</td>
                              <td className="py-2 pr-3 text-ink2 underline decoration-dotted underline-offset-2">{String(c.title ?? c.description ?? "—")}</td>
                              <td className="py-2 pr-3"><Badge value={displayStatus(c.status)} /></td>
                              <td className="py-2 pr-3"><Badge value={String(c.severity ?? "—")} kind="sev" /></td>
                              <td className="py-2 pr-3 text-ink3">{open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}</td>
                            </tr>
                            {open && (
                              <tr className="border-b border-line/60 bg-surface2/60">
                                <td colSpan={5} className="px-2 py-3">
                                  <FindingExplain c={c} />
                                </td>
                              </tr>
                            )}
                          </Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                </>
              )}
            </>
          )}
        </Card>
      )}
    </div>
  );
}

/** Expanded explanation: what / why / fix / if-not-fixed + deep links. */
function FindingExplain({ c }: { c: Ctrl }) {
  const ev = evidenceParts(c);
  const fix = fixParts(c);
  const findingId = c.finding_id ? String(c.finding_id) : "";
  const frameworks = (c.frameworks ?? {}) as Record<string, unknown>;
  const fwList = Object.entries(frameworks).filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `${k}:${Array.isArray(v) ? (v as unknown[]).map(String).join("+") : String(v)}`);
  const refs = Array.isArray(c.references) ? (c.references as unknown[]).map(String) : [];
  const why = str(c.why_explanation, "");
  const impact = str(c.impact_statement, "");
  const statusU = String(c.status ?? "").toUpperCase();
  const isPass = statusU === "PASS";
  const isNa = statusU === "NOT_APPLICABLE";
  const isUnknown = !isNa && (statusU === "UNKNOWN" || ev.missing);
  const isOk = isPass || isNa;

  return (
    <div className="grid gap-2 md:grid-cols-2">
      <div className="rounded-lg border border-line bg-surface p-3">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-ink3">What is the issue?</p>
        <p className="mt-1 text-sm font-semibold text-ink">{str(c.title, "Untitled control")}</p>
        <p className="mt-1 text-xs leading-relaxed text-ink2">{str(c.description, str(c.title, "See control title."))}</p>
        {(fwList.length > 0 || refs.length > 0) && (
          <p className="mt-2 text-[11px] text-ink3">
            {fwList.length > 0 && <>Maps to {fwList.join(" · ")} </>}
            {refs.length > 0 && <>· Refs: {refs.join(", ")}</>}
          </p>
        )}
      </div>
      <div className="rounded-lg border border-line bg-surface p-3">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-ink3">{isOk ? "Why is this shown?" : "Why was this flagged?"}</p>
        {isPass && <p className="mt-1 inline-block rounded-md border border-ok/30 bg-okbg px-2 py-0.5 text-[11px] font-semibold text-ok">Compliant — observed matches expected, nothing to fix</p>}
        {isNa && <p className="mt-1 inline-block rounded-md border border-line bg-surface2 px-2 py-0.5 text-[11px] font-semibold text-ink2">Not applicable to this device — skipped before evaluation, not scored</p>}
        {isUnknown && <p className="mt-1 inline-block rounded-md border border-warn/30 bg-warnbg px-2 py-0.5 text-[11px] font-semibold text-warn">No evidence in this configuration — unverifiable, not a confirmed failure</p>}
        {why ? <p className="mt-1 text-xs leading-relaxed text-ink2">{why}</p> : null}
        <dl className="mt-2 space-y-1 text-xs">
          {[["Observed", ev.observed], ["Expected", ev.expected], ["Property", ev.property], ["Result", displayStatus(c.status)]].map(([k, v]) => (
            <div key={k} className="flex justify-between gap-3 rounded bg-surface2 px-2 py-1">
              <dt className="text-ink3">{k}</dt><dd className="break-all font-mono text-ink">{v}</dd>
            </div>
          ))}
        </dl>
      </div>
      <div className="rounded-lg border border-line bg-surface p-3">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-ink3">How to fix it</p>
        {isOk ? (
          <>
            <p className="mt-1 text-xs leading-relaxed text-ink2">{isNa ? "No action needed — this control cannot apply to this device's platform." : "Already compliant — no changes needed."}</p>
            {!isNa && fix.validation.length > 0 && <p className="mt-2 text-[11px] text-ink3">Confirm: <span className="font-mono">{fix.validation.join(" · ")}</span></p>}
          </>
        ) : (
          <>
            {isUnknown && (
              <p className="mt-1 text-[11px] leading-relaxed text-ink3">
                First check whether the setting already exists under different syntax. If it does, submit it under{" "}
                <Link to="/training" className="font-semibold text-primary hover:underline">Training</Link>{" "}
                so the parser learns it; otherwise apply the steps below.
              </p>
            )}
            {fix.title && <p className="mt-1 text-xs font-semibold text-ink">{fix.title}</p>}
            {fix.commands.length ? (
              <ol className="mt-2 space-y-1">
                {fix.commands.map((l, j) => (
                  <li key={j} className="rounded bg-surface2 px-2 py-1 font-mono text-[11px] text-ink2">{j + 1}. {l}</li>
                ))}
              </ol>
            ) : null}
            {fix.validation.length > 0 && <p className="mt-2 text-[11px] text-ink3">Verify: <span className="font-mono">{fix.validation.join(" · ")}</span></p>}
            {fix.rollback.length > 0 && <p className="mt-1 text-[11px] text-ink3">Rollback: <span className="font-mono">{fix.rollback.join(" · ")}</span></p>}
          </>
        )}
      </div>
      <div className={`rounded-lg border p-3 ${isOk ? "border-ok/30 bg-okbg" : "border-danger/30 bg-dangerbg"}`}>
        <p className={`text-[11px] font-semibold uppercase tracking-wider ${isOk ? "text-ok" : "text-danger"}`}>{isOk ? "Status" : isUnknown ? "If this is actually missing" : "If you do not fix it"}</p>
        {impact ? <p className="mt-1 text-xs leading-relaxed text-ink2">{impact}</p> : null}
        <div className="mt-2.5 flex flex-wrap gap-2">
          {findingId && <Link to={`/findings/${findingId}`} className="rounded-lg border border-primary/40 bg-surface px-3 py-1.5 text-xs font-semibold text-primary hover:bg-primarylight">Full finding detail →</Link>}
          {findingId && !isOk && <Link to={`/remediation/${findingId}`} className="rounded-lg bg-primary px-3 py-1.5 text-xs font-semibold text-onprimary hover:bg-primaryhover">Fix this now →</Link>}
        </div>
      </div>
    </div>
  );
}
