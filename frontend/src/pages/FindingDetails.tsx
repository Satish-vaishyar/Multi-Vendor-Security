import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getFinding } from "../api/findings.api";
import { getRemediation } from "../api/remediation.api";
import { getVulnDetail } from "../api/vulnerabilities.api";
import { Badge, Card, ErrorState, Loader, PageHeader, btnGhost, btnPrimary } from "../components/common";

type Rec = Record<string, unknown>;

function fmt(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

function riskScore(risk: Rec): string {
  const s = risk.risk_score ?? risk.score ?? risk.rule_score;
  return s === undefined || s === null || s === "" ? "—" : String(s);
}

/** Normalize advisory references: strings or {url} objects → deduped URL list. */
function refsOf(...sources: unknown[]): string[] {
  const out: string[] = [];
  for (const s of sources) {
    const arr = Array.isArray(s) ? s : [];
    for (const r of arr) {
      const u = typeof r === "string" ? r : String((r as Rec).url ?? "");
      if (u && !out.includes(u)) out.push(u);
    }
  }
  return out;
}

function isCve(d: Rec): boolean {
  const e = String(d.engine ?? d.type ?? "").toLowerCase();
  return e.includes("cve") || e.includes("vuln");
}

/** Plain-language summary so a network engineer knows what failed and why. */
function buildSummary(d: Rec, ev: Rec, vuln: Rec | undefined, refs: string[]): string {
  const engine = String(d.engine ?? d.type ?? "").toLowerCase();
  const status = String(d.status ?? "");
  const title = String(d.title ?? "");
  const property = String(ev.property ?? ev.control_id ?? d.control_id ?? "");
  const observed = ev.observed_value ?? ev.observed ?? (ev.detail as Rec | undefined)?.observed;
  const expected = ev.expected_value ?? ev.expected;
  const operator = String(ev.operator ?? "");
  const control = String(ev.control_id ?? d.control_id ?? "");

  if (engine.includes("cve") || engine.includes("vuln")) {
    const cve = String((d.source as Rec | undefined)?.cve ?? (vuln?.cve_id as string | undefined) ?? title.split(":")[0] ?? "");
    const fixed = String((vuln?.fixed_version as string | undefined) ?? (d.remediation as Rec | undefined)?.fixed_version ?? "");
    const installed = String((vuln?.installed_version as string | undefined) ?? ev.installed_version ?? ev.observed ?? "");
    const product = String((vuln?.product as string | undefined) ?? ev.product ?? "");
    const desc = String((vuln?.description as string | undefined) ?? "");
    const where = product || installed ? ` (${[product, installed].filter(Boolean).join(" ")})` : "";
    if (fixed && fixed !== "—")
      return `${cve}${where} is vulnerable. ${desc ? desc + " " : ""}Fix: upgrade to ${fixed} (or later), verify with \`show version\`, then re-audit.`;
    const adv = refs.length ? ` Vendor advisory: ${refs[0]}${refs.length > 1 ? ` (+${refs.length - 1} more below)` : ""}` : "";
    return `${cve}${where} is vulnerable. ${desc ? desc + " " : ""}No fixed release is recorded in the KB — open the vendor advisory to pick the fixed release for your train, upgrade, verify with \`show version\`, then re-audit.${adv}`;
  }
  if (engine.includes("pqc")) {
    const row = (ev.observed as Rec | undefined) ?? {};
    const algo = String(row.algorithm ?? title);
    const proto = String(row.protocol ?? "");
    const klass = String(row.klass ?? "");
    const migration = String((d.remediation as Rec | undefined)?.migration ?? row.migration ?? "");
    return `${algo}${proto ? ` on ${proto}` : ""} is ${klass || "not quantum-safe"} and flagged MIGRATION_REQUIRED. ${migration ? `Migration: ${migration}.` : "Plan a migration to a NIST-approved PQC algorithm."}`;
  }
  if (engine.includes("secur")) {
    const detail = fmt(ev.detail ?? ev.observed);
    return `Security analytics flagged ${property || title}: ${detail}. Review the config for exposure/misconfiguration even though no compliance rule fired.`;
  }
  // compliance (default)
  if (status === "PASS") return `${control ? `Control ${control}: ` : ""}${title} — device satisfies the check (${property} meets expected value). No action needed.`;
  if (status === "UNKNOWN" || observed === undefined || observed === null || observed === "—")
    return `${control ? `Control ${control}: ` : ""}${title} — could not be verified because "${property || "required property"}" was not found in the parsed config. Check Unknown Tokens / Training, then re-audit. This is NOT proof of compliance.`;
  return `${control ? `Control ${control}: ` : ""}${title} — "${property}" is ${fmt(observed)} but the policy requires ${fmt(expected)}${operator ? ` (rule: ${operator})` : ""}. Fix the config value, then re-audit to verify PASS.`;
}

function actionSteps(d: Rec, plan: Rec | undefined, vuln: Rec | undefined): { steps: string[]; validation: string[]; meta: string[] } {
  // CVE: prefer the version-grounded vuln-detail steps, then the plan steps.
  if (isCve(d) && vuln) {
    const vRem = (vuln.remediation ?? {}) as Rec;
    const vSteps = Array.isArray(vRem.steps) ? (vRem.steps as unknown[]).map(String).filter(Boolean) : [];
    const vVal = Array.isArray(vRem.validation) ? (vRem.validation as unknown[]).map(String).filter(Boolean) : [];
    if (vSteps.length || vVal.length)
      return { steps: vSteps, validation: vVal, meta: [] };
  }
  const steps: string[] = [];
  const validation: string[] = [];
  const meta: string[] = [];
  const pSteps = plan?.steps as { order?: number; command?: string }[] | undefined;
  if (pSteps?.length) steps.push(...pSteps.map((s) => String(s.command ?? "")).filter(Boolean));
  const pVal = plan?.validation as unknown[] | undefined;
  if (pVal?.length) validation.push(...pVal.map(String).filter(Boolean));
  if (plan?.rollback_available !== undefined)
    meta.push(`Rollback: ${plan.rollback_available === true ? "available" : "not available"}`);
  if (plan?.vendor) meta.push(`Vendor: ${String(plan.vendor)}${plan?.platform ? ` / ${String(plan.platform)}` : ""}`);

  const rem = (d.remediation ?? {}) as Rec;
  const detail = (rem.detail ?? {}) as Rec;
  const vendors = (detail.vendors ?? {}) as Rec;
  if (!steps.length) {
    for (const v of Object.values(vendors)) {
      const cmds = (v as Rec).commands as unknown[] | undefined;
      if (cmds?.length) {
        steps.push(...cmds.map(String).filter(Boolean));
        const vv = (v as Rec).validation as unknown[] | undefined;
        if (vv?.length && !validation.length) validation.push(...vv.map(String).filter(Boolean));
        break;
      }
    }
  }
  const fixed = String(rem.fixed_version ?? "");
  if (!steps.length && fixed) steps.push(`Upgrade to vendor-validated version ${fixed}`, "Back up running-config, upgrade in a maintenance window, verify with `show version`", "Re-run audit to verify the CVE is resolved");
  const migration = String(rem.migration ?? "");
  if (!steps.length && migration) steps.push(migration);
  return { steps, validation, meta };
}

export default function FindingDetails() {
  const { findingId = "" } = useParams();
  const q = useQuery({ queryKey: ["finding", findingId], queryFn: () => getFinding(findingId) });
  const plan = useQuery({ queryKey: ["rem", findingId], queryFn: () => getRemediation(findingId), retry: false });
  const d = (q.data ?? undefined) as unknown as Rec | undefined;
  const auditId = d ? String(d.audit_id ?? "") : "";
  const cveMode = d ? isCve(d) : false;
  const vulnQ = useQuery({
    queryKey: ["vuln-detail", auditId, findingId],
    queryFn: () => getVulnDetail(auditId, findingId),
    enabled: !!d && cveMode && !!auditId,
    retry: false,
  });
  const vuln = (vulnQ.data ?? undefined) as unknown as Rec | undefined;

  if (q.isLoading) return <Loader />;
  if (q.isError || !d) return <ErrorState message="Finding not found." onRetry={() => q.refetch()} />;
  const ev = (d.evidence ?? {}) as Rec;
  const risk = (d.risk ?? {}) as Rec;
  const rem = (d.remediation ?? {}) as Rec;
  const frameworks = (d.frameworks ?? {}) as Rec;
  const source = (d.source ?? {}) as Rec;
  const detail = (rem.detail ?? {}) as Rec;
  const planData = (plan.data ?? undefined) as Rec | undefined;
  const refs = refsOf(
    (vuln?.references as unknown[] | undefined),
    (planData?.references as unknown[] | undefined),
    (rem.references as unknown[] | undefined),
    (ev.references as unknown[] | undefined),
  );
  const { steps, validation, meta } = actionSteps(d, planData, vuln);
  const observed = ev.observed_value ?? ev.observed ?? "—";
  const expected = ev.expected_value ?? ev.expected ?? "—";
  const property = ev.property ?? ev.control_id ?? d.control_id ?? "—";
  const operator = ev.operator ?? "—";
  const matchedRule = (vuln?.matched_rule as Rec | undefined) ?? (ev.matched_rule as Rec | undefined);
  const cvss = ((vuln?.cvss as Rec | undefined) ?? (ev.cvss as Rec | undefined) ?? {}) as Rec;
  const pqcRow = (ev.observed as Rec | undefined) ?? (typeof ev.observed === "object" ? (ev.observed as Rec) : undefined);

  return (
    <div>
      <PageHeader
        title={String(d.title ?? findingId)}
        sub={`${String(d.severity ?? "—")} · ${String(d.status ?? "—")} · ${String(d.engine ?? d.type ?? "—")} · Risk ${riskScore(risk)} · Confidence ${fmt(d.confidence)}`}
        actions={
          <>
            <Link to="/findings" className={btnGhost}>← All findings</Link>
            <Link to={`/remediation/${findingId}`} className={btnPrimary}>Fix this → Remediation</Link>
          </>
        }
      />
      <div className="mb-4 flex flex-wrap gap-2">
        <Badge value={String(d.severity ?? "?")} kind="sev" />
        <Badge value={String(d.status ?? "—")} />
        <Badge value={String(d.type ?? d.engine ?? "—")} />
        {d.control_id ? <Badge value={String(d.control_id)} /> : null}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-4">
          <Card title="What does this mean?" sub="Plain-language explanation for the network engineer">
            <p className="text-sm leading-relaxed text-ink">{buildSummary(d, ev, vuln, refs)}</p>
            <dl className="mt-3 space-y-2 text-sm">
              {[
                ["Check", String(d.control_id ?? source.cve ?? vuln?.cve_id ?? d.finding_id ?? "—")],
                cveMode
                  ? ["Device software", `${fmt((vuln?.product as string | undefined) ?? ev.product ?? "—")} ${fmt((vuln?.installed_version as string | undefined) ?? ev.installed_version ?? observed)}`]
                  : ["Device setting", `${fmt(property)} = ${fmt(observed)}`],
                cveMode
                  ? ["Fixed release", fmt((vuln?.fixed_version as string | undefined) ?? rem.fixed_version ?? "not recorded — see advisory links")]
                  : ["Policy requires", `${fmt(expected)}${operator !== "—" ? ` (operator ${fmt(operator)})` : ""}`],
                ["Verdict", `${String(d.status ?? "—")} — ${String(d.status) === "FAIL" ? "must fix" : String(d.status) === "PASS" ? "no action" : "needs investigation"}`],
                ["Asset / Audit", `${fmt(d.asset_id)} / ${fmt(d.audit_id)}`],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between gap-3 rounded-lg bg-surface2 px-3 py-2">
                  <dt className="shrink-0 text-ink3">{k}</dt>
                  <dd className="break-all text-right font-mono text-xs text-ink">{v}</dd>
                </div>
              ))}
            </dl>
          </Card>

          {cveMode && (
            <Card title="CVE advisory — rule-based record" sub="Description, CVSS and vendor links from the CVE knowledge base (pre-set data, not AI)">
              {vulnQ.isLoading ? (
                <Loader label="Loading advisory…" />
              ) : (
                <>
                  {vuln?.description ? <p className="text-sm leading-relaxed text-ink2">{String(vuln.description)}</p> : null}
                  <dl className="mt-3 space-y-2 text-sm">
                    {[
                      ["CVE", fmt((vuln?.cve_id as string | undefined) ?? source.cve ?? d.control_id)],
                      ["Product / version", `${fmt((vuln?.product as string | undefined) ?? ev.product)} / ${fmt((vuln?.installed_version as string | undefined) ?? ev.installed_version ?? observed)}`],
                      ["CPE", fmt((vuln?.cpe as string | undefined) ?? ev.installed_cpe ?? ev.cpe)],
                      ["CVSS", `${fmt(cvss.score ?? cvss.base_score)} / ${fmt(cvss.severity)}`],
                      ["Vector", fmt(cvss.vector)],
                      ["CWE", fmt(vuln?.cwe)],
                      ["Affected range", matchedRule && (matchedRule.start != null || matchedRule.end != null) ? fmt(matchedRule) : "not version-bounded in KB — every installed release treated as affected"],
                      ["Fixed release", fmt((vuln?.fixed_version as string | undefined) ?? rem.fixed_version ?? "not recorded — pick from advisory")],
                      ["Confidence", fmt(vuln?.confidence ?? d.confidence)],
                    ].map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-3 rounded-lg bg-surface2 px-3 py-2">
                        <dt className="shrink-0 text-ink3">{k}</dt>
                        <dd className="break-all text-right font-mono text-xs text-ink">{v}</dd>
                      </div>
                    ))}
                  </dl>
                  {refs.length > 0 ? (
                    <div className="mt-3">
                      <p className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-ink3">Advisory links — open the vendor notice for this CVE</p>
                      <ul className="space-y-1.5">
                        {refs.map((u) => (
                          <li key={u} className="break-all rounded-lg bg-surface2 px-3 py-2 font-mono text-xs">
                            <a href={u} target="_blank" rel="noreferrer" className="text-primary hover:underline">{u}</a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <p className="mt-3 text-xs text-ink3">No advisory URL stored for this CVE — search the vendor security portal for {String(source.cve ?? d.control_id ?? findingId)}.</p>
                  )}
                </>
              )}
            </Card>
          )}

          {!cveMode && (
            <Card title="Evidence" sub="Exact values the engine compared — proof of the verdict">
              <dl className="space-y-2 text-sm">
                {[
                  ["Property", fmt(property)],
                  ["Observed (on device)", fmt(observed)],
                  ["Expected (policy)", fmt(expected)],
                  ["Operator", fmt(operator)],
                  ["Control", fmt(ev.control_id ?? d.control_id)],
                  ["CVE / source", fmt(source.cve ?? source.control ?? source.analytics ?? (source.cbom ? "crypto inventory (CBOM)" : "—"))],
                  ["CPE", fmt(ev.cpe)],
                  ["Matched version rule", matchedRule ? fmt(matchedRule) : "—"],
                  ["PQC detail", pqcRow && (d.engine === "pqc" || d.type === "PQC") ? fmt(pqcRow) : "—"],
                  ["Security detail", fmt(ev.detail)],
                  ["Confidence", fmt(d.confidence)],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-3 rounded-lg bg-surface2 px-3 py-2">
                    <dt className="shrink-0 text-ink3">{k}</dt>
                    <dd className="break-all text-right font-mono text-xs text-ink">{v}</dd>
                  </div>
                ))}
              </dl>
              {Object.keys(frameworks).length > 0 && (
                <div className="mt-3">
                  <p className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-ink3">Satisfies frameworks — one fix covers all</p>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(frameworks).map(([fw, id]) => (
                      <span key={fw} className="rounded-md border border-line bg-surface2 px-2 py-0.5 font-mono text-[11px] text-ink2">
                        {fw}: {fmt(id)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </Card>
          )}

          <Card title="Risk & priority" sub="Why this matters and how urgently to fix it">
            <dl className="space-y-2 text-sm">
              {[
                ["Risk score", riskScore(risk)],
                ["Priority", fmt(risk.priority)],
                ["Severity", fmt(d.severity)],
                ["Rule score (M6)", fmt(risk.rule_score)],
                ["Risk factors", fmt(risk.factors)],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between gap-3 rounded-lg bg-surface2 px-3 py-2">
                  <dt className="shrink-0 text-ink3">{k}</dt>
                  <dd className="break-all text-right font-mono text-xs text-ink">{v}</dd>
                </div>
              ))}
            </dl>
          </Card>
        </div>

        <div className="space-y-4">
          <Card title="What do I have to do? — fix steps" sub="Concrete upgrade / config change, then verify. Nothing touches a live device.">
            {plan.isLoading ? (
              <Loader label="Loading fix plan…" />
            ) : steps.length || validation.length ? (
              <div className="space-y-3">
                {steps.length > 0 && (
                  <div>
                    <p className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-ink3">Run these ({steps.length})</p>
                    <ol className="space-y-1.5">
                      {steps.map((c, i) => (
                        <li key={i} className="flex gap-2 rounded-lg bg-surface2 px-3 py-2 font-mono text-xs text-ink">
                          <span className="shrink-0 font-semibold text-primary">{i + 1}.</span>
                          <span className="break-all">{c}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
                {validation.length > 0 && (
                  <div>
                    <p className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-ink3">Verify with</p>
                    <ul className="space-y-1.5">
                      {validation.map((c, i) => (
                        <li key={i} className="rounded-lg border border-dashed border-linestrong px-3 py-1.5 font-mono text-xs text-ink2">{c}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {refs.length > 0 && (
                  <div>
                    <p className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-ink3">Vendor advisory</p>
                    <ul className="space-y-1.5">
                      {refs.map((u) => (
                        <li key={u} className="break-all rounded-lg bg-surface2 px-3 py-2 font-mono text-xs">
                          <a href={u} target="_blank" rel="noreferrer" className="text-primary hover:underline">{u}</a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {meta.length > 0 && <p className="text-[11px] text-ink3">{meta.join(" · ")}</p>}
                <Link to={`/remediation/${findingId}`} className={btnPrimary}>Approve & dry-run apply →</Link>
              </div>
            ) : (
              <div className="space-y-2 text-sm text-ink2">
                <p>
                  {String(rem.available) === "true" || rem.available === true
                    ? "A fix is marked available but no step list was returned — open Remediation for the vendor procedure."
                    : "No automated fix for this finding type (typical for Security-analytics anomalies). Manually review the evidence above, harden the config, then re-audit."}
                </p>
                {rem.fixed_version ? <p className="font-mono text-xs">Upgrade target: {fmt(rem.fixed_version)}</p> : null}
                {rem.migration ? <p className="font-mono text-xs">Migration: {fmt(rem.migration)}</p> : null}
                {Object.keys(detail).length > 0 && !Object.keys(detail).includes("vendors") ? (
                  <pre className="overflow-auto rounded-lg border border-line bg-surface2 p-2.5 font-mono text-[11px] text-ink2">{JSON.stringify(detail, null, 2)}</pre>
                ) : null}
                <Link to={`/remediation/${findingId}`} className={btnGhost}>Open in Remediation →</Link>
                {plan.isError ? <p className="text-[11px] text-ink3">Fix-plan API unavailable — showing finding-embedded guidance only.</p> : null}
              </div>
            )}
          </Card>

          <Card title="Record" sub="IDs for audit trail / deep links">
            <dl className="space-y-2 text-sm">
              {[
                ["Finding ID", String(d.finding_id ?? findingId)],
                ["Type / Engine", `${fmt(d.type)} / ${fmt(d.engine)}`],
                ["Status", fmt(d.status)],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between gap-3 rounded-lg bg-surface2 px-3 py-2">
                  <dt className="shrink-0 text-ink3">{k}</dt>
                  <dd className="break-all text-right font-mono text-xs text-ink">{v}</dd>
                </div>
              ))}
              <div className="flex justify-between gap-3 rounded-lg bg-surface2 px-3 py-2">
                <dt className="shrink-0 text-sm text-ink3">Audit</dt>
                <dd className="text-right font-mono text-xs">
                  {d.audit_id ? <Link to={`/audits/${String(d.audit_id)}/results`} className="text-primary hover:underline">{String(d.audit_id)}</Link> : "—"}
                </dd>
              </div>
              <div className="flex justify-between gap-3 rounded-lg bg-surface2 px-3 py-2">
                <dt className="shrink-0 text-sm text-ink3">Asset</dt>
                <dd className="text-right font-mono text-xs">
                  {d.asset_id ? <Link to={`/assets/${String(d.asset_id)}`} className="text-primary hover:underline">{String(d.asset_id)}</Link> : "—"}
                </dd>
              </div>
            </dl>
          </Card>

          <details className="rounded-[10px] border border-line bg-surface p-4">
            <summary className="cursor-pointer text-sm font-semibold text-ink2">Raw backend payload (debug)</summary>
            <pre className="code-view mt-2 max-h-[40vh] overflow-auto rounded-lg border border-line bg-surface2 p-3 text-[11px] text-ink2">{JSON.stringify(d, null, 2)}</pre>
          </details>
        </div>
      </div>
    </div>
  );
}
