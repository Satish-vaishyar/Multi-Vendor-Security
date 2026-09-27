import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { getPqc } from "../api/pqc.api";
import { fmtScore, useAuditOverviews, useSelectedAudit } from "../hooks/useAuditOverviews";
import { AuditPicker } from "../components/AuditPicker";
import { Card, Empty, ErrorState, Loader, PageHeader, PqcBadge } from "../components/common";

type Row = Record<string, unknown>;
const str = (v: unknown, fb = "—") => (v === null || v === undefined || v === "" ? fb : String(v));

/** Display-only label for 0–100 readiness. Backend remains the source of truth for score/counts. */
function readinessLabel(score: number | null, counts: Record<string, number>): string {
  if (score == null || Number.isNaN(score)) return "—";
  if (score >= 85 && (counts.READY ?? 0) > 0) return "On track";
  if (score >= 60) return "Progressing";
  if (score >= 25) return "Early transition";
  return "At risk";
}

const RISK_FALLBACK: Record<string, string> = {
  MIGRATION_REQUIRED: "High — broken or deprecated, fix first.",
  TRANSITION: "Medium — works today but would break against a quantum attacker. Plan the upgrade.",
  READY: "Low — post-quantum / hybrid support is present.",
  UNKNOWN: "Unknown — not enough evidence to assess.",
};
const PRIORITY_FALLBACK: Record<string, string> = {
  MIGRATION_REQUIRED: "P1 — fix now",
  TRANSITION: "P2 — plan next",
  READY: "P3 — keep current",
  UNKNOWN: "—",
};

function statusOf(r: Row): string {
  return str(r.pqc_status ?? (r as Row).status, "UNKNOWN");
}

/**
 * Join recommendations to inventory rows so the "Current" column always
 * names the affected item (never the recommendation text) and Risk/Priority
 * are never blank — including audits stored by older backends where recs
 * were plain strings like "Track vendor PQC/hybrid roadmap".
 */
function normalizeRecs(recs: unknown, algos: Row[]): Row[] {
  if (!Array.isArray(recs)) return [];
  return (recs as unknown[]).map((r): Row => {
    if (typeof r === "string") {
      const match =
        algos.find((a) => r === str(a.migration, "") || r === str(a.recommended, "")) ??
        algos.find((a) => { const m = str(a.migration, ""); return !!m && m !== "—" && r.includes(m); }) ??
        algos[0];
      if (!match) {
        return { current: "General crypto hygiene", risk: "—", priority: "—", recommended_direction: r, fix_steps: [r], migration: r };
      }
      const st = statusOf(match);
      return {
        algorithm: match.algorithm, protocol: match.protocol,
        current: currentOf(match), summary: str(match.summary, ""),
        risk: str(match.risk, RISK_FALLBACK[st] ?? "—"),
        priority: str(match.priority, PRIORITY_FALLBACK[st] ?? "—"),
        recommended_direction: str(match.recommended ?? match.migration, r),
        fix_steps: Array.isArray(match.fix_steps) && match.fix_steps.length ? match.fix_steps : [r],
        migration: r,
      };
    }
    const d = { ...((r ?? {}) as Row) };
    const st = statusOf(d);
    const match = algos.find((a) => a.algorithm === d.algorithm && (d.protocol == null || a.protocol === d.protocol));
    if (!d.risk) d.risk = str(match?.risk, RISK_FALLBACK[st] ?? "—");
    if (!d.priority) d.priority = str(match?.priority, PRIORITY_FALLBACK[st] ?? "—");
    if (!d.current) d.current = str(d.algorithm ?? d.migration, "—");
    if (!d.recommended_direction) d.recommended_direction = str(d.recommended ?? d.migration, "—");
    if (!Array.isArray(d.fix_steps) || !(d.fix_steps as unknown[]).length) {
      const fromRow = match?.fix_steps;
      d.fix_steps = (Array.isArray(fromRow) && fromRow.length ? fromRow : d.migration ? [d.migration] : []) as unknown;
    }
    return d;
  });
}

function currentOf(a: Row): string {
  if (typeof a.current === "string" && a.current) return a.current;
  const base = str(a.algorithm ?? a.name, "Unknown item");
  const extra = a.key_size !== null && a.key_size !== undefined && String(a.key_size) !== "" ? String(a.key_size) : str(a.version ?? "", "");
  const proto = str(a.protocol ?? "", "");
  let cur = extra ? `${base} (${extra})` : base;
  if (proto && proto !== "—" && !cur.toLowerCase().includes(proto.toLowerCase().split(" ")[0])) cur += ` — ${proto}`;
  return cur;
}

function keyOrVersion(a: Row): string {
  if (a.key_size !== null && a.key_size !== undefined && String(a.key_size) !== "") return str(a.key_size);
  return str(a.version ?? "", "not detected");
}

const prioRank = (p: unknown) => {
  const s = String(p ?? "");
  if (s.startsWith("P1")) return 1;
  if (s.startsWith("P2")) return 2;
  if (s.startsWith("P3")) return 3;
  return 9;
};

export default function PQC() {
  const [auditId, select] = useSelectedAudit();
  const audits = useAuditOverviews();
  const q = useQuery({ queryKey: ["pqc", auditId], queryFn: () => getPqc(auditId), enabled: !!auditId });
  const d = (q.data ?? {}) as Row;
  const algos = useMemo(() => (Array.isArray(d.algorithms) ? (d.algorithms as Row[]) : []), [q.data]);
  const recs = useMemo(() => normalizeRecs(d.migration_recommendations, algos), [q.data, algos]);
  const orderedFixes = useMemo(() => [...recs].sort((a, b) => prioRank(a.priority) - prioRank(b.priority)), [recs]);
  const counts = (d.counts ?? {}) as Record<string, number>;
  const scoreRaw = d.readiness_score ?? d.readiness;
  const score = scoreRaw == null ? null : Number(scoreRaw);
  const label = str(d.readiness_label ?? (score != null ? readinessLabel(score, counts) : "—"));
  const needMigration = Number(counts.MIGRATION_REQUIRED ?? 0);
  const inTransition = Number(counts.TRANSITION ?? 0);

  return (
    <div>
      <PageHeader
        title="PQC Security"
        sub="Which encryption in this audit breaks against quantum computers, and exactly what to do about it."
      />
      <div className="mb-4">
        <AuditPicker
          overviews={audits.overviews} isLoading={audits.isLoading} isError={audits.isError} onRetry={audits.refetch}
          value={auditId} onSelect={select}
          renderBrief={(a) => <>PQC readiness {fmtScore(a.pqc_readiness)}{a.pqc_readiness != null ? "%" : ""} · {a.engines.PQC ?? 0} PQC findings</>}
        />
      </div>
      {!auditId ? <Empty label="Select an audit above to inspect PQC readiness." /> : (
        <Card title={`PQC detail — ${auditId}`} sub={q.data ? "Inventory of the crypto found, why each item got its status, and the fix list in priority order." : undefined}>
          {q.isLoading ? <Loader /> : q.isError ? <ErrorState message="PQC data unavailable." onRetry={() => q.refetch()} /> : (
            <>
              {/* How to read this page */}
              <div className="mb-4 rounded-[10px] border border-line bg-surface2 p-4 text-xs leading-relaxed text-ink2">
                <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-ink3">How to read this page (30 seconds)</p>
                <ul className="list-disc space-y-1 pl-5">
                  <li><b className="text-ink">CBOM</b> = the list of encryption below: what was found and where (config file vs. installed software).</li>
                  <li><b className="text-ink">Score</b> = average over the items: Ready counts 100, Transition 60, Migration-required 10, Unknown 40.
                    {algos.length > 0 && score != null && !Number.isNaN(score)
                      ? ` Here, ${algos.length} item${algos.length === 1 ? "" : "s"} average to ${score}%.`
                      : ""}</li>
                  <li><b className="text-ink">Transition ≠ safe.</b> It means "works today, breaks against a quantum attacker" — plan the upgrade (P2). <b className="text-ink">Migration required</b> means broken or deprecated — fix now (P1).</li>
                </ul>
              </div>

              {/* Summary band */}
              <div className="mb-4 grid gap-3 md:grid-cols-[1fr_2fr]">
                <div className="rounded-[10px] bg-pqcbg p-4 text-center">
                  <p className="text-3xl font-semibold text-pqc">{score != null && !Number.isNaN(score) ? `${score}%` : "—"}</p>
                  <p className="mt-1 text-xs font-semibold uppercase tracking-wider text-pqc">{label}</p>
                  <p className="mt-2 text-[11px] leading-relaxed text-ink2">
                    {algos.length === 0 ? "No crypto was found to score."
                      : needMigration > 0 ? `${needMigration} item${needMigration === 1 ? "" : "s"} must be fixed now (P1)${inTransition > 0 ? `, ${inTransition} planned next (P2)` : ""}. Start with fix #1 below.`
                      : inTransition > 0 ? `Nothing is broken today. ${inTransition} item${inTransition === 1 ? "" : "s"} need${inTransition === 1 ? "s" : ""} a planned upgrade to hybrid post-quantum crypto (P2).`
                      : "Everything inventoried already uses post-quantum / hybrid crypto. Keep it updated."}
                  </p>
                </div>
                <div className="rounded-[10px] border border-line bg-surface2 p-4">
                  <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-ink3">Inventory by status</p>
                  <div className="flex flex-wrap gap-2">
                    {(["MIGRATION_REQUIRED", "TRANSITION", "READY", "UNKNOWN"] as const).map((s) => (
                      <span key={s} className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface px-2.5 py-1 text-xs text-ink2">
                        <PqcBadge value={s} />
                        <b className="text-ink">{Number(counts[s] ?? 0)}</b>
                      </span>
                    ))}
                    <span className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface px-2.5 py-1 text-xs text-ink2">
                      Total <b className="text-ink">{algos.length}</b>
                    </span>
                  </div>
                  <ul className="mt-3 space-y-1 text-[11px] leading-relaxed text-ink2">
                    <li><b className="text-ink">Migration required (P1)</b> — broken or deprecated now (weak ciphers, short RSA, old TLS/IKE/SSH). Fix before anything else.</li>
                    <li><b className="text-ink">Transition (P2)</b> — secure against today's attackers but not quantum-safe (RSA ≥ 2048, TLS 1.2+, IKEv2, current libraries). Schedule the hybrid upgrade (ML-KEM for key exchange, ML-DSA for signatures).</li>
                    <li><b className="text-ink">Ready (P3)</b> — already uses post-quantum / hybrid algorithms. No action.</li>
                  </ul>
                </div>
              </div>

              {/* Inventory */}
              <h3 className="mb-2 text-sm font-semibold text-ink">What was found and why it got this status</h3>
              {!algos.length ? <Empty label="No crypto was found in this audit's config or software inventory." /> : (
                <div className="space-y-2">
                  {algos.map((a, i) => {
                    const st = statusOf(a);
                    return (
                      <div key={i} className="rounded-lg border border-line bg-surface2 p-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <p className="text-sm font-semibold text-ink">
                            {str(a.algorithm ?? a.name, `Item ${i + 1}`)}
                            <span className="ml-2 font-mono text-xs font-normal text-ink3">
                              {str(a.version ? `v${a.version}` : "", "")}{a.key_size !== null && a.key_size !== undefined && String(a.key_size) !== "" ? ` · key ${String(a.key_size)}` : ""} · {str(a.protocol ?? "", "")} · found in {str(a.location, "config")}
                            </span>
                          </p>
                          <PqcBadge value={st} />
                        </div>
                        {str(a.summary, "") !== "—" && str(a.summary, "") !== "" && (
                          <p className="mt-1 text-xs leading-relaxed text-ink2">{str(a.summary)}</p>
                        )}
                        <p className="mt-1 text-xs text-ink3"><b className="text-ink2">Key / version:</b> <span className="font-mono">{keyOrVersion(a)}</span></p>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Fix list */}
              {!!orderedFixes.length && (
                <div className="mt-5">
                  <h3 className="mb-1 text-sm font-semibold text-ink">Fix list — do these in order (from backend, never invented)</h3>
                  <p className="mb-2 text-xs text-ink3">P1 items first (broken today), then P2 (quantum-only risk). Each fix shows the concrete steps.</p>
                  <div className="space-y-2">
                    {orderedFixes.map((r, i) => (
                      <div key={i} className="rounded-lg border border-line bg-surface2 p-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <p className="text-sm font-semibold text-ink">
                            <span className="mr-2 inline-flex h-5 w-5 items-center justify-center rounded-full bg-pqcbg text-[11px] text-pqc">{i + 1}</span>
                            {str(r.current, `Item ${i + 1}`)}
                          </p>
                          <span className="rounded-md border border-line bg-surface px-2 py-0.5 text-[11px] font-semibold text-ink2">{str(r.priority, "—")}</span>
                        </div>
                        <p className="mt-1.5 text-xs leading-relaxed text-ink2"><b className="text-ink">Why it matters:</b> {str(r.risk, "See inventory above.")}</p>
                        {str(r.summary, "") !== "" && str(r.summary, "") !== "—" && (
                          <p className="mt-0.5 text-xs leading-relaxed text-ink3">{str(r.summary)}</p>
                        )}
                        <div className="mt-1.5 text-xs leading-relaxed text-ink2">
                          <b className="text-ink">Fix:</b>{" "}
                          {Array.isArray(r.fix_steps) && (r.fix_steps as unknown[]).length ? (
                            <ol className="mt-1 list-decimal space-y-0.5 pl-5">
                              {(r.fix_steps as unknown[]).map((s, j) => <li key={j}>{String(s)}</li>)}
                            </ol>
                          ) : (
                            <span>{str(r.recommended_direction, "—")}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <details className="mt-4 rounded-[10px] border border-line bg-surface2 p-3 text-[11px] leading-relaxed text-ink3">
                <summary className="cursor-pointer font-semibold text-ink2">Glossary — what do these terms mean?</summary>
                <ul className="mt-2 list-disc space-y-1 pl-5">
                  <li><b>Shor's algorithm</b> — a quantum-computer method that breaks RSA, ECDSA, and Diffie-Hellman key exchange. "Harvest now, decrypt later" means today's encrypted traffic can be recorded and decrypted once such a computer exists. Key exchange must go hybrid now; signatures only need replacing before such computers exist.</li>
                  <li><b>ML-KEM / ML-DSA / SLH-DSA</b> — the NIST-approved replacements, finalized August 2024: ML-KEM for key exchange (FIPS 203), ML-DSA for signatures (FIPS 204), SLH-DSA hash-based backup signatures (FIPS 205). HQC was selected (March 2025) as a backup key-exchange standard; FN-DSA/Falcon (FIPS 206) is still draft.</li>
                  <li><b>Hybrid</b> — using classical + post-quantum together during migration, so connections stay secure even if one side has a flaw. Real examples: <span className="font-mono">mlkem768x25519-sha256</span> and <span className="font-mono">sntrup761x25519-sha512</span> for SSH, <span className="font-mono">X25519MLKEM768</span> for TLS.</li>
                  <li><b>Deadlines (NIST IR 8547, NSA CNSA 2.0)</b> — classical public-key algorithms deprecate after 2030 and are disallowed after 2035; CNSA 2.0 migration began 2025. Externally-exposed systems go first.</li>
                  <li><b>OpenSSH reality check</b> — hybrid key exchange is available and default-on since 9.0 (<span className="font-mono">sntrup761x25519-sha512</span>, RFC 9941), ML-KEM hybrid since 9.9 and default since 10.0 (RFC 10042); 10.1+ warns on non-PQ sessions. Post-quantum host-key <i>signatures</i> are not in stable OpenSSH yet — that part stays RSA ≥ 3072 bits until OpenSSH ships it.</li>
                  <li><b>AES-128/256, SHA-256+</b> — symmetric encryption and hashes with long enough keys. Only mildly affected by quantum computers, so they are not flagged here.</li>
                </ul>
              </details>
            </>
          )}
        </Card>
      )}
    </div>
  );
}
