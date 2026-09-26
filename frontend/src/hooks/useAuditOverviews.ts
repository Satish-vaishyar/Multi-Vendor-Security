import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams, useSearchParams } from "react-router-dom";
import { listAudits } from "../api/audits.api";

export interface AuditOverview {
  audit_id: string;
  status: string;
  progress?: number;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  compliance_score?: number;
  frameworks?: Record<string, { score?: number }>;
  risk_score?: number;
  pqc_readiness?: number;
  /** findings per engine: COMPLIANCE / CVE / PQC / SECURITY */
  engines: Record<string, number>;
  /** engine -> severity -> count */
  engineSev: Record<string, Record<string, number>>;
}

/** Recent audits from ONE lightweight list call (no per-audit fan-out). */
export function useAuditOverviews() {
  const q = useQuery({ queryKey: ["audits", "list"], queryFn: listAudits, staleTime: 30000 });

  const overviews: AuditOverview[] = useMemo(() => {
    return (q.data?.items ?? []).map((a) => {
      const s = a.summary ?? {};
      const crit = Number(s.critical ?? 0);
      const high = Number(s.high ?? 0);
      const med = Number(s.medium ?? 0);
      const low = Number(s.low ?? 0);
      const risk = Number(s.security_risk ?? NaN);
      const pqc = Number(s.pqc_readiness ?? NaN);
      const engines: Record<string, number> = {};
      const engineSev: Record<string, Record<string, number>> = {};
      for (const [e, sevs] of Object.entries(a.engines ?? {})) {
        engineSev[e] = sevs;
        engines[e] = Object.values(sevs).reduce((t, n) => t + Number(n), 0);
      }
      return {
        audit_id: a.audit_id,
        status: String(a.status ?? "—"),
        progress: typeof a.progress === "number" ? a.progress : undefined,
        total: crit + high + med + low,
        critical: crit,
        high,
        medium: med,
        low,
        compliance_score: s.compliance_score,
        frameworks: a.frameworks,
        risk_score: Number.isNaN(risk) ? undefined : risk,
        pqc_readiness: Number.isNaN(pqc) ? undefined : pqc,
        engines,
        engineSev,
      };
    });
  }, [q.data]);

  return {
    overviews,
    isLoading: q.isLoading,
    isError: q.isError,
    refetch: () => q.refetch(),
  };
}

/** Selected audit id shared via ?auditId=, falling back to the :auditId path param. */
export function useSelectedAudit(): [string, (id: string) => void] {
  const params = useParams();
  const [sp, setSp] = useSearchParams();
  const pathId = (params as Record<string, string | undefined>).auditId ?? "";
  const selected = sp.get("auditId") ?? pathId;
  const select = (id: string) =>
    setSp((prev) => {
      const n = new URLSearchParams(prev);
      if (id) n.set("auditId", id);
      else n.delete("auditId");
      return n;
    });
  return [selected, select];
}

export function fmtScore(v: number | undefined, d = 1): string {
  return v == null || Number.isNaN(v) ? "—" : Number(v).toFixed(d);
}
