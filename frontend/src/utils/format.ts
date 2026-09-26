export function fmtNum(v: unknown, d = 1): string {
  const n = Number(v);
  if (Number.isNaN(n)) return "—";
  return n.toFixed(d);
}

/* Semantic severity colours — theme-aware via CSS variables.
   Red means critical, orange high, amber warning, blue low. */
export function sevColor(sev?: string): string {
  switch (String(sev ?? "").toUpperCase()) {
    case "CRITICAL":
      return "bg-dangerbg text-danger border-danger/30";
    case "HIGH":
      return "bg-highbg text-high border-high/30";
    case "MEDIUM":
      return "bg-warnbg text-warn border-warn/30";
    case "LOW":
      return "bg-infobg text-info border-info/30";
    default:
      return "bg-surface2 text-ink2 border-line";
  }
}

export function statusColor(s?: string): string {
  const v = String(s ?? "").toUpperCase().replace(/ /g, "_");
  if (["PASS", "COMPLETED", "APPROVED", "READY", "NOT_AFFECTED", "ACTIVE", "VALIDATED"].includes(v))
    return "bg-okbg text-ok border-ok/30";
  if (["FAIL", "FAILED", "VULNERABLE", "AT_RISK", "CRITICAL"].includes(v))
    return "bg-dangerbg text-danger border-danger/30";
  if (["RUNNING", "PENDING", "QUEUED", "GENERATING", "TRANSITION", "PARTIAL", "UNKNOWN"].includes(v))
    return "bg-warnbg text-warn border-warn/30";
  return "bg-surface2 text-ink2 border-line";
}

export function shortId(id?: string): string {
  return String(id ?? "—");
}

/** Read chart palette + surface tokens from the live theme. */
export function chartVars(): { charts: string[]; sev: string[]; surface: string; border: string; ink: string; muted: string } {
  const cs = getComputedStyle(document.documentElement);
  const g = (n: string) => cs.getPropertyValue(n).trim();
  return {
    charts: [g("--chart-1"), g("--chart-2"), g("--chart-3"), g("--chart-4")],
    sev: [g("--danger"), g("--high"), g("--warning"), g("--info")],
    surface: g("--surface"),
    border: g("--border"),
    ink: g("--text-primary"),
    muted: g("--text-muted"),
  };
}
