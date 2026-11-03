export function fmtNum(v: unknown, d = 1): string {
  const n = Number(v);
  if (Number.isNaN(n)) return "—";
  return n.toFixed(d);
}

/* Semantic severity colours — theme-aware via CSS variables.
   Red means critical, orange high, amber warning, blue low. */
export function sevColor(sev?: string): string {
  switch (String(sev ?? "").split(":")[0].trim().toUpperCase()) {
    case "CRITICAL":
      return "bg-dangerbg text-danger border-danger/25";
    case "HIGH":
      return "bg-highbg text-high border-high/25";
    case "MEDIUM":
      return "bg-warnbg text-warn border-warn/25";
    case "LOW":
      return "bg-infobg text-info border-info/25";
    default:
      return "bg-surface2 text-ink2 border-line";
  }
}

export type Tone = "ok" | "bad" | "wait" | "none";

/** Semantic tone of a status word - drives both colour and the icon (never colour alone). */
export function statusTone(s?: string): Tone {
  const v = String(s ?? "").toUpperCase().replace(/ /g, "_");
  if (["PASS", "COMPLETED", "APPROVED", "READY", "NOT_AFFECTED", "ACTIVE", "VALIDATED"].includes(v)) return "ok";
  if (["FAIL", "FAILED", "VULNERABLE", "AT_RISK", "CRITICAL"].includes(v)) return "bad";
  if (["RUNNING", "PENDING", "QUEUED", "GENERATING", "TRANSITION", "PARTIAL", "UNKNOWN", "GAP"].includes(v)) return "wait";
  return "none";
}

export function statusColor(s?: string): string {
  switch (statusTone(s)) {
    case "ok": return "bg-okbg text-ok border-ok/25";
    case "bad": return "bg-dangerbg text-danger border-danger/25";
    case "wait": return "bg-warnbg text-warn border-warn/25";
    default: return "bg-surface2 text-ink2 border-line";
  }
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

/** Only http(s) links from the knowledge base are rendered as anchors (never javascript:/data:). */
export function safeUrl(u: unknown): string | undefined {
  const s = String(u ?? "").trim();
  return /^https?:\/\//i.test(s) ? s : undefined;
}
