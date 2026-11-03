import { createElement, useEffect, useId, useRef, useState, type ReactNode } from "react";
import { CircleAlert, CircleCheck, CircleHelp, CircleX, Clock, Inbox, Info, Minus, OctagonAlert, TriangleAlert } from "lucide-react";
import { sevColor, statusColor, statusTone } from "../utils/format";
import { GLOSSARY } from "../constants";

/* ---------- Surfaces ---------- */

export function Card({ title, sub, right, children, className = "" }: { title?: ReactNode; sub?: string; right?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`min-w-0 rounded-xl border border-line bg-surface p-4 sm:p-5 ${className}`}>
      {(title || right) && (
        <div className="mb-3 flex flex-wrap items-start justify-between gap-x-3 gap-y-2">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold text-ink">{title}</h2>}
            {sub && <p className="mt-0.5 text-xs text-ink3">{sub}</p>}
          </div>
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

/* ---------- Badges (always icon + text, never colour alone) ---------- */

const badgeBase = "inline-flex items-center gap-1 whitespace-nowrap rounded-md border px-2 py-0.5 text-[11px] font-semibold";

function sevIcon(value?: string) {
  switch (String(value ?? "").split(":")[0].trim().toUpperCase()) {
    case "CRITICAL": return OctagonAlert;
    case "HIGH": return TriangleAlert;
    case "MEDIUM": return CircleAlert;
    case "LOW": return Info;
    default: return Minus;
  }
}

function statusIcon(value?: string) {
  switch (statusTone(value)) {
    case "ok": return CircleCheck;
    case "bad": return CircleX;
    case "wait": return Clock;
    default: return Minus;
  }
}

export function Badge({ value, kind = "status" }: { value?: string; kind?: "sev" | "status" }) {
  const cls = kind === "sev" ? sevColor(value) : statusColor(value);
  const icon = kind === "sev" ? sevIcon(value) : statusIcon(value);
  return (
    <span className={`${badgeBase} ${cls}`}>
      {createElement(icon, { size: 12, "aria-hidden": true, className: "shrink-0" })}
      {String(value ?? "—").replace(/_/g, " ")}
    </span>
  );
}

/** Muted indigo badge — reserved for AI-originated content only. */
export function AiBadge({ value }: { value?: string }) {
  return (
    <span className={`${badgeBase} border-ai/25 bg-aibg text-ai`}>
      {value ?? "AI Suggested"}
    </span>
  );
}

/** Muted teal badge — reserved for PQC content only. */
export function PqcBadge({ value }: { value?: string }) {
  return (
    <span className={`${badgeBase} border-pqc/25 bg-pqcbg text-pqc`}>
      {String(value ?? "—").replace(/_/g, " ")}
    </span>
  );
}

/* ---------- Loading / empty / error ---------- */

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton ${className}`} aria-hidden="true" />;
}

/** Skeleton block standing in for content that is loading. The label stays readable for screen readers. */
export function Loader({ label = "Loading…", rows = 4 }: { label?: string; rows?: number }) {
  return (
    <div role="status" aria-busy="true" className="rounded-xl border border-line bg-surface p-5">
      <p className="mb-3 text-xs text-ink3">{label}</p>
      <div className="space-y-2.5">
        {Array.from({ length: rows }).map((_, i) => (
          <Skeleton key={i} className="h-4" />
        ))}
      </div>
    </div>
  );
}

/** Row of KPI-sized skeleton cards. */
export function KpiSkeleton({ count = 4 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4" role="status" aria-busy="true" aria-label="Loading">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="rounded-xl border border-line bg-surface p-4">
          <Skeleton className="h-7 w-16" />
          <Skeleton className="mt-2 h-3 w-24" />
        </div>
      ))}
    </div>
  );
}

export function Empty({ label = "No data found.", hint, action, icon }: { label?: string; hint?: ReactNode; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center rounded-xl border border-dashed border-linestrong bg-surface2/50 px-4 py-8 text-center">
      <span className="mb-3 rounded-full bg-surface p-2.5 text-ink3 ring-1 ring-line">{icon ?? <Inbox size={20} aria-hidden="true" />}</span>
      <p className="text-sm font-medium text-ink">{label}</p>
      {hint && <p className="mt-1 max-w-md text-xs text-ink3">{hint}</p>}
      {action && <div className="mt-4 flex flex-wrap justify-center gap-2">{action}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="rounded-xl border border-danger/25 bg-dangerbg p-5 text-sm text-danger">
      <p className="flex items-center gap-2 font-semibold"><CircleX size={16} aria-hidden="true" /> Unable to load data.</p>
      <p className="mt-1 text-ink2">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-3 rounded-lg border border-danger/40 bg-surface px-3 py-1.5 text-xs font-semibold text-danger hover:bg-dangerbg"
        >
          Retry
        </button>
      )}
    </div>
  );
}

/** Inline notice (success / error / info) used instead of ad-hoc coloured paragraphs. */
export function Notice({ kind = "info", children, testId }: { kind?: "ok" | "error" | "info"; children: ReactNode; testId?: string }) {
  const cls = kind === "ok" ? "border-ok/25 bg-okbg text-ok" : kind === "error" ? "border-danger/25 bg-dangerbg text-danger" : "border-line bg-surface2 text-ink2";
  const Icon = kind === "ok" ? CircleCheck : kind === "error" ? CircleX : Info;
  return (
    <p data-testid={testId} role={kind === "error" ? "alert" : "status"} className={`flex items-start gap-2 rounded-lg border p-2.5 text-xs ${cls}`}>
      <Icon size={14} className="mt-px shrink-0" aria-hidden="true" />
      <span className="min-w-0">{children}</span>
    </p>
  );
}

/* ---------- Page chrome ---------- */

export function PageHeader({ title, sub, actions }: { title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-x-4 gap-y-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-ink sm:text-2xl">{title}</h1>
        {sub && <p className="mt-1 max-w-2xl text-sm text-ink3">{sub}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block text-xs font-medium text-ink2">
      <span className="mb-1 block text-ink2">{label}</span>
      {children}
    </label>
  );
}

/* ---------- Plain-language hints for jargon ---------- */

/** Small "?" button that explains a term in plain language on hover, focus or tap. */
export function Hint({ term, text, label }: { term?: string; text?: string; label?: string }) {
  const id = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);
  const body = text ?? (term ? GLOSSARY[term] : undefined);

  const show = () => {
    const r = btn.current?.getBoundingClientRect();
    if (!r) return;
    const w = Math.min(272, window.innerWidth - 16);
    const left = Math.max(8, Math.min(r.left + r.width / 2 - w / 2, window.innerWidth - w - 8));
    setPos({ left, top: r.bottom + 6 });
  };
  const hide = () => setPos(null);

  useEffect(() => {
    if (!pos) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setPos(null); };
    const onScroll = () => setPos(null);
    window.addEventListener("keydown", onKey);
    window.addEventListener("scroll", onScroll, true);
    return () => { window.removeEventListener("keydown", onKey); window.removeEventListener("scroll", onScroll, true); };
  }, [pos]);

  if (!body) return null;
  return (
    <span className="inline-flex align-middle" onMouseEnter={show} onMouseLeave={hide}>
      <button
        ref={btn}
        type="button"
        aria-label={`What is ${label ?? term ?? "this"}?`}
        aria-describedby={pos ? id : undefined}
        onFocus={show}
        onBlur={hide}
        onClick={() => (pos ? hide() : show())}
        className="rounded-full p-0.5 text-ink3 hover:text-primary"
      >
        <CircleHelp size={14} aria-hidden="true" />
      </button>
      {pos && (
        <span id={id} role="tooltip" style={{ left: pos.left, top: pos.top, width: Math.min(272, window.innerWidth - 16) }}
          className="pointer-events-none fixed z-50 rounded-lg border border-line bg-surface p-3 text-left text-xs font-normal normal-case leading-relaxed tracking-normal text-ink2 shadow-[var(--shadow-pop)]">
          {term && <b className="mb-0.5 block text-ink">{label ?? term}</b>}
          {body}
        </span>
      )}
    </span>
  );
}

/* ---------- Form + button styles ---------- */

export const inputCls =
  "w-full min-w-0 rounded-lg border border-linestrong bg-surface px-3 py-2 text-sm text-ink placeholder:text-ink3 outline-none transition-colors hover:border-ink3 focus:border-primary focus:ring-1 focus:ring-primary";

const btnBase = "inline-flex min-h-9 items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-50";
export const btnPrimary = `${btnBase} bg-primary text-onprimary hover:bg-primaryhover`;
export const btnGhost = `${btnBase} border border-linestrong bg-surface text-ink2 hover:bg-surface2 hover:text-ink`;
