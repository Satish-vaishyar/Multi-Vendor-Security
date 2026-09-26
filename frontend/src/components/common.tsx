import type { ReactNode } from "react";
import { sevColor, statusColor } from "../utils/format";

export function Card({ title, sub, right, children }: { title?: string; sub?: string; right?: ReactNode; children: ReactNode }) {
  return (
    <div className="card-shadow rounded-[10px] border border-line bg-surface p-4">
      {(title || right) && (
        <div className="mb-3 flex items-start justify-between gap-3">
          <div>
            {title && <h3 className="text-sm font-semibold text-ink">{title}</h3>}
            {sub && <p className="mt-0.5 text-xs text-ink3">{sub}</p>}
          </div>
          {right}
        </div>
      )}
      {children}
    </div>
  );
}

export function Badge({ value, kind = "status" }: { value?: string; kind?: "sev" | "status" }) {
  const cls = kind === "sev" ? sevColor(value) : statusColor(value);
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold tracking-wide ${cls}`}>
      {String(value ?? "—").replace(/_/g, " ")}
    </span>
  );
}

/** Muted indigo badge — reserved for AI-originated content only. */
export function AiBadge({ value }: { value?: string }) {
  return (
    <span className="inline-flex items-center rounded-md border border-ai/30 bg-aibg px-2 py-0.5 text-[11px] font-semibold text-ai">
      {value ?? "AI Suggested"}
    </span>
  );
}

/** Muted teal badge — reserved for PQC content only. */
export function PqcBadge({ value }: { value?: string }) {
  return (
    <span className="inline-flex items-center rounded-md border border-pqc/30 bg-pqcbg px-2 py-0.5 text-[11px] font-semibold text-pqc">
      {String(value ?? "—").replace(/_/g, " ")}
    </span>
  );
}

export function Loader({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="card-shadow flex items-center gap-3 rounded-[10px] border border-line bg-surface p-6 text-sm text-ink2">
      <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-linestrong border-t-primary" />
      {label}
    </div>
  );
}

export function Empty({ label = "No data found." }: { label?: string }) {
  return (
    <div className="rounded-[10px] border border-dashed border-linestrong bg-surface2 p-6 text-center text-sm text-ink3">
      {label}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="rounded-[10px] border border-danger/30 bg-dangerbg p-6 text-sm text-danger">
      <p className="font-semibold">Unable to load data.</p>
      <p className="mt-1 opacity-90">{message}</p>
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

export function PageHeader({ title, sub, actions }: { title: string; sub?: string; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-2xl font-semibold text-ink">{title}</h1>
        {sub && <p className="mt-1 text-sm text-ink3">{sub}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block text-xs font-medium text-ink2">
      <span className="mb-1 block uppercase tracking-wider text-ink3">{label}</span>
      {children}
    </label>
  );
}

export const inputCls =
  "w-full rounded-lg border border-linestrong bg-surface px-3 py-2 text-sm text-ink placeholder:text-ink3/70 outline-none focus:border-primary focus:ring-1 focus:ring-primary";

export const btnPrimary =
  "rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-onprimary hover:bg-primaryhover disabled:opacity-50";
export const btnGhost =
  "rounded-lg border border-linestrong bg-surface px-4 py-2 text-sm font-semibold text-ink2 hover:bg-surface2 disabled:opacity-50";
