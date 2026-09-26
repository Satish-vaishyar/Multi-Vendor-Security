import { useState, type ReactNode } from "react";
import { ChevronDown, ChevronUp, Search } from "lucide-react";
import type { AuditOverview } from "../hooks/useAuditOverviews";
import { Badge, Card, Empty, ErrorState, Loader } from "./common";

interface Props {
  overviews: AuditOverview[];
  isLoading: boolean;
  isError: boolean;
  onRetry: () => void;
  value: string;
  onSelect: (id: string) => void;
  /** one-line brief of this route's work inside the audit */
  renderBrief: (a: AuditOverview) => ReactNode;
  title?: string;
  sub?: string;
}

/** Searchable audit list — each row shows the audit id + route brief, click loads detail. */
export function AuditPicker({
  overviews, isLoading, isError, onRetry, value, onSelect, renderBrief,
  title = "Select Audit", sub = "Search by audit ID, then click an audit to inspect it.",
}: Props) {
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(true);
  const filtered = (overviews ?? []).filter((a) =>
    a.audit_id.toLowerCase().includes(q.trim().toLowerCase()),
  );
  const sel = (overviews ?? []).find((a) => a.audit_id === value);

  return (
    <Card
      title={title}
      sub={value && sel ? `Showing ${value} — change selection below` : sub}
      right={
        <button
          onClick={() => setOpen((o) => !o)}
          className="flex items-center gap-1 rounded-lg border border-linestrong bg-surface px-2.5 py-1.5 text-xs font-semibold text-ink2 hover:bg-surface2"
        >
          {open ? <>Hide <ChevronUp size={14} /></> : <>Audits <ChevronDown size={14} /></>}
        </button>
      }
    >
      {isLoading ? <Loader label="Loading audits…" /> :
        isError ? <ErrorState message="Unable to list audits." onRetry={onRetry} /> :
          !overviews.length ? <Empty label="No audits yet. Upload a configuration and start an audit." /> :
            open ? (
              <>
                <div className="relative mb-3">
                  <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink3" />
                  <input
                    value={q}
                    onChange={(e) => setQ(e.target.value)}
                    placeholder="Search audit by ID (e.g. AUD-…)"
                    className="w-full rounded-lg border border-linestrong bg-surface py-2 pl-9 pr-3 text-sm text-ink placeholder:text-ink3/70 outline-none focus:border-primary"
                  />
                </div>
                {!filtered.length ? <Empty label={`No audits match "${q}".`} /> : (
                  <>
                    <p className="mb-2 text-xs text-ink3">{filtered.length} audit{filtered.length === 1 ? "" : "s"}</p>
                    <ul className="max-h-72 space-y-2 overflow-auto pr-0.5">
                      {filtered.map((a) => (
                        <li key={a.audit_id}>
                          <button
                            onClick={() => onSelect(a.audit_id)}
                            className={`w-full rounded-lg border p-3 text-left ${value === a.audit_id ? "border-primary bg-primarylight" : "border-line bg-surface hover:bg-surface2"}`}
                          >
                            <span className="flex flex-wrap items-center justify-between gap-2">
                              <span className="font-mono text-sm font-semibold text-primary">{a.audit_id}</span>
                              <Badge value={a.status} />
                            </span>
                            <span className="mt-1 block text-xs text-ink2">{renderBrief(a)}</span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </>
            ) : sel ? (
              <p className="text-xs text-ink2">{renderBrief(sel)}</p>
            ) : null}
    </Card>
  );
}
