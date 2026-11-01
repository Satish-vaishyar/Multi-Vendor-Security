import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Search, Server, type LucideIcon } from "lucide-react";
import { listAssets } from "../../api/assets.api";
import { useAuth } from "../../stores/auth";
import { visibleGroups } from "./nav";

interface Result { key: string; label: string; desc: string; to: string; icon: LucideIcon; group: string }

/** Ctrl/Cmd+K quick search: jump to any page the role can use, or to a device by name. */
export default function CommandPalette({ onClose }: { onClose: () => void }) {
  const nav = useNavigate();
  const role = useAuth((s) => s.user?.role);
  const [q, setQ] = useState("");
  const [dq, setDq] = useState("");
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  useEffect(() => { input.current?.focus(); }, []);
  useEffect(() => {
    const t = setTimeout(() => setDq(q.trim()), 200);
    return () => clearTimeout(t);
  }, [q]);

  const pages: Result[] = useMemo(
    () => visibleGroups(role).flatMap((g) => g.items.map((i) => ({
      key: i.to, label: i.label, desc: i.desc, to: i.to, icon: i.icon, group: g.label,
      hay: `${i.label} ${i.desc} ${i.keywords ?? ""} ${g.label}`.toLowerCase(),
    }))),
    [role],
  ) as (Result & { hay: string })[];

  const assets = useQuery({
    queryKey: ["palette-assets", dq],
    queryFn: () => listAssets({ q: dq, page_size: 6, status: "ACTIVE" }),
    enabled: dq.length >= 2,
    staleTime: 30000,
  });

  const results: Result[] = useMemo(() => {
    const needle = q.trim().toLowerCase();
    // Name matches first ("risk" -> Risk acceptance before pages that merely mention risk in their description).
    const rank = (r: Result) => (r.label.toLowerCase().startsWith(needle) ? 0 : r.label.toLowerCase().includes(needle) ? 1 : 2);
    const p = needle
      ? (pages as (Result & { hay: string })[]).filter((r) => needle.split(/\s+/).every((w) => r.hay.includes(w))).sort((a, b) => rank(a) - rank(b))
      : pages;
    const a: Result[] = (assets.data?.items ?? []).map((x) => ({
      key: `asset-${x.asset_id}`, label: x.name, desc: [x.vendor, x.product, x.asset_id].filter(Boolean).join(" · "),
      to: `/assets/${x.asset_id}`, icon: Server, group: "Devices",
    }));
    return [...p.slice(0, 12), ...a];
  }, [q, pages, assets.data]);

  useEffect(() => {
    (listRef.current?.children[active] as HTMLElement | undefined)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const go = (r?: Result) => {
    if (!r) return;
    onClose();
    nav(r.to);
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") { e.preventDefault(); onClose(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); setActive((i) => Math.min(i + 1, results.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((i) => Math.max(i - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); go(results[active]); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 pt-[10vh]" role="dialog" aria-modal="true" aria-label="Quick search" onKeyDown={onKey}>
      <div className="absolute inset-0 bg-ink/40" onClick={onClose} aria-hidden="true" />
      <div className="relative w-full max-w-xl overflow-hidden rounded-xl border border-line bg-surface shadow-[var(--shadow-pop)]">
        <div className="flex items-center gap-2 border-b border-line px-4">
          <Search size={16} className="text-ink3" aria-hidden="true" />
          <input
            ref={input}
            value={q}
            onChange={(e) => { setQ(e.target.value); setActive(0); }}
            placeholder="Search pages and devices…"
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={results[active] ? `pal-${results[active].key}` : undefined}
            className="w-full bg-transparent py-3.5 text-sm text-ink outline-none placeholder:text-ink3"
          />
          <kbd className="rounded border border-line px-1.5 text-[10px] text-ink3">Esc</kbd>
        </div>
        <ul id="palette-list" ref={listRef} role="listbox" className="max-h-[50vh] overflow-y-auto p-2">
          {results.length === 0 && <li className="px-3 py-6 text-center text-sm text-ink3">{assets.isFetching ? "Searching…" : "Nothing matches. Try a page name or a device name."}</li>}
          {results.map((r, i) => (
            <li
              key={r.key}
              id={`pal-${r.key}`}
              role="option"
              aria-selected={i === active}
              onMouseMove={() => setActive(i)}
              onClick={() => go(r)}
              className={`flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 ${i === active ? "bg-primarylight" : ""}`}
            >
              <r.icon size={16} className={i === active ? "text-primary" : "text-ink3"} aria-hidden="true" />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-medium text-ink">{r.label}</span>
                <span className="block truncate text-xs text-ink3">{r.desc}</span>
              </span>
              <span className="shrink-0 text-[10px] uppercase tracking-wider text-ink3">{r.group}</span>
            </li>
          ))}
        </ul>
        <p className="hidden border-t border-line px-4 py-2 text-[11px] text-ink3 sm:block">Arrow keys to move, Enter to open, Esc to close.</p>
      </div>
    </div>
  );
}
