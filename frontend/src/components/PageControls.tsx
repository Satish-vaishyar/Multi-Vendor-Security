import { btnGhost } from "./common";

/** Server-side pagination footer: Prev / "Page X of Y · N total" / Next. */
export function PageControls({ page, pageSize, total, onPage }: {
  page: number; pageSize: number; total: number; onPage: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)));
  return (
    <div className="mt-4 flex items-center gap-2 text-xs text-ink3">
      <button className={btnGhost} disabled={page <= 1} onClick={() => onPage(page - 1)}>Prev</button>
      <span>Page {page} of {pages} · {total} total</span>
      <button className={btnGhost} disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
    </div>
  );
}
