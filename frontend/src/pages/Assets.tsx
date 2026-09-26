import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { listAssets } from "../api/assets.api";
import { Badge, Card, Empty, ErrorState, Loader, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";

export default function Assets() {
  const [sp] = useSearchParams();
  const [page, setPage] = useState(1);
  const [vendor, setVendor] = useState("");
  const [status, setStatus] = useState("");
  // Pre-fill from the header global search (?q=).
  const [q, setQ] = useState(sp.get("q") ?? "");
  const query = useQuery({
    queryKey: ["assets", page, vendor, status, q],
    queryFn: () => listAssets({ page, page_size: 20, vendor, status, q }),
  });

  return (
    <div>
      <PageHeader title="Assets" sub="Network devices under audit" />
      <Card>
        <div className="mb-4 grid gap-2 md:grid-cols-4">
          <input className={inputCls} placeholder="Search name / vendor / product…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
          <input className={inputCls} placeholder="Vendor filter (e.g. Cisco)" value={vendor} onChange={(e) => { setVendor(e.target.value); setPage(1); }} />
          <select className={inputCls} value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
            <option value="">All statuses</option>
            <option value="ACTIVE">Active</option>
            <option value="DELETED">Deleted</option>
          </select>
          <Link to="/configurations/upload" className={`${btnPrimary} text-center`}>Add via Upload</Link>
        </div>
        {query.isLoading ? <Loader /> :
          query.isError ? <ErrorState message="Unable to load assets." onRetry={() => query.refetch()} /> :
            !(query.data?.items?.length) ? <Empty label="No assets found." /> : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr className="border-b border-line text-xs uppercase text-ink3">
                        <th className="py-2 pr-3 font-medium">Asset</th><th className="py-2 pr-3 font-medium">Vendor</th>
                        <th className="py-2 pr-3 font-medium">Product</th><th className="py-2 pr-3 font-medium">Version</th>
                        <th className="py-2 pr-3 font-medium">Criticality</th><th className="py-2 pr-3 font-medium">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(query.data?.items ?? []).map((a) => (
                        <tr key={a.asset_id} className="border-b border-line/60 hover:bg-surface2">
                          <td className="py-2 pr-3"><Link to={`/assets/${a.asset_id}`} className="font-semibold text-primary hover:underline">{a.name}</Link>
                            <span className="block text-[11px] text-ink3">{a.asset_id}</span></td>
                          <td className="py-2 pr-3 text-ink2">{String(a.vendor ?? "—")}</td>
                          <td className="py-2 pr-3 text-ink2">{String(a.product ?? "—")}</td>
                          <td className="py-2 pr-3 text-ink2">{String(a.version ?? "—")}</td>
                          <td className="py-2 pr-3"><Badge value={String(a.criticality ?? "—")} kind="sev" /></td>
                          <td className="py-2 pr-3"><Badge value={String(a.status ?? "—")} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="mt-4 flex items-center gap-2 text-xs text-ink3">
                  <button className={btnGhost} disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Prev</button>
                  <span>Page {query.data?.page} · {query.data?.total} total</span>
                  <button className={btnGhost} disabled={(query.data?.items?.length ?? 0) < (query.data?.page_size ?? 20)} onClick={() => setPage((p) => p + 1)}>Next</button>
                </div>
              </>
            )}
      </Card>
    </div>
  );
}
