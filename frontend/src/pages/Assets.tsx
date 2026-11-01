import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { useAuth } from "../stores/auth";
import { hasRole } from "../utils/roles";
import { deleteAsset, listAssets, mergeDuplicateAssets } from "../api/assets.api";
import { toMessage } from "../api/client";
import { PageControls } from "../components/PageControls";
import { Badge, Card, Empty, ErrorState, Loader, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";

export default function Assets() {
  const [sp] = useSearchParams();
  const role = useAuth((s) => s.user?.role);
  const canUpload = hasRole(role, "AUDITOR");
  const isAdmin = hasRole(role, "ADMIN");
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const [vendor, setVendor] = useState("");
  // Deleted rows stay in the DB (soft-delete) — hide them by default.
  const [status, setStatus] = useState("ACTIVE");
  const [notice, setNotice] = useState("");
  // Pre-fill from the header global search (?q=).
  const [q, setQ] = useState(sp.get("q") ?? "");
  const query = useQuery({
    queryKey: ["assets", page, vendor, status, q],
    queryFn: () => listAssets({ page, page_size: 20, vendor, status, q }),
  });

  const del = useMutation({
    mutationFn: (id: string) => deleteAsset(id),
    onSuccess: () => { setNotice(""); qc.invalidateQueries({ queryKey: ["assets"] }); },
    onError: (e) => setNotice(toMessage(e)),
  });

  const merge = useMutation({
    mutationFn: mergeDuplicateAssets,
    onSuccess: (d) => {
      setNotice(d.total_merged
        ? `Merged ${d.total_merged} redundant asset${d.total_merged > 1 ? "s" : ""} into their originals (configurations, audits and findings re-pointed).`
        : "No duplicate devices found. Every active device is already unique.");
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
    onError: (e) => setNotice(toMessage(e)),
  });

  return (
    <div>
      <PageHeader
        title="Devices"
        sub="The routers, firewalls and switches you audit. Open one to see its history, configurations and findings."
        actions={<>
          {isAdmin && (
            <button className={btnGhost} disabled={merge.isPending} onClick={() => merge.mutate()}>
              {merge.isPending ? "Merging…" : "Merge duplicates"}
            </button>
          )}
          {canUpload && <Link to="/quick-audit" className={btnPrimary}>Upload & audit</Link>}
        </>}
      />
      <Card>
        <div className="mb-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          <input className={inputCls} aria-label="Search devices" placeholder="Search name, vendor or product…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
          <input className={inputCls} aria-label="Filter by vendor" placeholder="Vendor (e.g. Cisco)" value={vendor} onChange={(e) => { setVendor(e.target.value); setPage(1); }} />
          <select className={inputCls} aria-label="Filter by status" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
            <option value="ACTIVE">Active</option>
            <option value="">All statuses</option>
            <option value="DELETED">Deleted</option>
          </select>
        </div>
        {notice && <p className="mb-3 rounded-lg border border-line bg-surface2 p-2.5 text-xs text-ink2">{notice}</p>}
        {query.isLoading ? <Loader label="Loading devices…" rows={6} /> :
          query.isError ? <ErrorState message="Unable to load devices." onRetry={() => query.refetch()} /> :
            !(query.data?.items?.length) ? <Empty label={q || vendor ? "No devices match these filters." : "No devices yet."} hint={q || vendor ? "Try clearing the search or vendor filter." : "Upload a configuration file and the device is created for you."} action={canUpload && !q && !vendor ? <><Link to="/quick-audit" className={btnPrimary}>Upload & audit</Link><Link to="/quick-audit?sample=1" className={btnGhost}>Try a sample</Link></> : undefined} /> : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr className="border-b border-line text-xs uppercase text-ink3">
                        <th className="py-2 pr-3 font-medium">Device</th><th className="py-2 pr-3 font-medium">Vendor</th>
                        <th className="py-2 pr-3 font-medium">Product</th><th className="py-2 pr-3 font-medium">Version</th>
                        <th className="py-2 pr-3 font-medium">Criticality</th><th className="py-2 pr-3 font-medium">Status</th>
                        <th className="py-2 pr-3 font-medium"><span className="sr-only">Actions</span></th>
                      </tr>
                    </thead>
                    <tbody>
                      {(query.data?.items ?? []).map((a) => (
                        <tr key={a.asset_id} className="border-b border-line/60 hover:bg-surface2">
                          <td className="py-2 pr-3"><Link to={`/assets/${a.asset_id}`} className="font-semibold text-primary hover:underline">{a.name}</Link>
                            <span className="block font-mono text-[11px] text-ink3">{a.asset_id}</span></td>
                          <td className="py-2 pr-3 text-ink2">{String(a.vendor ?? "—")}</td>
                          <td className="py-2 pr-3 text-ink2">{String(a.product ?? "—")}</td>
                          <td className="py-2 pr-3 text-ink2">{String(a.version ?? "—")}</td>
                          <td className="py-2 pr-3"><Badge value={String(a.criticality ?? "—")} kind="sev" /></td>
                          <td className="py-2 pr-3"><Badge value={String(a.status ?? "—")} /></td>
                          <td className="py-2 pr-3 text-right">
                            {String(a.status ?? "").toUpperCase() !== "DELETED" && (
                              <button
                                className="rounded-lg border border-danger/40 px-2.5 py-1 text-xs font-semibold text-danger hover:bg-dangerbg disabled:opacity-50"
                                disabled={del.isPending}
                                onClick={() => { if (window.confirm(`Delete device ${a.name} (${a.asset_id})? Configurations and audits are kept.`)) del.mutate(a.asset_id); }}
                              >Delete</button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <PageControls page={query.data?.page ?? page} pageSize={query.data?.page_size ?? 20} total={query.data?.total ?? 0} onPage={setPage} />
              </>
            )}
      </Card>
    </div>
  );
}
