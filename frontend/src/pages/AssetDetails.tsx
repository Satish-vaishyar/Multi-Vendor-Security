import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { getAsset } from "../api/assets.api";
import { listFindings } from "../api/findings.api";
import { Badge, Card, ErrorState, Loader, PageHeader } from "../components/common";

export default function AssetDetails() {
  const { assetId = "" } = useParams();
  const a = useQuery({ queryKey: ["asset", assetId], queryFn: () => getAsset(assetId) });
  const f = useQuery({ queryKey: ["findings", "asset", assetId], queryFn: () => listFindings({ asset_id: assetId }) });

  if (a.isLoading) return <Loader />;
  if (a.isError || !a.data) return <ErrorState message="Asset not found. It may have been deleted." />;
  const asset = a.data;
  const rows: [string, string][] = [
    ["Vendor", String(asset.vendor ?? "—")],
    ["Product", String(asset.product ?? "—")],
    ["Platform", String(asset.model ?? "—")],
    ["Version", String(asset.version ?? "—")],
    ["IP", String(asset.ip_address ?? "—")],
    ["Environment", String(asset.environment ?? "—")],
    ["Criticality", String(asset.criticality ?? "—")],
    ["Status", String(asset.status ?? "—")],
  ];

  return (
    <div>
      <PageHeader title={asset.name} sub={`Asset ${asset.asset_id}`} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Asset Information">
          <dl className="grid grid-cols-2 gap-2 text-sm">
            {rows.map(([k, v]) => (
              <div key={k} className="rounded-lg bg-surface2 p-2.5">
                <dt className="text-[11px] uppercase tracking-wider text-ink3">{k}</dt>
                <dd className="mt-0.5 text-ink">{v}</dd>
              </div>
            ))}
          </dl>
        </Card>
        <Card title="Findings" sub="Linked to this asset">
          {f.isLoading ? <Loader label="Loading findings…" /> :
            !f.data?.items.length ? <p className="text-sm text-ink3">No findings for this asset yet.</p> : (
              <ul className="space-y-2 text-sm">
                {(f.data?.items ?? []).slice(0, 10).map((x) => (
                  <li key={x.finding_id} className="flex items-center justify-between gap-2 rounded-lg bg-surface2 p-2.5">
                    <Link to={`/findings/${x.finding_id}`} className="truncate text-primary hover:underline">
                      {x.title ?? x.finding_id}
                    </Link>
                    <Badge value={String(x.severity ?? "?")} kind="sev" />
                  </li>
                ))}
              </ul>
            )}
        </Card>
      </div>
    </div>
  );
}
