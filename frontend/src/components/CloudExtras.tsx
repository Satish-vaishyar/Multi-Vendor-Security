/* Opt-in extras for one cloud scan (RTM S23): a kept file + recurring scans, notifications through an existing webhook, and a link
   to an existing asset. Nothing here is on by default; every control only appears for a role allowed to use it. */
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createCloudSchedule, deleteCloudSchedule, deleteKeptFile, getKeptFile, linkCloudWebhook, linkScanAsset, listCloudSchedules,
  listCloudWebhookLinks, listExistingWebhooks, listScanAssets, patchCloudSchedule, runCloudSchedule, unlinkCloudWebhook, unlinkScanAsset,
} from "../api/cloud.api";
import { listAssets } from "../api/assets.api";
import { toMessage } from "../api/client";
import { Badge, Card, Empty, Loader, Notice, btnGhost, btnPrimary, inputCls } from "./common";

const INTERVALS = [{ label: "Every hour", minutes: 60 }, { label: "Every 6 hours", minutes: 360 }, { label: "Daily", minutes: 1440 }, { label: "Weekly", minutes: 10080 }];
const label = (m: number) => INTERVALS.find((i) => i.minutes === m)?.label ?? `Every ${m} minutes`;
const when = (t: number | null) => (t ? new Date(t * 1000).toLocaleString() : "never");

export default function CloudExtras({ scanId, canChange, isAdmin }: { scanId: string; canChange: boolean; isAdmin: boolean }) {
  const qc = useQueryClient();
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [minutes, setMinutes] = useState(1440);
  const [hook, setHook] = useState("");
  const [asset, setAsset] = useState("");
  const done = (m = "") => (_: unknown) => { setErr(""); setMsg(m); void qc.invalidateQueries({ queryKey: ["cloud-extras"] }); };
  const fail = (e: unknown) => { setMsg(""); setErr(toMessage(e)); };

  const kept = useQuery({ queryKey: ["cloud-extras", "kept", scanId], queryFn: () => getKeptFile(scanId) });
  const schedules = useQuery({ queryKey: ["cloud-extras", "schedules"], queryFn: listCloudSchedules });
  const links = useQuery({ queryKey: ["cloud-extras", "hooks"], queryFn: listCloudWebhookLinks });
  const hooks = useQuery({ queryKey: ["cloud-extras", "all-hooks"], queryFn: listExistingWebhooks, enabled: isAdmin });
  const assets = useQuery({ queryKey: ["cloud-extras", "scan-assets", scanId], queryFn: () => listScanAssets(scanId) });
  const allAssets = useQuery({ queryKey: ["cloud-extras", "all-assets"], queryFn: () => listAssets({ page_size: 100 }), enabled: canChange });

  const create = useMutation({ mutationFn: () => createCloudSchedule({ scan_id: scanId, interval_minutes: minutes }), onSuccess: done("Recurring scan created."), onError: fail });
  const toggle = useMutation({ mutationFn: (s: { id: string; enabled: boolean }) => patchCloudSchedule(s.id, { enabled: s.enabled }), onSuccess: done(), onError: fail });
  const runNow = useMutation({ mutationFn: (id: string) => runCloudSchedule(id), onSuccess: (r) => { done(`Run finished: ${r.status}.`)(r); void qc.invalidateQueries({ queryKey: ["cloud", "scans"] }); }, onError: fail });
  const remove = useMutation({ mutationFn: (id: string) => deleteCloudSchedule(id), onSuccess: done("Recurring scan deleted."), onError: fail });
  const dropFile = useMutation({ mutationFn: () => deleteKeptFile(scanId), onSuccess: done("Kept file and its recurring scans deleted."), onError: fail });
  const link = useMutation({ mutationFn: () => linkCloudWebhook(hook, ["cloud.scan.completed", "cloud.scan.failed"]), onSuccess: done("Notifications turned on."), onError: fail });
  const unlink = useMutation({ mutationFn: (id: string) => unlinkCloudWebhook(id), onSuccess: done("Notifications turned off."), onError: fail });
  const addAsset = useMutation({ mutationFn: () => linkScanAsset(scanId, asset), onSuccess: done("Linked to the asset."), onError: fail });
  const removeAsset = useMutation({ mutationFn: (id: string) => unlinkScanAsset(scanId, id), onSuccess: done(), onError: fail });

  const mine = (schedules.data?.items ?? []).filter((s) => s.scan_id === scanId);
  const linked = new Set((links.data?.items ?? []).map((l) => l.webhook_id));
  const linkable = (hooks.data?.items ?? []).filter((h) => h.format === "json" && !linked.has(h.webhook_id));

  return (
    <Card title="Recurring scans, notifications and assets" sub="All optional. Nothing is kept, sent or linked unless you turn it on here.">
      {err && <Notice kind="error">{err}</Notice>}
      {msg && <Notice kind="ok">{msg}</Notice>}

      <h3 className="mt-2 text-sm font-semibold">Recurring scan</h3>
      {kept.isLoading ? <Loader rows={1} /> : !kept.data?.kept ? (
        <p className="text-xs text-ink2">
          This scan has no kept file. To scan a file again on a schedule, upload it with “Keep this file for recurring scans” selected
          (not possible for files that contain a hard-coded secret).
        </p>
      ) : (
        <div className="space-y-2">
          <p className="text-xs text-ink2">
            An encrypted copy of this file is kept until {kept.data.expires_at ? new Date(kept.data.expires_at).toLocaleDateString() : "it expires"}.
            It is re-scanned in the same isolated scanner; nothing is deployed.
          </p>
          {canChange && (
            <div className="flex flex-wrap items-center gap-2">
              <select aria-label="Interval" className={`${inputCls} max-w-48`} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
                {INTERVALS.map((i) => <option key={i.minutes} value={i.minutes}>{i.label}</option>)}
              </select>
              <button className={btnPrimary} disabled={create.isPending} onClick={() => create.mutate()}>Add recurring scan</button>
              <button className={btnGhost} disabled={dropFile.isPending} onClick={() => dropFile.mutate()}>Delete kept file</button>
            </div>
          )}
          {mine.length === 0 ? <Empty label="No recurring scans for this file." /> : (
            <ul className="divide-y divide-line">
              {mine.map((s) => (
                <li key={s.schedule_id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
                  <span>{s.name} · {label(s.interval_minutes)} <Badge value={s.enabled ? "ENABLED" : "PAUSED"} />
                    <span className="block text-xs text-ink2">Next: {when(s.next_run_at)} · Last: {when(s.last_run_at)} {s.last_status ?? ""}</span>
                  </span>
                  {canChange && (
                    <span className="flex gap-2">
                      <button className={btnGhost} onClick={() => runNow.mutate(s.schedule_id)} disabled={runNow.isPending}>Run now</button>
                      <button className={btnGhost} onClick={() => toggle.mutate({ id: s.schedule_id, enabled: !s.enabled })}>{s.enabled ? "Pause" : "Resume"}</button>
                      <button className={btnGhost} onClick={() => remove.mutate(s.schedule_id)}>Delete</button>
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <h3 className="mt-5 text-sm font-semibold">Notifications</h3>
      <p className="text-xs text-ink2">
        Sends “cloud.scan.completed” and “cloud.scan.failed” (scan id, file name and counts only; never file content) to a webhook you already
        created under Integrations. Only webhooks in the JSON format can be used.
      </p>
      <ul className="divide-y divide-line">
        {(links.data?.items ?? []).map((l) => (
          <li key={l.webhook_id} className="flex items-center justify-between py-2 text-sm">
            <span>{l.name} <Badge value={l.enabled ? "ENABLED" : "DISABLED"} /></span>
            {isAdmin && <button className={btnGhost} onClick={() => unlink.mutate(l.webhook_id)}>Turn off</button>}
          </li>
        ))}
      </ul>
      {isAdmin && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <select aria-label="Webhook" className={`${inputCls} max-w-64`} value={hook} onChange={(e) => setHook(e.target.value)}>
            <option value="">Choose a webhook…</option>
            {linkable.map((h) => <option key={h.webhook_id} value={h.webhook_id}>{h.name}</option>)}
          </select>
          <button className={btnPrimary} disabled={!hook || link.isPending} onClick={() => link.mutate()}>Turn on</button>
        </div>
      )}
      {!isAdmin && (links.data?.items.length ?? 0) === 0 && <p className="text-xs text-ink2">An administrator can turn notifications on.</p>}

      <h3 className="mt-5 text-sm font-semibold">Linked assets</h3>
      <p className="text-xs text-ink2">Associates this scan with an existing asset so it is easy to find. The asset itself is never changed.</p>
      <ul className="divide-y divide-line">
        {(assets.data?.items ?? []).map((a) => (
          <li key={a.asset_id} className="flex items-center justify-between py-2 text-sm">
            <span>{a.asset_name}</span>
            {canChange && <button className={btnGhost} onClick={() => removeAsset.mutate(a.asset_id)}>Unlink</button>}
          </li>
        ))}
      </ul>
      {canChange && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <select aria-label="Asset" className={`${inputCls} max-w-64`} value={asset} onChange={(e) => setAsset(e.target.value)}>
            <option value="">Choose an asset…</option>
            {(allAssets.data?.items ?? []).map((a) => <option key={a.asset_id} value={a.asset_id}>{a.name}</option>)}
          </select>
          <button className={btnPrimary} disabled={!asset || addAsset.isPending} onClick={() => addAsset.mutate()}>Link</button>
        </div>
      )}
    </Card>
  );
}
