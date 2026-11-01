import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { collectNow, createCredential, getTarget, listCredentials, listProfiles, saveTarget, scanHostKey } from "../api/collection.api";
import { toMessage } from "../api/client";
import { useAuth } from "../stores/auth";
import { hasRole } from "../utils/roles";
import { Badge, Card, Field, Loader, Notice, btnGhost, btnPrimary, inputCls } from "./common";

/** Read-only live collection for one device. Administrators configure the target (host, credential, pinned host key);
 *  auditors can run it. The device is only ever sent allow-listed show commands (docs/COLLECTION.md). */
export default function CollectionCard({ assetId }: { assetId: string }) {
  const qc = useQueryClient();
  const role = useAuth((s) => s.user?.role);
  const isAdmin = hasRole(role, "ADMIN");
  const canRun = hasRole(role, "AUDITOR");
  const target = useQuery({ queryKey: ["collection", assetId], queryFn: () => getTarget(assetId) });
  const profiles = useQuery({ queryKey: ["collection-profiles"], queryFn: listProfiles });
  const creds = useQuery({ queryKey: ["collection-creds"], queryFn: listCredentials, enabled: isAdmin });
  const [f, setF] = useState({ host: "", port: 22, profile: "cisco_ios", credential_id: "", host_key: "" });
  const [newCred, setNewCred] = useState({ name: "", username: "", secret: "", auth_type: "password" });
  const [msg, setMsg] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [editing, setEditing] = useState(false);

  useEffect(() => {
    const t = target.data;
    if (t) setF({ host: t.host, port: t.port, profile: t.profile, credential_id: t.credential_id ?? "", host_key: t.host_key });
  }, [target.data]);

  const done = (text: string) => { setMsg({ kind: "ok", text }); void qc.invalidateQueries({ queryKey: ["collection", assetId] }); };
  const fail = (e: unknown) => setMsg({ kind: "error", text: toMessage(e) });
  const scan = useMutation({
    mutationFn: () => scanHostKey(assetId, f.host, f.port),
    onSuccess: (r) => { setF((p) => ({ ...p, host_key: r.fingerprint })); setMsg({ kind: "ok", text: "Host key fetched. Compare it with the device before saving." }); },
    onError: fail,
  });
  const save = useMutation({
    mutationFn: () => saveTarget(assetId, { ...f, credential_id: f.credential_id || null }),
    onSuccess: () => { setEditing(false); done("Collection target saved."); },
    onError: fail,
  });
  const run = useMutation({
    mutationFn: () => collectNow(assetId, true),
    onSuccess: (r) => done(`Collection queued (job ${r.job_id}). Follow it on the Jobs page.`),
    onError: fail,
  });
  const addCred = useMutation({
    mutationFn: () => createCredential(newCred),
    onSuccess: (c) => { setNewCred({ name: "", username: "", secret: "", auth_type: "password" }); setF((p) => ({ ...p, credential_id: c.credential_id })); void qc.invalidateQueries({ queryKey: ["collection-creds"] }); setMsg({ kind: "ok", text: "Credential stored encrypted; it cannot be read back." }); },
    onError: fail,
  });

  if (target.isLoading) return <Card title="Live collection"><Loader /></Card>;
  const t = target.data;
  const ready = !!(t && t.credential_id && t.host_key);
  const showForm = isAdmin && (editing || !t);

  return (
    <Card title="Live collection" sub="Pull the running configuration over read-only SSH (only show commands are sent)">
      {msg && <div className="mb-3"><Notice kind={msg.kind}>{msg.text}</Notice></div>}
      {t && !showForm && (
        <div className="space-y-2 text-sm">
          <p className="text-ink2"><span className="font-mono text-ink">{t.host}:{t.port}</span> · {profiles.data?.find((p) => p.key === t.profile)?.label ?? t.profile}</p>
          <p className="break-all font-mono text-xs text-ink3">Pinned host key {t.host_key || "- none"}</p>
          <p className="text-xs text-ink3">
            {t.last_status ? <><Badge value={t.last_status === "OK" ? "PASS" : "FAIL"} /> {t.last_status === "OK" ? "last collected " + (t.last_collected_at ?? "").slice(0, 16).replace("T", " ") : t.last_error}</> : "Never collected."}
          </p>
          <div className="flex flex-wrap gap-2">
            {canRun && <button className={btnPrimary} disabled={!ready || run.isPending} onClick={() => run.mutate()}>{run.isPending ? "Queuing…" : "Collect & audit now"}</button>}
            {isAdmin && <button className={btnGhost} onClick={() => setEditing(true)}>Edit target</button>}
            <Link to="/jobs" className={btnGhost}>Jobs</Link>
          </div>
        </div>
      )}
      {!t && !isAdmin && <p className="text-sm text-ink3">Live collection is not set up for this device. An administrator can configure it.</p>}
      {showForm && (
        <form className="grid gap-3 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <Field label="Host / address"><input className={inputCls} value={f.host} onChange={(e) => setF({ ...f, host: e.target.value })} required /></Field>
          <Field label="SSH port"><input className={inputCls} type="number" min={1} max={65535} value={f.port} onChange={(e) => setF({ ...f, port: Number(e.target.value) })} /></Field>
          <Field label="Platform">
            <select className={inputCls} value={f.profile} onChange={(e) => setF({ ...f, profile: e.target.value })}>
              {(profiles.data ?? []).map((p) => <option key={p.key} value={p.key}>{p.label}</option>)}
            </select>
          </Field>
          <Field label="Credential (read-only account)">
            <select className={inputCls} value={f.credential_id} onChange={(e) => setF({ ...f, credential_id: e.target.value })} required>
              <option value="">Select…</option>
              {(creds.data?.items ?? []).map((c) => <option key={c.credential_id} value={c.credential_id}>{c.name} ({c.username})</option>)}
            </select>
          </Field>
          <div className="sm:col-span-2">
            <Field label="Pinned host key (SHA256 fingerprint)">
              <div className="flex gap-2">
                <input className={`${inputCls} font-mono`} value={f.host_key} onChange={(e) => setF({ ...f, host_key: e.target.value })} required minLength={10} />
                <button type="button" className={btnGhost} disabled={!f.host || scan.isPending} onClick={() => scan.mutate()}>{scan.isPending ? "Scanning…" : "Scan"}</button>
              </div>
            </Field>
            <p className="mt-1 text-[11px] text-ink3">Confirm this fingerprint on the device (for example <code>show ip ssh</code>) before saving. A credential is only ever sent to a host whose key matches.</p>
          </div>
          <div className="flex gap-2 sm:col-span-2">
            <button className={btnPrimary} disabled={save.isPending}>{save.isPending ? "Saving…" : "Save target"}</button>
            {t && <button type="button" className={btnGhost} onClick={() => setEditing(false)}>Cancel</button>}
          </div>
          <details className="rounded-lg border border-line p-3 sm:col-span-2">
            <summary className="cursor-pointer text-sm text-ink2">Add a credential</summary>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <Field label="Name"><input className={inputCls} value={newCred.name} onChange={(e) => setNewCred({ ...newCred, name: e.target.value })} /></Field>
              <Field label="Username"><input className={inputCls} value={newCred.username} onChange={(e) => setNewCred({ ...newCred, username: e.target.value })} autoComplete="off" /></Field>
              <Field label="Type">
                <select className={inputCls} value={newCred.auth_type} onChange={(e) => setNewCred({ ...newCred, auth_type: e.target.value })}>
                  <option value="password">Password</option><option value="key">Private key (PEM)</option>
                </select>
              </Field>
              <Field label={newCred.auth_type === "key" ? "Private key" : "Password"}>
                <input className={inputCls} type="password" value={newCred.secret} onChange={(e) => setNewCred({ ...newCred, secret: e.target.value })} autoComplete="new-password" />
              </Field>
              <div className="sm:col-span-2">
                <button type="button" className={btnGhost} disabled={addCred.isPending || !newCred.name || !newCred.username || !newCred.secret} onClick={() => addCred.mutate()}>Store credential</button>
              </div>
            </div>
          </details>
        </form>
      )}
    </Card>
  );
}
