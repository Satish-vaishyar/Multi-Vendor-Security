import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { UploadCloud } from "lucide-react";
import { createAssetFull, listAssets } from "../api/assets.api";
import { bulkUpload, uploadConfiguration } from "../api/configurations.api";
import { toMessage } from "../api/client";
import { Card, Field, Notice, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";

export default function UploadConfiguration() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const [files, setFiles] = useState<File[]>([]);
  const [assetId, setAssetId] = useState("");
  const [newAsset, setNewAsset] = useState({ name: "", vendor: "", product: "", version: "", criticality: "MEDIUM" });
  const [vendor, setVendor] = useState("");
  const [platform, setPlatform] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [assetNote, setAssetNote] = useState("");
  const assets = useQuery({ queryKey: ["assets", "all"], queryFn: () => listAssets({ page: 1, page_size: 100, status: "ACTIVE" }) });

  const ensureAsset = async (): Promise<string> => {
    if (assetId) return assetId;
    if (!newAsset.name.trim()) throw new Error("Enter a name for the new asset (or pick an existing asset).");
    const res = await createAssetFull({ ...newAsset, name: newAsset.name.trim() });
    const id = res.data.asset_id as string | undefined;
    if (!id) throw new Error("Asset creation returned no id — try again.");
    setAssetNote(res.reused ? `An asset with this name already exists — reusing ${id} instead of creating a duplicate.` : "");
    // Keep the existing-asset dropdown in sync so a retry uploads against the id just created.
    setAssetId(id);
    void qc.invalidateQueries({ queryKey: ["assets", "all"] });
    return id;
  };

  const up = useMutation({
    mutationFn: async () => {
      const aid = await ensureAsset();
      if (files.length === 1) {
        return { single: await uploadConfiguration(files[0], aid, vendor, platform) };
      }
      return bulkUpload(files, aid);
    },
    onSuccess: (d) => {
      setErr("");
      const single = (d as { single?: { configuration_id?: string } }).single;
      if (single?.configuration_id) {
        setMsg(`Uploaded — detected ${(single as unknown as Record<string, string>).detected_vendor ?? "vendor"}. Opening configuration…`);
        setTimeout(() => nav(`/configurations/${single.configuration_id}`), 800);
      } else {
        setMsg("Bulk upload accepted. Open Audits to run audits per configuration.");
      }
    },
    onError: (e) => { setMsg(""); setErr(toMessage(e)); },
  });

  return (
    <div>
      <PageHeader title="Upload configuration" sub="Advanced upload: choose the device, set the vendor by hand or upload several files at once. For a single file, Upload & audit is quicker." actions={<Link to="/quick-audit" className={btnGhost}>Back to Upload &amp; audit</Link>} />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Configuration Files" sub="Supported: .txt .cfg .conf .yaml .json">
          <label
            className="flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed border-linestrong bg-surface2/50 p-8 text-center hover:border-primary focus-within:border-primary focus-within:ring-2 focus-within:ring-primary/30"
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => { e.preventDefault(); setFiles(Array.from(e.dataTransfer.files)); }}
          >
            <UploadCloud className="mb-2 text-primary" size={28} />
            <span className="text-sm text-ink2">Drag &amp; drop configuration{files.length > 1 ? "s" : ""} here</span>
            <span className="mt-2 rounded-lg border border-linestrong bg-surface px-3 py-1.5 text-xs font-semibold text-ink2">Browse files</span>
            <input data-testid="upload-file-input" type="file" multiple className="sr-only" onChange={(e) => setFiles(Array.from(e.target.files ?? []))} />
          </label>
          {files.length > 0 && (
            <ul className="mt-3 space-y-1 text-xs text-ink2">
              {files.map((f) => <li key={f.name} className="rounded-lg bg-surface2 px-3 py-1.5">{f.name} · {(f.size / 1024).toFixed(1)} KB</li>)}
            </ul>
          )}
          <div className="mt-4 grid gap-2 sm:grid-cols-2">
            <Field label="Vendor (optional — auto-detect)"><input className={inputCls} value={vendor} onChange={(e) => setVendor(e.target.value)} placeholder="Cisco" /></Field>
            <Field label="Platform (optional)"><input className={inputCls} value={platform} onChange={(e) => setPlatform(e.target.value)} placeholder="IOS-XE" /></Field>
          </div>
        </Card>

        <Card title="Target Asset" sub="Pick existing or create inline">
          <Field label="Existing asset">
            <select className={inputCls} value={assetId} onChange={(e) => setAssetId(e.target.value)}>
              <option value="">— Create new asset —</option>
              {(assets.data?.items ?? []).map((a) => <option key={a.asset_id} value={a.asset_id}>{a.name} ({a.asset_id})</option>)}
            </select>
          </Field>
          {!assetId && (
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              <Field label="Name"><input className={inputCls} value={newAsset.name} onChange={(e) => setNewAsset({ ...newAsset, name: e.target.value })} /></Field>
              <Field label="Vendor"><input className={inputCls} value={newAsset.vendor} onChange={(e) => setNewAsset({ ...newAsset, vendor: e.target.value })} /></Field>
              <Field label="Product"><input className={inputCls} value={newAsset.product} onChange={(e) => setNewAsset({ ...newAsset, product: e.target.value })} /></Field>
              <Field label="Version"><input className={inputCls} value={newAsset.version} onChange={(e) => setNewAsset({ ...newAsset, version: e.target.value })} /></Field>
            </div>
          )}
          {assetNote && <div className="mt-3"><Notice>{assetNote}</Notice></div>}
          <div className="mt-4 flex gap-2">
            <button data-testid="upload-submit" className={btnPrimary} disabled={!files.length || up.isPending} onClick={() => up.mutate()}>
              {up.isPending ? "Uploading…" : `Upload ${files.length || ""}`.trim()}
            </button>
            <button className={btnGhost} onClick={() => setFiles([])}>Clear</button>
          </div>
          {msg && <div className="mt-3"><Notice kind="ok" testId="upload-success">{msg}</Notice></div>}
          {err && <div className="mt-3"><Notice kind="error" testId="upload-error">{err}</Notice></div>}
        </Card>
      </div>
      <p className="mt-4 text-xs text-ink3">Flow: upload, open the configuration, press Start audit, then follow the progress to the results.</p>
    </div>
  );
}
