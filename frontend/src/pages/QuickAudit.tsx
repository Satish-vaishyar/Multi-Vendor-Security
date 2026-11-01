import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { CircleCheck, FileText, Loader2, UploadCloud, X } from "lucide-react";
import { createAssetFull, listAssets, patchAsset } from "../api/assets.api";
import { createAudit } from "../api/audits.api";
import { uploadConfiguration } from "../api/configurations.api";
import { toMessage } from "../api/client";
import { FRAMEWORKS } from "../constants";
import { Card, Field, Hint, Notice, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";

const SAMPLE_URL = "/samples/cisco_iosxe_branch_insecure.cfg";
const STEPS = ["Upload the file and detect the vendor", "Run the audit (compliance, CVEs, post-quantum, analytics)", "Open the results"];

function stem(name: string): string {
  return name.replace(/\.[^.]+$/, "").replace(/[_]+/g, "-").slice(0, 60) || "device";
}

export default function QuickAudit() {
  const nav = useNavigate();
  const [sp] = useSearchParams();
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [assetId, setAssetId] = useState(sp.get("asset") ?? "");
  const [step, setStep] = useState(-1); // -1 idle, 0..2 running
  const [vendor, setVendor] = useState("");
  const [err, setErr] = useState("");
  const [drag, setDrag] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const busy = step >= 0 && !err;
  const assets = useQuery({ queryKey: ["assets", "all"], queryFn: () => listAssets({ page: 1, page_size: 100, status: "ACTIVE" }) });

  const pick = (f?: File | null) => {
    if (!f) return;
    setFile(f);
    setErr("");
    setStep(-1);
    setVendor("");
  };

  const loadSample = async () => {
    try {
      const r = await fetch(SAMPLE_URL);
      if (!r.ok) throw new Error("sample missing");
      const blob = await r.blob();
      pick(new File([blob], "sample-branch-router.cfg", { type: "text/plain" }));
      setName("sample-branch-router");
    } catch {
      setErr("Could not load the sample config. Choose a file from your computer instead.");
    }
  };

  // /quick-audit?sample=1 pre-loads the bundled sample so a new user can try the flow with one click.
  useEffect(() => {
    if (sp.get("sample") === "1") void loadSample();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const run = async () => {
    if (!file) return;
    setErr("");
    try {
      setStep(0);
      let aid = assetId;
      if (!aid) {
        const res = await createAssetFull({ name: (name.trim() || stem(file.name)), vendor: "", product: "", version: "", criticality: "MEDIUM" });
        aid = res.data.asset_id as string;
        if (!aid) throw new Error("Could not create a device record. Try again.");
      }
      const cfg = await uploadConfiguration(file, aid);
      const detected = String((cfg as unknown as Record<string, unknown>).detected_vendor ?? (cfg as unknown as Record<string, unknown>).vendor ?? "");
      setVendor(detected);
      // Record the detected vendor on a freshly created device so lists and filters show it (best effort).
      if (!assetId && detected && detected !== "unknown") await patchAsset(aid, { vendor: detected }).catch(() => undefined);
      setStep(1);
      const a = await createAudit({
        asset_id: aid, configuration_id: cfg.configuration_id as string, frameworks: [...FRAMEWORKS],
        run_cve: true, run_pqc: true, run_security_analysis: true, generate_report: false,
      });
      setStep(2);
      nav(`/audits/${a.audit_id}/results`);
    } catch (e) {
      setErr(toMessage(e));
    }
  };

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="Upload & audit"
        sub="Drop a router, firewall or switch configuration. We detect the vendor, audit it and open the results."
      />

      <Card>
        <label
          className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-4 py-10 text-center transition-colors focus-within:border-primary focus-within:ring-2 focus-within:ring-primary/30 ${drag ? "border-primary bg-primarylight" : "border-linestrong bg-surface2/50 hover:border-primary"}`}
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files[0]); }}
        >
          <UploadCloud className="mb-2 text-primary" size={30} aria-hidden="true" />
          <span className="text-sm font-medium text-ink">Drop a configuration file here</span>
          <span className="mt-1 text-xs text-ink3">or click to browse · .cfg .conf .txt .yaml .json</span>
          <input ref={inputRef} data-testid="quick-file-input" type="file" className="sr-only" onChange={(e) => pick(e.target.files?.[0])} disabled={busy} />
        </label>

        {file && (
          <div className="mt-4 flex items-center gap-3 rounded-lg bg-surface2 px-3 py-2.5 text-sm">
            <FileText size={16} className="shrink-0 text-ink3" aria-hidden="true" />
            <span className="min-w-0 flex-1 truncate text-ink">{file.name}</span>
            <span className="shrink-0 text-xs text-ink3">{(file.size / 1024).toFixed(1)} KB</span>
            {!busy && (
              <button onClick={() => { setFile(null); setStep(-1); setErr(""); if (inputRef.current) inputRef.current.value = ""; }} className="rounded-md p-1 text-ink3 hover:text-ink" aria-label="Remove file">
                <X size={14} aria-hidden="true" />
              </button>
            )}
          </div>
        )}

        {step >= 0 && (
          <ol className="mt-4 space-y-2" aria-live="polite">
            {STEPS.map((s, i) => (
              <li key={s} className={`flex items-center gap-2.5 text-sm ${i > step ? "text-ink3" : "text-ink"}`}>
                {i < step || (i === step && step === 2) ? <CircleCheck size={16} className="text-ok" aria-hidden="true" /> :
                  i === step && !err ? <Loader2 size={16} className="animate-spin text-primary" aria-hidden="true" /> :
                    <span className="h-4 w-4 rounded-full border border-linestrong" aria-hidden="true" />}
                <span>{s}{i === 1 && vendor ? <span className="text-ink3"> · detected {vendor}</span> : null}</span>
              </li>
            ))}
          </ol>
        )}
        {step === 1 && !err && <p className="mt-3 text-xs text-ink3">The first audit after a restart can take a minute while the analysis models warm up.</p>}

        {err && <div className="mt-4"><Notice kind="error" testId="quick-error">{err}</Notice></div>}

        <div className="mt-5 flex flex-wrap items-center gap-2">
          <button className={btnPrimary} disabled={!file || busy} onClick={run} data-testid="quick-run">
            {busy ? <><Loader2 size={16} className="animate-spin" aria-hidden="true" /> Auditing…</> : err ? "Try again" : "Upload & run audit"}
          </button>
          <button className={btnGhost} disabled={busy} onClick={loadSample}>Try a sample config</button>
        </div>

        <details className="mt-5 border-t border-line pt-4 text-sm">
          <summary className="cursor-pointer text-xs font-semibold text-ink2">Options (optional)</summary>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <Field label="Device name">
              <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder={file ? stem(file.name) : "Taken from the file name"} />
            </Field>
            <Field label="Or add to an existing device">
              <select className={inputCls} value={assetId} onChange={(e) => setAssetId(e.target.value)}>
                <option value="">New device</option>
                {(assets.data?.items ?? []).map((a) => <option key={a.asset_id} value={a.asset_id}>{a.name}</option>)}
              </select>
            </Field>
          </div>
          <p className="mt-3 text-xs text-ink3">
            Checks CIS, NIST, STIG and ISO 27001 plus CVEs, post-quantum crypto and security analytics.
            Need to pick frameworks, set the vendor or upload several files? Use the <Link to="/configurations/upload" className="font-medium text-primary hover:underline">advanced upload</Link>.
          </p>
        </details>
      </Card>

      <p className="mt-4 text-xs text-ink3">
        What happens next: you get a compliance score, a list of findings with severity, and fix commands for each one. <Hint term="audit" />
      </p>
    </div>
  );
}
