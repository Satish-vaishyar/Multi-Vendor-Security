import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { getCanonicalIr, getConfiguration, getUnknowns } from "../api/configurations.api";
import { createAudit } from "../api/audits.api";
import { toMessage } from "../api/client";
import { FRAMEWORKS } from "../constants";
import { Badge, Card, Empty, ErrorState, Field, Loader, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";

const tabCls = (active: boolean) =>
  `rounded-lg border px-3 py-1.5 font-semibold ${active ? "border-primary bg-primarylight text-primary" : "border-linestrong bg-surface text-ink2 hover:bg-surface2"}`;

export default function ConfigurationDetails() {
  const { configurationId = "" } = useParams();
  const nav = useNavigate();
  const [tab, setTab] = useState<"raw" | "ir" | "unknown" | "info">("raw");
  const [showAudit, setShowAudit] = useState(false);
  const [fw, setFw] = useState<string[]>([...FRAMEWORKS]);
  const [runCve, setRunCve] = useState(true);
  const [runPqc, setRunPqc] = useState(true);
  const [runSec, setRunSec] = useState(true);
  const [genPdf, setGenPdf] = useState(false);
  const [err, setErr] = useState("");

  const meta = useQuery({ queryKey: ["cfg", configurationId], queryFn: () => getConfiguration(configurationId) });
  const ir = useQuery({ queryKey: ["ir", configurationId], queryFn: () => getCanonicalIr(configurationId), enabled: tab === "ir" });
  const unk = useQuery({ queryKey: ["unk", configurationId], queryFn: () => getUnknowns(configurationId), enabled: tab === "unknown" });

  const audit = useMutation({
    mutationFn: () => {
      const aid = meta.data?.asset_id as string | undefined;
      if (!aid) throw new Error("This configuration has no asset — re-upload it against an asset first.");
      return createAudit({
        asset_id: aid,
        configuration_id: configurationId,
        frameworks: fw,
        run_cve: runCve,
        run_pqc: runPqc,
        run_security_analysis: runSec,
        generate_report: genPdf,
      });
    },
    onSuccess: (d) => nav(`/audits/${d.audit_id}`),
    onError: (e) => setErr(toMessage(e)),
  });

  if (meta.isLoading) return <Loader />;
  if (meta.isError || !meta.data) return <ErrorState message="Configuration not found." />;
  const m = meta.data as Record<string, unknown>;

  const toggle = (f: string) => setFw((p) => (p.includes(f) ? p.filter((x) => x !== f) : [...p, f]));

  return (
    <div>
      <PageHeader
        title={String(m.filename ?? configurationId)}
        sub={`Vendor: ${String(m.detected_vendor ?? m.vendor ?? "—")} · Platform: ${String(m.detected_platform ?? m.platform ?? "—")} · Version: ${String(m.detected_version ?? m.version ?? "—")}`}
        actions={<><button className={btnGhost} onClick={() => nav("/configurations/upload")}>New Upload</button>
          <button className={btnPrimary} onClick={() => setShowAudit(true)}>Start Audit</button></>}
      />
      <div className="mb-4 flex gap-2 text-xs">
        {(["raw", "ir", "unknown", "info"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={tabCls(tab === t)}>
            {{ raw: "Raw Configuration", ir: "Canonical IR", unknown: "Unknown Tokens", info: "Parsing Information" }[t]}
          </button>
        ))}
      </div>

      {tab === "info" && (
        <Card title="Parsing Information">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <Badge value={String(m.status ?? "—")} />
            <span className="text-xs text-ink3">Parser: {JSON.stringify(m.parser ?? {})} · Confidence: {String((m.parser as { confidence?: number } | undefined)?.confidence ?? "—")}</span>
          </div>
        </Card>
      )}
      {tab === "raw" && (
        <Card title="Raw Configuration" sub="Read-only viewer">
          <pre className="code-view max-h-[60vh] overflow-auto rounded-lg border border-line bg-surface2 p-4 text-ink2">
            {String(m.config_text ?? m.raw ?? "Raw text not returned by this endpoint — see canonical IR.").split("\n").map((l, i) => (
              <div key={i} className="flex gap-4"><span className="w-8 shrink-0 select-none text-right text-ink3">{i + 1}</span><span>{l}</span></div>
            ))}
          </pre>
        </Card>
      )}
      {tab === "ir" && (
        <Card title="Canonical IR" sub="Normalized, vendor-neutral security representation">
          {ir.isLoading ? <Loader /> : ir.isError ? <ErrorState message="Could not load canonical IR." onRetry={() => ir.refetch()} /> : (
            <pre className="code-view max-h-[60vh] overflow-auto rounded-lg border border-line bg-surface2 p-4 text-ink2">{JSON.stringify(ir.data, null, 2)}</pre>
          )}
        </Card>
      )}
      {tab === "unknown" && (
        <Card title="Unknown Tokens" sub="Feeds the AI training queue">
          {unk.isLoading ? <Loader /> : !unk.data ? <Empty /> : (
            <pre className="code-view max-h-[60vh] overflow-auto rounded-lg border border-line bg-surface2 p-4 text-ink2">{JSON.stringify(unk.data, null, 2)}</pre>
          )}
        </Card>
      )}

      {showAudit && (
        <div className="fixed inset-0 z-30 flex items-center justify-center bg-ink/40 p-4" onClick={() => setShowAudit(false)}>
          <div className="card-shadow w-full max-w-md rounded-xl border border-line bg-surface p-5" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-base font-semibold text-ink">Start Audit</h2>
            <p className="mt-1 text-xs text-ink3">Select frameworks and analysis engines</p>
            <div className="mt-3">
              <p className="mb-1.5 text-[11px] uppercase tracking-wider text-ink3">Frameworks</p>
              <div className="flex flex-wrap gap-2">
                {FRAMEWORKS.map((f) => (
                  <label key={f} className={`cursor-pointer rounded-lg border px-3 py-1.5 text-xs font-semibold ${fw.includes(f) ? "border-primary bg-primarylight text-primary" : "border-linestrong text-ink2"}`}>
                    <input type="checkbox" className="mr-1.5 accent-primary" checked={fw.includes(f)} onChange={() => toggle(f)} />{f}
                  </label>
                ))}
              </div>
            </div>
            <div className="mt-3 space-y-1.5 text-ink2">
              {[["CVE analysis", runCve, setRunCve], ["PQC analysis", runPqc, setRunPqc], ["Security analytics", runSec, setRunSec], ["Generate PDF report", genPdf, setGenPdf]].map(([l, v, s]) => (
                <label key={l as string} className="flex items-center gap-2 text-xs">
                  <input type="checkbox" className="accent-primary" checked={v as boolean} onChange={(e) => (s as (b: boolean) => void)(e.target.checked)} />{l as string}
                </label>
              ))}
            </div>
            <Field label="Asset ID"><input className={`${inputCls} mt-1`} value={String(m.asset_id ?? "missing — re-upload against an asset")} readOnly /></Field>
            {err && <p className="mt-2 text-xs text-danger">{err}</p>}
            <div className="mt-4 flex gap-2">
              <button className={btnPrimary} disabled={!fw.length || audit.isPending} onClick={() => audit.mutate()}>
                {audit.isPending ? "Starting…" : "Start Audit"}
              </button>
              <button className={btnGhost} onClick={() => setShowAudit(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
