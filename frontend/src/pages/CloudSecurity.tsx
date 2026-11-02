import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { cloudStatus, downloadCloudScan, getCloudScan, listCloudFindings, listCloudScans, uploadCloudScan } from "../api/cloud.api";
import { toMessage } from "../api/client";
import { Badge, Card, Empty, ErrorState, Loader, Notice, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";
import CloudExtras from "../components/CloudExtras";
import { useAuth } from "../stores/auth";
import { hasRole } from "../utils/roles";

const STATES = ["", "FAIL_STATIC", "UNKNOWN_STATIC", "PASS_STATIC", "NOT_APPLICABLE"];
const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function CloudSecurity() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const canScan = hasRole(user?.role, "AUDITOR");
  const status = useQuery({ queryKey: ["cloud", "status"], queryFn: cloudStatus, retry: false });
  const [selected, setSelected] = useState("");
  const [state, setState] = useState("FAIL_STATIC");
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(1);
  const [err, setErr] = useState("");
  const [retain, setRetain] = useState(false);
  const [kept, setKept] = useState("");
  const enabled = status.isSuccess;
  const scans = useQuery({ queryKey: ["cloud", "scans"], queryFn: listCloudScans, enabled });
  const scan = useQuery({ queryKey: ["cloud", "scan", selected], queryFn: () => getCloudScan(selected), enabled: enabled && !!selected });
  const findings = useQuery({
    queryKey: ["cloud", "findings", selected, state, severity, page],
    queryFn: () => listCloudFindings(selected, { state: state || undefined, severity: severity || undefined, page }),
    enabled: enabled && !!selected,
  });
  const upload = useMutation({
    mutationFn: (f: File) => uploadCloudScan(f, retain),
    onSuccess: (r) => { setErr(""); setKept(r.retention && !r.retention.kept ? `The file was scanned but not kept: ${r.retention.reason ?? "not kept"}.` : ""); setSelected(r.scan_id); setPage(1); void qc.invalidateQueries({ queryKey: ["cloud", "scans"] }); },
    onError: (e) => setErr(toMessage(e)),
  });

  if (status.isLoading) return <Loader />;
  if (!enabled) {
    return (
      <div>
        <PageHeader title="Cloud security" />
        <Empty label="The cloud security module is not enabled." hint="An administrator can turn it on with the CLOUD_MODULE_ENABLED setting. Nothing else in the product depends on it." />
      </div>
    );
  }
  const items = findings.data?.items ?? [];
  const total = findings.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / (findings.data?.size ?? 50)));
  return (
    <div>
      <PageHeader
        title="Cloud security"
        sub="Upload Terraform, CloudFormation, Azure ARM or Kubernetes files (or a zip of them). They are analysed statically in an isolated scanner; nothing is deployed or executed, and no cloud account is contacted."
      />
      {status.data?.scanner.status !== "ok" && <Notice kind="error">The scanner service is not reachable ({status.data?.scanner.status}). Uploads will fail until it is running.</Notice>}
      {canScan && (
        <Card title="New scan" sub="Up to 50 MB. Files containing secrets are flagged and the secret values are never stored.">
          <input
            type="file"
            aria-label="Infrastructure files"
            accept=".tf,.json,.yaml,.yml,.zip,.tgz,.tar.gz,.tfvars"
            disabled={upload.isPending}
            onChange={(e) => { const f = e.target.files?.[0]; if (f) upload.mutate(f); e.target.value = ""; }}
            className={inputCls}
          />
          <label className="mt-2 flex items-center gap-2 text-xs text-ink2">
            <input type="checkbox" checked={retain} onChange={(e) => setRetain(e.target.checked)} />
            Keep this file (encrypted, 90 days) so it can be scanned again on a schedule. Off by default; never kept if it contains a secret.
          </label>
          {upload.isPending && <Loader label="Scanning…" rows={1} />}
          {kept && <Notice kind="info">{kept}</Notice>}
          {err && <Notice kind="error">{err}</Notice>}
        </Card>
      )}
      <Card title="Scans">
        {scans.isLoading ? <Loader /> : scans.isError ? <ErrorState message={toMessage(scans.error)} onRetry={() => void scans.refetch()} /> :
          (scans.data?.items.length ?? 0) === 0 ? <Empty label="No cloud scans yet." /> : (
            <ul className="divide-y divide-line">
              {scans.data!.items.map((s) => (
                <li key={s.scan_id} className="flex items-center justify-between py-2">
                  <button className="text-left text-primary hover:underline" onClick={() => { setSelected(s.scan_id); setPage(1); }}>
                    {s.file_name || s.scan_id}
                  </button>
                  <span className="flex items-center gap-2 text-xs text-ink2">
                    {(s.providers ?? []).join(", ")} <Badge value={s.status} /> {s.created_at ? new Date(s.created_at).toLocaleString() : ""}
                  </span>
                </li>
              ))}
            </ul>
          )}
      </Card>
      {selected && (
        <Card
          title={`Findings for ${scan.data?.file_name ?? selected}`}
          sub={scan.data?.summary?.statement}
          right={
            <span className="flex gap-2">
              {(["json", "csv", "sarif", "pdf"] as const).map((f) => (
                <button key={f} className={btnGhost} onClick={() => void downloadCloudScan(selected, f).catch((e) => setErr(toMessage(e)))}>
                  {f.toUpperCase()}
                </button>
              ))}
            </span>
          }
        >
          <div className="mb-3 flex gap-2">
            <select aria-label="Result" className={inputCls} value={state} onChange={(e) => { setState(e.target.value); setPage(1); }}>
              {STATES.map((s) => <option key={s} value={s}>{s || "All results"}</option>)}
            </select>
            <select aria-label="Severity" className={inputCls} value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s || "All severities"}</option>)}
            </select>
          </div>
          {findings.isLoading ? <Loader /> : findings.isError ? <ErrorState message={toMessage(findings.error)} /> :
            items.length === 0 ? <Empty label="No results for these filters." hint="UNKNOWN means the files do not contain enough to decide; it is never counted as a pass." /> : (
              <table className="w-full text-sm">
                <thead><tr className="text-left text-xs text-ink2"><th>Rule</th><th>Finding</th><th>Severity</th><th>Result</th><th>Where</th></tr></thead>
                <tbody>
                  {items.map((f) => (
                    <tr key={f.finding_id} className="border-t border-line align-top">
                      <td className="py-2 pr-2 font-mono text-xs">{f.rule_id}</td>
                      <td className="py-2 pr-2">
                        {f.title}
                        <div className="text-xs text-ink2">{f.source.resource_address}</div>
                        {f.source.notes?.map((n) => <div key={n} className="text-xs text-ink2">{n}</div>)}
                        {f.remediation?.summary && <div className="text-xs text-ink2">Fix: {f.remediation.summary}</div>}
                        {f.remediation?.snippet && (
                          <details className="text-xs">
                            <summary className="cursor-pointer">Suggested change (not applied)</summary>
                            <pre className="overflow-x-auto bg-surface2 p-2">{f.remediation.snippet.text}</pre>
                            <div className="text-ink2">{f.remediation.snippet.disclaimer}</div>
                          </details>
                        )}
                      </td>
                      <td className="py-2 pr-2"><Badge value={f.severity} kind="sev" /></td>
                      <td className="py-2 pr-2"><Badge value={f.evidence_state} /></td>
                      <td className="py-2 font-mono text-xs">{f.source.file}{f.source.line_start ? `:${f.source.line_start}` : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          <div className="mt-3 flex items-center gap-2 text-xs text-ink2">
            <button className={btnPrimary} disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button>
            <span>Page {page} of {pages} ({total} results)</span>
            <button className={btnPrimary} disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</button>
          </div>
        </Card>
      )}
      {selected && <CloudExtras scanId={selected} canChange={canScan} isAdmin={hasRole(user?.role, "ADMIN")} />}
    </div>
  );
}
