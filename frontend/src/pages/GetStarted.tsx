import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ArrowRight, CircleCheck } from "lucide-react";
import { getSummary } from "../api/dashboard.api";
import { useAuditOverviews } from "../hooks/useAuditOverviews";
import { useAuth } from "../stores/auth";
import { hasRole } from "../utils/roles";
import { useMilestones } from "../utils/progress";
import { GLOSSARY } from "../constants";
import { Card, ErrorState, Hint, KpiSkeleton, PageHeader, btnGhost, btnPrimary } from "../components/common";

interface Step { id: string; title: string; why: string; done: boolean; cta: string; to: string; locked?: string }

export default function GetStarted() {
  const role = useAuth((s) => s.user?.role);
  const canUpload = hasRole(role, "AUDITOR");
  const sum = useQuery({ queryKey: ["dashboard"], queryFn: getSummary });
  const audits = useAuditOverviews();
  const ms = useMilestones();

  if (sum.isLoading || audits.isLoading) return <div><PageHeader title="Get started" /><KpiSkeleton count={5} /></div>;
  if (sum.isError) return <ErrorState message="Could not load your progress." onRetry={() => sum.refetch()} />;

  const hasDevice = (sum.data?.assets?.total ?? 0) > 0;
  const hasAudit = audits.overviews.length > 0;
  const hasFindings = (sum.data?.totals?.findings ?? 0) > 0 || audits.overviews.some((a) => a.total > 0);

  const steps: Step[] = [
    {
      id: "upload", title: "Add a device configuration",
      why: "Upload the saved config of a router, firewall or switch. The vendor is detected for you.",
      done: hasDevice, cta: canUpload ? "Upload a config" : "View devices", to: canUpload ? "/quick-audit" : "/assets",
      locked: canUpload ? undefined : "Your role is read-only. Ask an auditor to upload a config.",
    },
    {
      id: "audit", title: "Run the audit",
      why: "We check it against CIS, NIST, STIG and ISO 27001, look up known CVEs and test the encryption.",
      done: hasAudit, cta: canUpload ? "Run an audit" : "See audits", to: canUpload ? "/quick-audit" : "/audits",
    },
    {
      id: "findings", title: "Review the top findings",
      why: "Start with the critical and high items. Each one explains what is wrong and why it matters.",
      done: hasFindings && !!ms.findings, cta: "Open findings", to: "/findings",
    },
    {
      id: "fixes", title: "Get the fix commands",
      why: "Every finding has the exact device commands that fix it. Review them, then apply on the device.",
      done: !!ms.fixes, cta: "See fix commands", to: "/remediation",
    },
    {
      id: "report", title: "Export a report",
      why: "Create a PDF for your team or an auditor, with the evidence behind every result.",
      done: !!ms.report, cta: "Create a report", to: "/reports",
    },
  ];
  const doneCount = steps.filter((s) => s.done).length;
  const next = steps.find((s) => !s.done);
  const pct = Math.round((doneCount / steps.length) * 100);

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        title="Get started"
        sub="From a config file to a signed-off report in five steps. Your progress is detected automatically."
        actions={<Link to="/dashboard" className={btnGhost}>Go to dashboard</Link>}
      />

      <Card>
        <div className="mb-1 flex items-baseline justify-between">
          <p className="text-sm font-semibold text-ink">{doneCount === steps.length ? "All done. Nice work." : `${doneCount} of ${steps.length} steps done`}</p>
          <p className="text-xs text-ink3">{pct}%</p>
        </div>
        <div className="h-1.5 overflow-hidden rounded-full bg-surface2" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Setup progress">
          <div className="h-full rounded-full bg-primary transition-[width] duration-500" style={{ width: `${pct}%` }} />
        </div>
      </Card>

      <ol className="mt-4 space-y-3">
        {steps.map((s, i) => {
          const current = next?.id === s.id;
          return (
            <li key={s.id} className={`flex gap-4 rounded-xl border p-4 sm:p-5 ${current ? "border-primary/40 bg-primarylight/50" : "border-line bg-surface"}`}>
              <span className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-semibold ${s.done ? "bg-okbg text-ok" : current ? "bg-primary text-onprimary" : "bg-surface2 text-ink3"}`}>
                {s.done ? <CircleCheck size={16} aria-label="Done" /> : i + 1}
              </span>
              <div className="min-w-0 flex-1">
                <h2 className={`text-sm font-semibold ${s.done ? "text-ink2" : "text-ink"}`}>
                  {s.title}
                  {s.id === "audit" && <Hint term="compliance" label="compliance" />}
                  {s.id === "findings" && <Hint term="finding" />}
                  {s.id === "fixes" && <Hint term="remediation" />}
                </h2>
                <p className="mt-1 text-sm text-ink3">{s.why}</p>
                {s.locked && !s.done && <p className="mt-1 text-xs text-ink3">{s.locked}</p>}
                {(!s.done || current) && (
                  <Link to={s.to} className={`${current ? btnPrimary : btnGhost} mt-3`}>
                    {s.cta} <ArrowRight size={14} aria-hidden="true" />
                  </Link>
                )}
                {s.done && !current && <Link to={s.to} className="mt-2 inline-block text-xs font-medium text-primary hover:underline">Open again</Link>}
              </div>
            </li>
          );
        })}
      </ol>

      {!hasDevice && canUpload && (
        <Card className="mt-4" title="No config to hand?" sub="Try the whole flow with a bundled sample (a deliberately insecure Cisco branch router).">
          <Link to="/quick-audit?sample=1" className={btnGhost}>Try a sample config</Link>
        </Card>
      )}

      <Card className="mt-4" title="Words you will see" sub="Hover or tap the question marks anywhere in the app for the same explanations.">
        <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
          {([["CVE", "CVE"], ["PQC", "Post-quantum (PQC)"], ["CBOM", "CBOM"], ["STIG", "STIG"], ["drift", "Drift"], ["risk acceptance", "Risk acceptance"]] as const).map(([k, label]) => (
            <ShortTerm key={k} term={k} label={label} />
          ))}
        </dl>
      </Card>
    </div>
  );
}

function ShortTerm({ term, label }: { term: string; label: string }) {
  return (
    <div>
      <dt className="font-medium text-ink">{label}</dt>
      <dd className="text-xs text-ink3">{GLOSSARY[term]}</dd>
    </div>
  );
}
