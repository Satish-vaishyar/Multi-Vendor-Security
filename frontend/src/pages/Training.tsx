import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { approveMapping, rejectMapping, suggestMapping, trainingQueue } from "../api/training.api";
import { toMessage } from "../api/client";
import type { Suggestion, TrainingItem } from "../types";
import { AiBadge, Badge, Card, Empty, ErrorState, Field, Loader, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";

export default function Training() {
  const qc = useQueryClient();
  const [status, setStatus] = useState("PENDING");
  const [sel, setSel] = useState<TrainingItem | null>(null);
  const [prop, setProp] = useState("");
  const [val, setVal] = useState("");
  const [comment, setComment] = useState("");
  const [rejectReason, setRejectReason] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");

  const q = useQuery({ queryKey: ["training", status], queryFn: () => trainingQueue(status) });
  const items = ((q.data as { items?: TrainingItem[] } | undefined)?.items ?? []) as TrainingItem[];

  const sugg = useMutation({
    mutationFn: () => suggestMapping(sel!.training_id),
    onSuccess: () => { setErr(""); qc.invalidateQueries({ queryKey: ["training"] }); },
    onError: (e) => setErr(toMessage(e)),
  });
  const approve = useMutation({
    mutationFn: () => {
      if (!prop.trim()) throw new Error("Enter a canonical property (or pick an AI suggestion).");
      return approveMapping(sel!.training_id, { canonical_property: prop.trim(), canonical_value: coerce(val), comment });
    },
    onSuccess: (d) => {
      setErr(""); setNote(`Mapping approved. Registry updated (${JSON.stringify((d as Record<string, unknown>).mapping_id ?? "")}).`);
      qc.invalidateQueries({ queryKey: ["training"] });
    },
    onError: (e) => { setNote(""); setErr(toMessage(e)); },
  });
  const reject = useMutation({
    mutationFn: () => {
      if (!rejectReason.trim()) throw new Error("Enter a reason for rejection.");
      return rejectMapping(sel!.training_id, rejectReason.trim());
    },
    onSuccess: () => { setErr(""); setNote("Mapping rejected."); qc.invalidateQueries({ queryKey: ["training"] }); },
    onError: (e) => setErr(toMessage(e)),
  });

  const suggestions = (((sugg.data as Record<string, unknown> | undefined)?.suggestions ?? []) as Suggestion[]);

  return (
    <div>
      <PageHeader title="AI Training" sub="Adaptive learning loop — approve / reject AI mappings" />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card
          title="Unknown Command Queue"
          right={
            <select className={`${inputCls} w-32`} value={status} onChange={(e) => setStatus(e.target.value)}>
              {["PENDING", "APPROVED", "REJECTED"].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          }
        >
          {q.isLoading ? <Loader /> : q.isError ? <ErrorState message="Queue unavailable." onRetry={() => q.refetch()} /> :
            !items.length ? <Empty label={`No ${status.toLowerCase()} mappings.`} /> : (
              <ul className="max-h-[60vh] space-y-2 overflow-auto">
                {items.map((t) => (
                  <li key={t.training_id}>
                    <button onClick={() => { setSel(t); setNote(""); setErr(""); sugg.reset(); }}
                      className={`w-full rounded-lg border p-3 text-left text-sm ${sel?.training_id === t.training_id ? "border-primary bg-primarylight" : "border-line bg-surface hover:bg-surface2"}`}>
                      <p className="font-mono text-xs text-ink">{t.raw_command ?? t.training_id}</p>
                      <p className="mt-1 text-[11px] text-ink3">Vendor: {String(t.vendor ?? "—")} · Platform: {String(t.platform ?? "—")} · Context: {(t.context ?? []).join(", ") || "—"}</p>
                      <span className="mt-1.5 inline-block"><Badge value={String(t.status ?? status)} /></span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
        </Card>

        <Card title="AI Suggestions" sub={sel ? `Training ${sel.training_id}` : "Select a queue item"}>
          {!sel ? <Empty label="Select an unknown command to generate AI suggestions." /> : (
            <>
              <div className="mb-2"><AiBadge value="AI Suggested Mapping — human approval required" /></div>
              <button className={btnPrimary} disabled={sugg.isPending} onClick={() => sugg.mutate()}>
                {sugg.isPending ? "Generating…" : "Generate AI Suggestions"}
              </button>
              {sugg.isSuccess && !suggestions.length && <p className="mt-2 text-xs text-ink3">No suggestions returned.</p>}
              {!!suggestions.length && (
                <ul className="mt-3 space-y-2">
                  {suggestions.map((s, i) => (
                    <li key={i} className="rounded-lg bg-surface2 p-3 text-sm">
                      <p className="font-mono text-ink">{i + 1}. {s.canonical_property} = {JSON.stringify(s.value)}</p>
                      <p className="mt-1 text-xs text-ink3">Confidence: {s.confidence != null ? `${(Number(s.confidence) * 100).toFixed(0)}%` : "—"}</p>
                      <button className="mt-1.5 rounded-lg border border-primary/40 bg-surface px-2.5 py-1 text-xs font-semibold text-primary hover:bg-primarylight"
                        onClick={() => { setProp(s.canonical_property); setVal(String((s.value as unknown) ?? "")); }}>Use this mapping</button>
                    </li>
                  ))}
                </ul>
              )}
                <div className="mt-4 grid gap-2">
                <Field label="Canonical property (or choose different property)"><input className={inputCls} value={prop} onChange={(e) => setProp(e.target.value)} placeholder="e.g. SSH.VERSION" /></Field>
                <Field label="Canonical value"><input className={inputCls} value={val} onChange={(e) => setVal(e.target.value)} placeholder="e.g. 2" /></Field>
                <Field label="Comment"><input className={inputCls} value={comment} onChange={(e) => setComment(e.target.value)} placeholder="verification note" /></Field>
                <Field label="Reject reason"><input className={inputCls} value={rejectReason} onChange={(e) => setRejectReason(e.target.value)} placeholder="why is this mapping wrong?" /></Field>
                <div className="flex gap-2">
                  <button className={btnPrimary} disabled={approve.isPending} onClick={() => approve.mutate()}>
                    {approve.isPending ? "Approving…" : "Approve"}
                  </button>
                  <button className={btnGhost} disabled={reject.isPending} onClick={() => reject.mutate()}>Reject</button>
                </div>
                {note && <p className="rounded-lg border border-ok/30 bg-okbg p-2.5 text-xs text-ok">{note}</p>}
                {err && <p className="rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}
              </div>
            </>
          )}
        </Card>
      </div>
    </div>
  );
}

function coerce(v: string): unknown {
  if (v === "true") return true;
  if (v === "false") return false;
  const n = Number(v);
  return v !== "" && !Number.isNaN(n) ? n : v;
}
