import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { auditLog, createUser, listUsers, patchUser } from "../api/admin.api";
import { toMessage } from "../api/client";
import { Badge, Card, Empty, ErrorState, Field, Loader, PageHeader, btnGhost, btnPrimary, inputCls } from "../components/common";
import { useAuth } from "../stores/auth";
import { ROLES } from "../utils/roles";

const ROLE_HELP: Record<string, string> = {
  VIEWER: "Read-only; configs shown with secrets masked",
  AUDITOR: "Upload configs, run audits & reports, manage assets",
  APPROVER: "Approve learned mappings and remediation",
  ADMIN: "Everything, including users and this audit log",
};

function Users() {
  const qc = useQueryClient();
  const me = useAuth((s) => s.user);
  const q = useQuery({ queryKey: ["admin-users"], queryFn: listUsers });
  const [form, setForm] = useState({ email: "", name: "", password: "", role: "AUDITOR" });
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");

  const create = useMutation({
    mutationFn: () => createUser(form),
    onSuccess: (u) => {
      setErr("");
      setNote(`Created ${u.email}. They must choose a new password at first sign-in.`);
      setForm({ email: "", name: "", password: "", role: "AUDITOR" });
      void qc.invalidateQueries({ queryKey: ["admin-users"] });
    },
    onError: (e) => { setNote(""); setErr(toMessage(e)); },
  });
  const patch = useMutation({
    mutationFn: (v: { id: string; body: { role?: string; disabled?: boolean } }) => patchUser(v.id, v.body),
    onSuccess: () => { setErr(""); void qc.invalidateQueries({ queryKey: ["admin-users"] }); },
    onError: (e) => setErr(toMessage(e)),
  });

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <Card title="Users" sub="People in your organisation">
          {q.isLoading ? <Loader /> : q.isError ? <ErrorState message={toMessage(q.error)} onRetry={() => q.refetch()} /> :
            !q.data?.items.length ? <Empty label="No users." /> : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="text-xs uppercase tracking-wider text-ink3">
                    <tr><th className="py-2 pr-3">User</th><th className="pr-3">Role</th><th className="pr-3">Status</th><th /></tr>
                  </thead>
                  <tbody>
                    {q.data.items.map((u) => {
                      const self = u.id === me?.id;
                      return (
                        <tr key={u.id} className="border-t border-line">
                          <td className="py-2 pr-3"><div className="font-medium text-ink">{u.name}</div><div className="text-xs text-ink3">{u.email}</div></td>
                          <td className="pr-3">
                            <select className={`${inputCls} min-w-[7.5rem] py-1`} aria-label={`Role for ${u.email}`} value={u.role} disabled={self || patch.isPending}
                              onChange={(e) => patch.mutate({ id: u.id, body: { role: e.target.value } })}>
                              {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                            </select>
                          </td>
                          <td className="pr-3">
                            <Badge value={u.disabled ? "DISABLED" : u.must_change_password ? "PASSWORD RESET PENDING" : "ACTIVE"} />
                          </td>
                          <td className="text-right">
                            {!self && (
                              <button className={btnGhost} disabled={patch.isPending}
                                onClick={() => patch.mutate({ id: u.id, body: { disabled: !u.disabled } })}>
                                {u.disabled ? "Enable" : "Disable"}
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          {err && <p role="alert" className="mt-3 rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}
        </Card>
      </div>
      <Card title="Add user" sub="They will be asked to change this password at first sign-in">
        <form className="grid gap-3" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
          <Field label="Name"><input className={inputCls} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required /></Field>
          <Field label="Email"><input className={inputCls} type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required /></Field>
          <Field label="Temporary password"><input className={inputCls} type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required /></Field>
          <Field label="Role">
            <select className={inputCls} aria-label="Role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
              {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </Field>
          <p className="text-xs text-ink3">{ROLE_HELP[form.role]}</p>
          <button className={btnPrimary} disabled={create.isPending}>{create.isPending ? "Creating…" : "Create user"}</button>
          {note && <p className="rounded-lg border border-ok/30 bg-okbg p-2.5 text-xs text-ok">{note}</p>}
        </form>
      </Card>
    </div>
  );
}

function AuditLog() {
  const [action, setAction] = useState("");
  const q = useQuery({ queryKey: ["audit-log", action], queryFn: () => auditLog({ limit: 200, action: action || undefined }) });
  return (
    <Card title="Audit log" sub="Append-only record of sign-ins and every change (including denied attempts)"
      right={<input className={`${inputCls} w-56`} placeholder="Filter by action, e.g. auth.login" value={action} onChange={(e) => setAction(e.target.value)} />}>
      {q.isLoading ? <Loader /> : q.isError ? <ErrorState message={toMessage(q.error)} onRetry={() => q.refetch()} /> :
        !q.data?.items.length ? <Empty label="No events." /> : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="uppercase tracking-wider text-ink3">
                <tr><th className="py-2 pr-3">Time</th><th className="pr-3">Who</th><th className="pr-3">Action</th><th className="pr-3">Path</th><th className="pr-3">Result</th><th>IP</th></tr>
              </thead>
              <tbody>
                {q.data.items.map((r) => (
                  <tr key={r.id} className="border-t border-line align-top">
                    <td className="whitespace-nowrap py-1.5 pr-3 text-ink3">{new Date(r.ts).toLocaleString()}</td>
                    <td className="pr-3 text-ink">{r.actor_email ?? "—"}<span className="ml-1 text-ink3">{r.role ? `(${r.role})` : ""}</span></td>
                    <td className="pr-3 font-mono">{r.action}</td>
                    <td className="max-w-[18rem] truncate pr-3 font-mono text-ink3" title={r.path ?? ""}>{r.path ?? ""}</td>
                    <td className="pr-3"><Badge value={r.status && r.status >= 400 ? `${r.status}` : r.status ? "OK" : "—"} /></td>
                    <td className="text-ink3">{r.ip ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
    </Card>
  );
}

export default function Admin() {
  const [tab, setTab] = useState<"users" | "log">("users");
  return (
    <div>
      <PageHeader title="Administration" sub="Users, roles and the audit trail for your organisation" />
      <div className="mb-4 flex gap-2">
        {([["users", "Users & roles"], ["log", "Audit log"]] as const).map(([k, label]) => (
          <button key={k} onClick={() => setTab(k)}
            className={`rounded-lg border px-4 py-2 text-sm font-semibold ${tab === k ? "border-primary bg-primarylight text-primary" : "border-linestrong bg-surface text-ink2 hover:bg-surface2"}`}>
            {label}
          </button>
        ))}
      </div>
      {tab === "users" ? <Users /> : <AuditLog />}
    </div>
  );
}
