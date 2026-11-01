import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { KeyRound } from "lucide-react";
import { changePassword } from "../api/auth.api";
import { toMessage } from "../api/client";
import { useAuth } from "../stores/auth";
import { Card, Field, PageHeader, btnPrimary, inputCls } from "../components/common";

const MIN_LEN = 12;

/** Shown to users who must replace an admin-issued password, and reachable from Settings. */
export default function ChangePassword() {
  const nav = useNavigate();
  const { user, setSession } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const forced = !!user?.must_change_password;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    if (next.length < MIN_LEN) return setErr(`Use at least ${MIN_LEN} characters.`);
    if (next !== again) return setErr("The two new passwords do not match.");
    setBusy(true);
    try {
      const d = await changePassword(current, next);
      // The server signs out every other session; keep this one with the fresh token.
      setSession(d.access_token, { ...d.user, email: d.user.email ?? user?.email ?? "" });
      nav("/dashboard", { replace: true });
    } catch (ex) {
      setErr(toMessage(ex));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-md p-4 md:p-8">
      <PageHeader
        title={forced ? "Choose a new password" : "Change password"}
        sub={forced ? "Your password was issued by an administrator and must be replaced before you continue." : "All your other sessions will be signed out."}
      />
      <Card>
        <form onSubmit={submit} className="grid gap-3">
          <Field label="Current password">
            <input className={inputCls} type="password" autoComplete="current-password" value={current}
              onChange={(e) => setCurrent(e.target.value)} required />
          </Field>
          <Field label="New password">
            <input className={inputCls} type="password" autoComplete="new-password" value={next}
              onChange={(e) => setNext(e.target.value)} required />
          </Field>
          <Field label="Repeat new password">
            <input className={inputCls} type="password" autoComplete="new-password" value={again}
              onChange={(e) => setAgain(e.target.value)} required />
          </Field>
          <p className="text-xs text-ink3">
            At least {MIN_LEN} characters, mixing three of: lowercase, uppercase, digits, symbols.
          </p>
          {err && <p role="alert" className="rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}
          <button className={`${btnPrimary} flex items-center justify-center gap-2`} disabled={busy}>
            <KeyRound size={15} /> {busy ? "Saving…" : "Update password"}
          </button>
        </form>
      </Card>
    </div>
  );
}
