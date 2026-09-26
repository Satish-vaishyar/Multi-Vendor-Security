import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { login } from "../api/auth.api";
import { setToken, toMessage } from "../api/client";
import { useAuth } from "../stores/auth";
import { btnPrimary, inputCls } from "../components/common";

export default function Login() {
  const nav = useNavigate();
  const { setSession } = useAuth();
  const [email, setEmail] = useState("admin@example.com");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const d = await login(email, password);
      setToken(d.access_token);
      setSession(d.access_token, { id: d.user.id, name: d.user.name, email, role: d.user.role });
      nav("/dashboard");
    } catch (ex) {
      setErr(toMessage(ex));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas p-4">
      <form onSubmit={submit} className="card-shadow w-full max-w-sm rounded-xl border border-line bg-surface p-6">
        <div className="mb-5 flex items-center gap-2.5">
          <span className="rounded-lg bg-primary p-2.5"><ShieldCheck className="text-onprimary" size={20} /></span>
          <div>
            <h1 className="text-base font-semibold tracking-widest text-ink">QIROVA</h1>
            <p className="text-xs text-ink3">Security Compliance Auditor · Sign in</p>
          </div>
        </div>
        <label className="mb-3 block text-xs font-medium text-ink2">Email
          <input className={`${inputCls} mt-1`} value={email} onChange={(e) => setEmail(e.target.value)} type="email" required />
        </label>
        <label className="mb-4 block text-xs font-medium text-ink2">Password
          <input className={`${inputCls} mt-1`} value={password} onChange={(e) => setPassword(e.target.value)} type="password" required />
        </label>
        {err && <p className="mb-3 rounded-lg border border-danger/30 bg-dangerbg p-2.5 text-xs text-danger">{err}</p>}
        <button className={`${btnPrimary} w-full`} disabled={busy}>{busy ? "Signing in…" : "Sign In"}</button>
        <p className="mt-4 text-center text-[11px] text-ink3">Demo: admin@example.com / admin123</p>
      </form>
    </div>
  );
}
