import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { login, ssoConfig, ssoLoginUrl, type SsoConfig } from "../api/auth.api";
import { setToken, toMessage } from "../api/client";
import { useAuth } from "../stores/auth";
import { Notice, btnPrimary, inputCls } from "../components/common";

export default function Login() {
  const nav = useNavigate();
  const { setSession } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [needOtp, setNeedOtp] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(() => (new URLSearchParams(window.location.search).has("sso_error")
    ? "Single sign-on did not complete. You may not have access yet - ask an administrator, or try again." : ""));
  const [sso, setSso] = useState<SsoConfig | null>(null);
  const [showPw, setShowPw] = useState(false);
  useEffect(() => { void ssoConfig().then(setSso).catch(() => setSso(null)); }, []);
  const pwForm = !sso?.enabled || sso.password_login || showPw;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const d = await login(email, password, needOtp ? otp.trim() : undefined);
      setToken(d.access_token);
      setSession(d.access_token, { ...d.user, email: d.user.email ?? email });
      nav(d.user.must_change_password ? "/change-password" : "/dashboard");
    } catch (ex) {
      const m = toMessage(ex);
      if (/MFA code required/i.test(m)) { setNeedOtp(true); setErr(""); } else setErr(m);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-canvas p-4">
      <form onSubmit={submit} data-testid="login-form" className="w-full max-w-sm rounded-2xl border border-line bg-surface p-6 sm:p-8">
        <div className="mb-5 flex items-center gap-2.5">
          <span className="rounded-lg bg-primary p-2.5"><ShieldCheck className="text-onprimary" size={20} /></span>
          <div>
            <h1 className="text-base font-semibold tracking-widest text-ink">QIROVA</h1>
            <p className="text-xs text-ink3">Network security compliance auditor</p>
          </div>
        </div>
        {sso?.enabled && (
          <>
            <a data-testid="sso-login" href={ssoLoginUrl} className={`${btnPrimary} mb-3 block w-full text-center`}>Sign in with {sso.provider}</a>
            {sso.password_login ? <p className="mb-3 text-center text-[11px] text-ink3">or use your email and password</p>
              : !showPw && <button type="button" className="mb-3 w-full text-center text-[11px] text-ink3 underline" onClick={() => setShowPw(true)}>Administrator sign-in</button>}
          </>
        )}
        {pwForm && <>
        <label className="mb-3 block text-xs font-medium text-ink2">Email
          <input data-testid="login-email" className={`${inputCls} mt-1`} value={email} onChange={(e) => setEmail(e.target.value)} type="email" autoComplete="username" required />
        </label>
        <label className="mb-4 block text-xs font-medium text-ink2">Password
          <input data-testid="login-password" className={`${inputCls} mt-1`} value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoComplete="current-password" required />
        </label>
        {needOtp && (
          <label className="mb-4 block text-xs font-medium text-ink2">Authentication code (or recovery code)
            <input className={`${inputCls} mt-1`} value={otp} onChange={(e) => setOtp(e.target.value)} inputMode="text" autoComplete="one-time-code" autoFocus required />
          </label>
        )}
        {err && <div className="mb-3"><Notice kind="error" testId="login-error">{err}</Notice></div>}
        <button data-testid="login-submit" className={`${btnPrimary} w-full`} disabled={busy}>{busy ? "Signing in…" : "Sign In"}</button>
        </>}
        {!pwForm && err && <div className="mb-3"><Notice kind="error" testId="login-error">{err}</Notice></div>}
        <p className="mt-4 text-center text-[11px] text-ink3">Access is limited to authorised users. Activity is logged.</p>
      </form>
    </main>
  );
}
