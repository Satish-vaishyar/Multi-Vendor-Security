import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, setToken, toMessage, unwrap } from "../api/client";
import { Card, btnGhost, btnPrimary, inputCls } from "./common";
import { useAuth } from "../stores/auth";
import type { LoginResponse } from "../types";

interface Setup { secret: string; otpauth_uri: string }

/** Two-factor (TOTP) enrolment for the signed-in user. The server is the authority; this only drives the flow. */
export default function MfaCard() {
  const qc = useQueryClient();
  const { setSession, user } = useAuth();
  const st = useQuery({ queryKey: ["mfa"], queryFn: async () => unwrap<{ enabled: boolean; recovery_codes_left: number }>((await api.get("/auth/mfa")).data) });
  const [setup, setSetup] = useState<Setup | null>(null);
  const [code, setCode] = useState("");
  const [pw, setPw] = useState("");
  const [codes, setCodes] = useState<string[]>([]);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const adopt = (d: LoginResponse) => { setToken(d.access_token); setSession(d.access_token, { ...d.user, email: d.user.email }); void qc.invalidateQueries({ queryKey: ["mfa"] }); };
  const run = async (fn: () => Promise<void>) => { setBusy(true); setErr(""); try { await fn(); } catch (e) { setErr(toMessage(e)); } finally { setBusy(false); } };

  const start = () => run(async () => setSetup(unwrap<Setup>((await api.post("/auth/mfa/setup")).data)));
  const enable = () => run(async () => {
    const d = unwrap<LoginResponse & { recovery_codes: string[] }>((await api.post("/auth/mfa/enable", { code })).data);
    setCodes(d.recovery_codes); setSetup(null); setCode(""); adopt(d);
  });
  const disable = () => run(async () => {
    adopt(unwrap<LoginResponse>((await api.post("/auth/mfa/disable", { password: pw, code })).data));
    setCode(""); setPw("");
  });

  const enabled = st.data?.enabled;
  return (
    <Card title="Two-factor authentication" sub={enabled ? `Enabled · ${st.data?.recovery_codes_left ?? 0} recovery codes left` : "Protect your account with an authenticator app (TOTP)."}>
      {user?.role === "ADMIN" && !enabled && <p className="mb-2 rounded-lg border border-warn/30 bg-warnbg p-2 text-xs text-warn">Administrators must enable two-factor authentication before using the rest of the app.</p>}
      {codes.length > 0 && (
        <div className="mb-3 rounded-lg border border-warn/30 bg-warnbg p-3 text-xs text-warn">
          <b>Recovery codes - save them now, they are shown only once.</b>
          <ul className="mt-1 grid grid-cols-2 gap-1 font-mono text-ink">{codes.map((c) => <li key={c} className="select-all">{c}</li>)}</ul>
        </div>
      )}
      {!enabled && !setup && <button className={btnPrimary} disabled={busy} onClick={() => void start()}>Set up authenticator</button>}
      {setup && (
        <div className="space-y-2 text-xs text-ink2">
          <p>Add this key to your authenticator app (or open the link on your phone), then enter the 6-digit code.</p>
          <p className="break-all font-mono text-ink select-all">{setup.secret}</p>
          <a className="text-primary underline" href={setup.otpauth_uri}>Open in authenticator</a>
          <div className="flex gap-2">
            <input className={inputCls} aria-label="6-digit authentication code" inputMode="numeric" autoComplete="one-time-code" placeholder="123456" value={code} onChange={(e) => setCode(e.target.value)} />
            <button className={btnPrimary} disabled={busy || code.length < 6} onClick={() => void enable()}>Confirm</button>
          </div>
        </div>
      )}
      {enabled && (
        <div className="space-y-2 text-xs text-ink2">
          <p>To turn it off, confirm your password and a current code (or a recovery code).</p>
          <div className="flex flex-wrap gap-2">
            <input className={inputCls} aria-label="Current password" type="password" placeholder="Password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} />
            <input className={inputCls} aria-label="Authentication or recovery code" placeholder="Code" value={code} onChange={(e) => setCode(e.target.value)} />
            <button className={btnGhost} disabled={busy || !pw || !code} onClick={() => void disable()}>Disable</button>
          </div>
        </div>
      )}
      {err && <p role="alert" className="mt-2 rounded-lg border border-danger/30 bg-dangerbg p-2 text-xs text-danger">{err}</p>}
    </Card>
  );
}
