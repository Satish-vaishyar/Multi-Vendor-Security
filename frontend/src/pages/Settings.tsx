import { Card, PageHeader, inputCls } from "../components/common";
import { Link } from "react-router-dom";
import { useAuth } from "../stores/auth";
import { useUi } from "../stores/ui";
import MfaCard from "../components/MfaCard";

export default function Settings() {
  const base = import.meta.env.VITE_API_BASE_URL as string | undefined;
  const origin = (base ?? "").replace(/\/api\/v1\/?$/, "");
  const { theme, setTheme } = useUi();
  const user = useAuth((s) => s.user);
  return (
    <div>
      <PageHeader title="Settings" sub="Your account, appearance and sign-in security." />
      <div className="grid gap-4 lg:grid-cols-2">
        <MfaCard />
        <Card title="Appearance">
          <p className="mb-2 text-xs uppercase tracking-wider text-ink3">Theme</p>
          <div className="flex gap-2">
            {(["light", "dark", "system"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTheme(t)}
                className={`rounded-lg border px-4 py-2 text-sm font-semibold capitalize ${theme === t ? "border-primary bg-primarylight text-primary" : "border-linestrong bg-surface text-ink2 hover:bg-surface2"}`}
              >
                {t === "light" ? "☀ Light" : t === "dark" ? "☾ Dark" : "◐ System"}
              </button>
            ))}
          </div>
          <p className="mt-2 text-xs text-ink3">System follows your OS preference. Choice persists in localStorage.</p>
        </Card>
        <Card title="Account">
          <p className="text-sm text-ink">{user?.name} <span className="text-ink3">· {user?.email}</span></p>
          <p className="mt-1 text-xs text-ink3">Role: {user?.role} · Organisation: {user?.org_id ?? "—"}</p>
          <Link to="/change-password" className="mt-3 inline-block text-sm font-semibold text-primary hover:underline">
            Change password
          </Link>
        </Card>
        <Card title="Backend Connection">
          <p className="text-xs uppercase tracking-wider text-ink3">API base URL (from .env, never hardcoded)</p>
          <input className={`${inputCls} mt-1 font-mono`} aria-label="API base URL" value={base ?? ""} readOnly />
          {import.meta.env.DEV && (
            <p className="mt-2 text-xs text-ink3">
              Interactive docs (development only):{" "}
              <a className="text-primary hover:underline" href={`${origin}/docs`} target="_blank" rel="noreferrer">/docs</a> ·{" "}
              Spec: <a className="text-primary hover:underline" href={`${origin}/openapi.json`} target="_blank" rel="noreferrer">openapi.json</a>
            </p>
          )}
        </Card>
      </div>
    </div>
  );
}
