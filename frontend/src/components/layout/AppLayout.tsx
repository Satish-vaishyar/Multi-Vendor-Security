import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Activity, BrainCircuit, Bug, ClipboardCheck, FileCode, FileText,
  KeyRound, LayoutDashboard, LogOut, Menu, Monitor, Moon, Search, Server,
  Settings as SettingsIcon, ShieldCheck, Sun, TriangleAlert, Wrench,
} from "lucide-react";
import { useAuth } from "../../stores/auth";
import { useUi, type ThemePref } from "../../stores/ui";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/assets", label: "Assets", icon: Server },
  { to: "/configurations/upload", label: "Configurations", icon: FileCode },
  { to: "/audits", label: "Audits", icon: ClipboardCheck },
  { to: "/compliance", label: "Compliance", icon: ShieldCheck },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
  { to: "/pqc", label: "PQC Security", icon: KeyRound },
  { to: "/analytics", label: "Security Analytics", icon: Activity },
  { to: "/findings", label: "Findings", icon: TriangleAlert },
  { to: "/training", label: "AI Training", icon: BrainCircuit },
  { to: "/remediation", label: "Remediation", icon: Wrench },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

function ThemeSwitcher() {
  const { theme, setTheme } = useUi();
  const opts: { v: ThemePref; icon: typeof Sun; label: string }[] = [
    { v: "light", icon: Sun, label: "Light" },
    { v: "dark", icon: Moon, label: "Dark" },
    { v: "system", icon: Monitor, label: "System" },
  ];
  return (
    <div className="flex items-center rounded-lg border border-line bg-surface2 p-0.5" title="Theme: Light | Dark | System">
      {opts.map((o) => (
        <button
          key={o.v}
          onClick={() => setTheme(o.v)}
          title={o.label}
          className={`rounded-md p-1.5 ${theme === o.v ? "bg-surface text-ink shadow-sm" : "text-ink3 hover:text-ink2"}`}
        >
          <o.icon size={15} />
        </button>
      ))}
    </div>
  );
}

export default function AppLayout() {
  const { user, logout } = useAuth();
  const { sidebarOpen, toggleSidebar } = useUi();
  const nav = useNavigate();
  const [search, setSearch] = useState("");

  const onLogout = () => {
    logout();
    nav("/login");
  };

  const onSearch = (e: React.FormEvent) => {
    e.preventDefault();
    nav(search.trim() ? `/assets?q=${encodeURIComponent(search.trim())}` : "/assets");
  };

  return (
    <div className="min-h-screen bg-canvas">
      <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-line bg-surface px-4">
        <button onClick={toggleSidebar} className="rounded-md p-1.5 text-ink3 hover:bg-surface2" title="Toggle sidebar">
          <Menu size={18} />
        </button>
        <div className="flex items-center gap-2">
          <span className="rounded-md bg-primary p-1.5"><ShieldCheck size={16} className="text-onprimary" /></span>
          <span className="text-sm font-semibold tracking-widest text-ink">QIROVA</span>
          <span className="hidden text-xs text-ink3 lg:inline">Network Security Compliance Auditor</span>
        </div>
        <form onSubmit={onSearch} className="mx-auto hidden w-full max-w-sm items-center md:flex">
          <div className="relative w-full">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink3" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search assets…"
              className="w-full rounded-lg border border-line bg-canvas py-1.5 pl-9 pr-3 text-sm text-ink placeholder:text-ink3/70 outline-none focus:border-primary"
            />
          </div>
        </form>
        <div className="ml-auto flex items-center gap-2.5 text-sm md:ml-0">
          <ThemeSwitcher />
          <span className="hidden text-ink2 sm:inline">
            {user?.name ?? "—"} <span className="text-ink3">({user?.role ?? "—"})</span>
          </span>
          <button onClick={onLogout} className="flex items-center gap-1.5 rounded-lg border border-linestrong bg-surface px-3 py-1.5 text-xs font-semibold text-ink2 hover:bg-surface2">
            <LogOut size={14} /> Logout
          </button>
        </div>
      </header>

      <div className="flex">
        {sidebarOpen && (
          <aside className="sticky top-14 hidden h-[calc(100vh-3.5rem)] w-60 shrink-0 overflow-y-auto border-r border-line bg-surface py-3 md:block">
            <nav className="space-y-0.5 px-2">
              {NAV.map((n) => (
                <NavLink
                  key={n.to}
                  to={n.to}
                  className={({ isActive }) =>
                    `relative flex items-center gap-2.5 rounded-r-md px-3 py-2 text-[13px] font-medium ${
                      isActive
                        ? "bg-primarylight text-primary before:absolute before:left-0 before:top-1 before:bottom-1 before:w-[3px] before:rounded-full before:bg-primary"
                        : "text-ink2 hover:bg-surface2"
                    }`
                  }
                >
                  <n.icon size={16} />
                  {n.label}
                </NavLink>
              ))}
            </nav>
          </aside>
        )}
        <main className="min-w-0 flex-1 p-4 md:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
