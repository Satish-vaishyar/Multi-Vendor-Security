import { Fragment, Suspense, lazy, useEffect, useRef } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { ChevronDown, ChevronRight, LogOut, Menu, Monitor, Moon, PanelLeftClose, PanelLeftOpen, Search, ShieldCheck, Sun, X } from "lucide-react";
import { useAuth } from "../../stores/auth";
import { useUi, type ThemePref } from "../../stores/ui";
import { Loader } from "../common";
import { crumbsFor, visibleGroups } from "./nav";

const CommandPalette = lazy(() => import("./CommandPalette"));

const isMac = typeof navigator !== "undefined" && /mac/i.test(navigator.platform);

function ThemeSwitcher() {
  const { theme, setTheme } = useUi();
  const opts: { v: ThemePref; icon: typeof Sun; label: string }[] = [
    { v: "light", icon: Sun, label: "Light" },
    { v: "dark", icon: Moon, label: "Dark" },
    { v: "system", icon: Monitor, label: "System" },
  ];
  return (
    <div role="group" aria-label="Colour theme" className="flex items-center rounded-lg bg-surface2 p-0.5">
      {opts.map((o) => (
        <button
          key={o.v}
          type="button"
          onClick={() => setTheme(o.v)}
          title={`${o.label} theme`}
          aria-label={`${o.label} theme`}
          aria-pressed={theme === o.v}
          className={`rounded-md p-1.5 transition-colors ${theme === o.v ? "bg-surface text-ink shadow-sm" : "text-ink3 hover:text-ink"}`}
        >
          <o.icon size={14} aria-hidden="true" />
        </button>
      ))}
    </div>
  );
}

function SideNav({ onNavigate }: { onNavigate?: () => void }) {
  const role = useAuth((s) => s.user?.role);
  const { pathname } = useLocation();
  const { collapsed, toggleGroup } = useUi();
  const groups = visibleGroups(role);
  return (
    <nav aria-label="Main" className="space-y-1 px-2 pb-6">
      {groups.map((g) => {
        const hasActive = g.items.some((i) => pathname === i.to || pathname.startsWith(i.to + "/"));
        const open = !collapsed.includes(g.id) || hasActive;
        const panel = `nav-${g.id}`;
        return (
          <div key={g.id}>
            <button
              type="button"
              onClick={() => toggleGroup(g.id)}
              aria-expanded={open}
              aria-controls={panel}
              className="flex w-full items-center justify-between rounded-md px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-ink3 hover:text-ink"
            >
              {g.label}
              {open ? <ChevronDown size={12} aria-hidden="true" /> : <ChevronRight size={12} aria-hidden="true" />}
            </button>
            {open && (
              <ul id={panel} className="mb-2 space-y-0.5">
                {g.items.map((n) => (
                  <li key={n.to}>
                    <NavLink
                      to={n.to}
                      title={n.desc}
                      onClick={onNavigate}
                      className={({ isActive }) =>
                        `flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] font-medium transition-colors ${
                          isActive ? "bg-primarylight text-primary" : "text-ink2 hover:bg-surface2 hover:text-ink"
                        }`
                      }
                    >
                      <n.icon size={16} aria-hidden="true" className="shrink-0" />
                      <span className="truncate">{n.label}</span>
                    </NavLink>
                  </li>
                ))}
              </ul>
            )}
          </div>
        );
      })}
    </nav>
  );
}

function Breadcrumbs() {
  const { pathname } = useLocation();
  const trail = crumbsFor(pathname);
  if (!trail.length) return null;
  const shown = trail.length > 1 && trail[0].label === trail[1].label ? trail.slice(1) : trail;
  return (
    <nav aria-label="Breadcrumb" className="mb-4 text-xs text-ink3">
      <ol className="flex flex-wrap items-center gap-1">
        {shown.map((c, i) => (
          <Fragment key={`${c.label}-${i}`}>
            {i > 0 && <ChevronRight size={11} aria-hidden="true" />}
            <li aria-current={i === shown.length - 1 ? "page" : undefined}>
              {c.to ? <Link to={c.to} className="hover:text-primary hover:underline">{c.label}</Link> : <span className={i === shown.length - 1 ? "text-ink2" : ""}>{c.label}</span>}
            </li>
          </Fragment>
        ))}
      </ol>
    </nav>
  );
}

export default function AppLayout() {
  const { user, logout } = useAuth();
  const { sidebarOpen, toggleSidebar, drawerOpen, setDrawer, paletteOpen, setPalette } = useUi();
  const nav = useNavigate();
  const { pathname } = useLocation();
  const closeRef = useRef<HTMLButtonElement>(null);
  const mainRef = useRef<HTMLElement>(null);

  // New route: close the drawer, scroll to top.
  useEffect(() => {
    setDrawer(false);
    window.scrollTo(0, 0);
  }, [pathname, setDrawer]);

  // Each page gets its own document title (WCAG 2.4.2; also what the browser history and tabs show).
  useEffect(() => {
    const trail = crumbsFor(pathname);
    const label = trail.length ? trail[trail.length - 1].label : "";
    document.title = label ? `${label} · QIROVA` : "QIROVA · Network Security Compliance Auditor";
  }, [pathname]);

  // Global shortcut: Ctrl/Cmd+K opens quick search.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setPalette]);

  // Mobile drawer: Esc closes, focus moves in.
  useEffect(() => {
    if (!drawerOpen) return;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setDrawer(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawerOpen, setDrawer]);

  const onLogout = () => {
    logout();
    nav("/login");
  };

  return (
    <div className="min-h-screen bg-canvas">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-primary focus:px-3 focus:py-2 focus:text-onprimary">Skip to content</a>
      <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b border-line bg-surface px-3 sm:gap-3 sm:px-4">
        <button onClick={() => setDrawer(true)} className="rounded-md p-2 text-ink2 hover:bg-surface2 lg:hidden" aria-label="Open menu">
          <Menu size={18} aria-hidden="true" />
        </button>
        <button onClick={toggleSidebar} className="hidden rounded-md p-2 text-ink2 hover:bg-surface2 lg:block" aria-label={sidebarOpen ? "Hide sidebar" : "Show sidebar"} aria-pressed={sidebarOpen}>
          {sidebarOpen ? <PanelLeftClose size={18} aria-hidden="true" /> : <PanelLeftOpen size={18} aria-hidden="true" />}
        </button>
        <Link to="/dashboard" className="flex items-center gap-2">
          <span className="rounded-md bg-primary p-1.5"><ShieldCheck size={16} className="text-onprimary" aria-hidden="true" /></span>
          <span className="text-sm font-semibold tracking-widest text-ink">QIROVA</span>
        </Link>

        <button
          onClick={() => setPalette(true)}
          className="mx-auto hidden w-full max-w-sm items-center gap-2 rounded-lg border border-line bg-canvas px-3 py-1.5 text-left text-sm text-ink3 hover:border-linestrong md:flex"
          aria-label="Quick search: pages and devices"
        >
          <Search size={14} aria-hidden="true" />
          <span className="flex-1 truncate">Jump to a page or device…</span>
          <kbd className="rounded border border-line bg-surface px-1.5 text-[10px] font-medium text-ink3">{isMac ? "⌘" : "Ctrl"} K</kbd>
        </button>

        <div className="ml-auto flex items-center gap-2 text-sm md:ml-0">
          <button onClick={() => setPalette(true)} className="rounded-md p-2 text-ink2 hover:bg-surface2 md:hidden" aria-label="Quick search">
            <Search size={18} aria-hidden="true" />
          </button>
          <ThemeSwitcher />
          <span className="hidden text-ink2 lg:inline">
            {user?.name ?? "—"} <span className="text-ink3">· {String(user?.role ?? "—").toLowerCase()}</span>
          </span>
          <button onClick={onLogout} className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold text-ink2 hover:bg-surface2" aria-label="Log out">
            <LogOut size={14} aria-hidden="true" /> <span className="hidden sm:inline">Logout</span>
          </button>
        </div>
      </header>

      <div className="flex">
        {sidebarOpen && (
          <aside className="sticky top-14 hidden h-[calc(100vh-3.5rem)] w-60 shrink-0 overflow-y-auto border-r border-line bg-surface pt-3 lg:block">
            <SideNav />
          </aside>
        )}
        <main id="main" ref={mainRef} tabIndex={-1} className="min-w-0 flex-1 px-4 py-5 outline-none sm:px-6 md:py-7 lg:px-8">
          <div className="mx-auto w-full max-w-[1400px]">
            <Breadcrumbs />
            <div key={pathname} className="page-enter">
              <Suspense fallback={<Loader label="Loading page…" />}>
                <Outlet />
              </Suspense>
            </div>
          </div>
        </main>
      </div>

      {drawerOpen && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Menu">
          <div className="absolute inset-0 bg-ink/40" onClick={() => setDrawer(false)} aria-hidden="true" />
          <aside className="absolute inset-y-0 left-0 flex w-72 max-w-[85vw] flex-col bg-surface shadow-[var(--shadow-pop)]">
            <div className="flex h-14 items-center justify-between border-b border-line px-4">
              <span className="text-sm font-semibold tracking-widest text-ink">QIROVA</span>
              <button ref={closeRef} onClick={() => setDrawer(false)} className="rounded-md p-2 text-ink2 hover:bg-surface2" aria-label="Close menu">
                <X size={18} aria-hidden="true" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto pt-3">
              <SideNav onNavigate={() => setDrawer(false)} />
            </div>
          </aside>
        </div>
      )}

      {paletteOpen && (
        <Suspense fallback={null}>
          <CommandPalette onClose={() => setPalette(false)} />
        </Suspense>
      )}
    </div>
  );
}
