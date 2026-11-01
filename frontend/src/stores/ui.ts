import { create } from "zustand";

export type ThemePref = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

const KEY = "qirova_theme";
const NAV_KEY = "qirova_nav_collapsed";

function read(key: string): string | null {
  try { return localStorage.getItem(key); } catch { return null; }
}
function write(key: string, value: string) {
  try { localStorage.setItem(key, value); } catch { /* storage blocked - non-fatal */ }
}

function resolve(pref: ThemePref): ResolvedTheme {
  if (pref === "system") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return pref;
}

function apply(resolved: ResolvedTheme) {
  document.documentElement.dataset.theme = resolved;
  document.documentElement.style.colorScheme = resolved;
}

function readCollapsed(): string[] {
  try { return JSON.parse(read(NAV_KEY) ?? "[]") as string[]; } catch { return []; }
}

interface UiState {
  /** desktop: sidebar visible */
  sidebarOpen: boolean;
  toggleSidebar: () => void;
  /** mobile: drawer visible */
  drawerOpen: boolean;
  setDrawer: (o: boolean) => void;
  paletteOpen: boolean;
  setPalette: (o: boolean) => void;
  /** nav sections the user collapsed (remembered) */
  collapsed: string[];
  toggleGroup: (id: string) => void;
  theme: ThemePref;
  resolved: ResolvedTheme;
  setTheme: (t: ThemePref) => void;
  initTheme: () => void;
}

export const useUi = create<UiState>((set, get) => ({
  sidebarOpen: read("qirova_sidebar") !== "closed",
  toggleSidebar: () => {
    const next = !get().sidebarOpen;
    write("qirova_sidebar", next ? "open" : "closed");
    set({ sidebarOpen: next });
  },
  drawerOpen: false,
  setDrawer: (o) => set({ drawerOpen: o }),
  paletteOpen: false,
  setPalette: (o) => set({ paletteOpen: o }),
  collapsed: readCollapsed(),
  toggleGroup: (id) => {
    const cur = get().collapsed;
    const next = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
    write(NAV_KEY, JSON.stringify(next));
    set({ collapsed: next });
  },
  theme: "system",
  resolved: "light",
  setTheme: (t) => {
    write(KEY, t);
    const r = resolve(t);
    apply(r);
    set({ theme: t, resolved: r });
  },
  initTheme: () => {
    const stored = (read(KEY) as ThemePref | null) ?? "system";
    const r = resolve(stored);
    apply(r);
    set({ theme: stored, resolved: r });
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
      const cur = (read(KEY) as ThemePref | null) ?? "system";
      if (cur === "system") {
        const next = e.matches ? "dark" : "light";
        apply(next);
        set({ resolved: next });
      }
    });
  },
}));
