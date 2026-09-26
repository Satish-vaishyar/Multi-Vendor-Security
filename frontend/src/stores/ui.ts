import { create } from "zustand";

export type ThemePref = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

const KEY = "qirova_theme";

function resolve(pref: ThemePref): ResolvedTheme {
  if (pref === "system") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return pref;
}

function apply(resolved: ResolvedTheme) {
  document.documentElement.dataset.theme = resolved;
}

interface UiState {
  sidebarOpen: boolean;
  toggleSidebar: () => void;
  theme: ThemePref;
  resolved: ResolvedTheme;
  setTheme: (t: ThemePref) => void;
  initTheme: () => void;
}

export const useUi = create<UiState>((set) => ({
  sidebarOpen: true,
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),
  theme: "system",
  resolved: "light",
  setTheme: (t) => {
    localStorage.setItem(KEY, t);
    const r = resolve(t);
    apply(r);
    set({ theme: t, resolved: r });
  },
  initTheme: () => {
    const stored = (localStorage.getItem(KEY) as ThemePref | null) ?? "system";
    const r = resolve(stored);
    apply(r);
    set({ theme: stored, resolved: r });
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
      const cur = (localStorage.getItem(KEY) as ThemePref | null) ?? "system";
      if (cur === "system") {
        const next = e.matches ? "dark" : "light";
        apply(next);
        set({ resolved: next });
      }
    });
  },
}));
