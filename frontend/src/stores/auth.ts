import { create } from "zustand";
import { clearToken, getToken, setToken } from "../api/client";
import { me } from "../api/auth.api";
import type { User } from "../types";

interface AuthState {
  token: string | null;
  user: User | null;
  ready: boolean;
  setSession: (token: string, user: User | null) => void;
  bootstrap: () => Promise<void>;
  logout: () => void;
}

export const useAuth = create<AuthState>((set) => ({
  token: getToken(),
  user: null,
  ready: false,
  setSession: (token, user) => {
    setToken(token);
    set({ token, user, ready: true });
  },
  bootstrap: async () => {
    const t = getToken();
    if (!t) {
      set({ token: null, user: null, ready: true });
      return;
    }
    try {
      const u = await me();
      set({ token: t, user: u, ready: true });
    } catch {
      clearToken();
      set({ token: null, user: null, ready: true });
    }
  },
  logout: () => {
    clearToken();
    set({ token: null, user: null, ready: true });
  },
}));
