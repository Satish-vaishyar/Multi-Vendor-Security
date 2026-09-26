/* Single Axios instance for the whole app (frontend.md §6).
   Handles base URL, JWT, JSON headers, 401 redirect and the common envelope. */
import axios, { AxiosError } from "axios";

const baseURL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ??
  "http://127.0.0.1:8000/api/v1";

export const TOKEN_KEY = "sih26155_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(t: string) {
  localStorage.setItem(TOKEN_KEY, t);
}
export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export const api = axios.create({
  baseURL,
  headers: { "Content-Type": "application/json" },
  timeout: 60000,
});

/* Cold backend calls (first upload / audit / unknowns) lazily load ML + OKF
   layers in-request and can exceed the default 60 s. Use SLOW_TIMEOUT for them. */
export const SLOW_TIMEOUT = 300000;

api.interceptors.request.use((cfg) => {
  const t = getToken();
  if (t) cfg.headers.Authorization = `Bearer ${t}`;
  return cfg;
});

export interface BackendError {
  code: string;
  message: string;
}

export function toMessage(err: unknown): string {
  const ax = err as AxiosError<{ success?: boolean; error?: BackendError; detail?: string }>;
  const data = ax?.response?.data;
  if (data?.error?.message) {
    const code = data.error.code ?? "";
    // Map raw backend codes to user-friendly text (frontend.md §44)
    const map: Record<string, string> = {
      AUDIT_NOT_FOUND: "Audit not found. It may have been deleted or you lack access.",
      INVALID_CONFIGURATION: "This configuration could not be parsed. Try another file.",
    };
    if (code && map[code]) return map[code];
    return data.error.message;
  }
  if (typeof data?.detail === "string") return data.detail;
  if (ax?.code === "ECONNABORTED") return "Request timed out. The backend may be busy — retry.";
  if (ax?.message === "Network Error") return "Cannot reach the backend API. Is it running on port 8000?";
  return ax?.message ?? "Something went wrong. Please retry.";
}

api.interceptors.response.use(
  (r) => r,
  (err: AxiosError) => {
    if (err?.response?.status === 401 && !window.location.pathname.startsWith("/login")) {
      clearToken();
      window.location.href = "/login";
    }
    return Promise.reject(err);
  },
);

/** Unwrap the common envelope {success, data} — falls back to raw payload. */
export function unwrap<T>(payload: { success?: boolean; data?: T } | T): T {
  if (payload && typeof payload === "object" && "data" in (payload as Record<string, unknown>)) {
    return (payload as { data: T }).data;
  }
  return payload as T;
}
