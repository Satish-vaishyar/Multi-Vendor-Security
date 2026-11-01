import { API_BASE, api, unwrap } from "./client";
import type { LoginResponse, User } from "../types";

export async function login(email: string, password: string, otp?: string): Promise<LoginResponse> {
  const r = await api.post("/auth/login", { email, password, ...(otp ? { otp } : {}) });
  return unwrap<LoginResponse>(r.data);
}

export async function me(): Promise<User> {
  const r = await api.get("/auth/me");
  return unwrap<User>(r.data);
}

/** Revokes the token server-side so a stolen copy stops working immediately. */
export async function logoutRequest(): Promise<void> {
  await api.post("/auth/logout");
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<LoginResponse> {
  const r = await api.post("/auth/change-password", {
    current_password: currentPassword,
    new_password: newPassword,
  });
  return unwrap<LoginResponse>(r.data);
}

export interface SsoConfig { enabled: boolean; provider: string; password_login: boolean }

export async function ssoConfig(): Promise<SsoConfig> {
  const r = await api.get("/auth/sso/config");
  return unwrap<SsoConfig>(r.data);
}

/** Full-page navigation (the identity provider takes over the browser); the session comes back as an httpOnly cookie. */
export const ssoLoginUrl = `${API_BASE}/auth/sso/login`;
