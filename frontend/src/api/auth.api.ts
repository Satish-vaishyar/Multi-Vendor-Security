import { api, unwrap } from "./client";
import type { LoginResponse, User } from "../types";

export async function login(email: string, password: string): Promise<LoginResponse> {
  const r = await api.post("/auth/login", { email, password });
  return unwrap<LoginResponse>(r.data);
}

export async function me(): Promise<User> {
  const r = await api.get("/auth/me");
  return unwrap<User>(r.data);
}
