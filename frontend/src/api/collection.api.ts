import { api, unwrap } from "./client";

export interface CollectionProfile { key: string; label: string; commands: string[] }
export interface Credential { credential_id: string; name: string; username: string; auth_type: "password" | "key"; created_at: string }
export interface CollectionTarget {
  asset_id: string; host: string; port: number; profile: string; credential_id: string | null; host_key: string;
  last_collected_at: string | null; last_status: string | null; last_error: string | null;
}

export const listProfiles = async () => unwrap<CollectionProfile[]>((await api.get("/collection/profiles")).data);
export const listCredentials = async () => unwrap<{ items: Credential[] }>((await api.get("/collection/credentials")).data);
export const createCredential = async (b: { name: string; username: string; secret: string; auth_type: string }) =>
  unwrap<Credential>((await api.post("/collection/credentials", b)).data);
export const deleteCredential = async (id: string) => unwrap<{ deleted: boolean }>((await api.delete(`/collection/credentials/${id}`)).data);
export const getTarget = async (assetId: string): Promise<CollectionTarget | null> => {
  try { return unwrap<CollectionTarget>((await api.get(`/assets/${assetId}/collection`)).data); }
  catch (e) { if ((e as { response?: { status?: number } }).response?.status === 404) return null; throw e; }
};
export const scanHostKey = async (assetId: string, host: string, port: number) =>
  unwrap<{ fingerprint: string }>((await api.post(`/assets/${assetId}/collection/scan-host-key`, { host, port })).data);
export const saveTarget = async (assetId: string, b: { host: string; port: number; profile: string; credential_id: string | null; host_key: string }) =>
  unwrap<CollectionTarget>((await api.put(`/assets/${assetId}/collection`, b)).data);
export const collectNow = async (assetId: string, audit: boolean) =>
  unwrap<{ job_id: string }>((await api.post(`/assets/${assetId}/collect`, { audit })).data);
