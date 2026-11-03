import { api, unwrap } from "./client";
import type { Asset, Paged } from "../types";

export interface AssetFilters {
  page?: number;
  page_size?: number;
  vendor?: string;
  status?: string;
  q?: string;
  sort?: string;
  order?: "asc" | "desc";
}

export async function listAssets(f: AssetFilters = {}): Promise<Paged<Asset>> {
  const r = await api.get("/assets", {
    params: {
      page: f.page ?? 1, page_size: f.page_size ?? 20, vendor: f.vendor || undefined, status: f.status || undefined,
      q: f.q || undefined, sort: f.sort || undefined, order: f.order || undefined,
    },
  });
  // search/sort/paging are all server-side now
  return unwrap<Paged<Asset>>(r.data);
}

export async function getAsset(id: string): Promise<Asset> {
  const r = await api.get(`/assets/${id}`);
  return unwrap<Asset>(r.data);
}

/** Create with the backend message kept — tells "created" apart from "reused existing". */
export async function createAssetFull(body: Record<string, unknown>): Promise<{ data: Asset; message: string; reused: boolean }> {
  const r = await api.post("/assets", body);
  const message = String((r.data as { message?: string })?.message ?? "");
  return { data: unwrap<Asset>(r.data), message, reused: /already exists|reusing/i.test(message) };
}

export async function mergeDuplicateAssets(): Promise<{ groups: unknown[]; total_merged: number }> {
  const r = await api.post("/assets/merge-duplicates");
  return unwrap<{ groups: unknown[]; total_merged: number }>(r.data);
}

export async function patchAsset(id: string, body: Record<string, unknown>): Promise<Asset> {
  const r = await api.patch(`/assets/${id}`, body);
  return unwrap<Asset>(r.data);
}

export async function deleteAsset(id: string): Promise<unknown> {
  const r = await api.delete(`/assets/${id}`);
  return unwrap(r.data);
}
