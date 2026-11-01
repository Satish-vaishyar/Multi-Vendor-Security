export interface Seed {
  insecure: { asset_id: string; configuration_id: string; audit_id: string; detected_vendor: string };
  hardened: { asset_id: string; configuration_id: string; audit_id: string; detected_vendor: string };
  findingId?: string;
  controlId?: string;
}

/** Data created once by global-setup.ts. */
export function seed(): Seed {
  const raw = process.env.QA_SEED;
  if (!raw) throw new Error('QA_SEED missing - global-setup did not run');
  return JSON.parse(raw) as Seed;
}
