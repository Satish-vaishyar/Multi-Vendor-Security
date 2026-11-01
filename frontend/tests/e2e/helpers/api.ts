import { APIRequestContext, request as pwRequest } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';

/** Direct backend access for test set-up / assertions that the UI is not the subject of. */
export const API = process.env.QA_API_URL ?? 'http://127.0.0.1:8000/api/v1';
export const ADMIN_EMAIL = process.env.QA_ADMIN_EMAIL ?? 'qa-admin@example.com';
export const ADMIN_PASSWORD = process.env.QA_ADMIN_PASSWORD ?? 'QaAdmin-Passw0rd!2026';
/** Strong password used for every test-created user (>= 12 chars, 3 of 4 classes). */
export const USER_PASSWORD = 'Qa-Tester-Passw0rd!77';
export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
export const CORPUS_DIR = path.join(REPO_ROOT, 'okf', 'tests', 'corpus');

export type Role = 'VIEWER' | 'AUDITOR' | 'APPROVER' | 'ADMIN';

export const uniq = (p = 'qa') => `${p}-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;

export async function newApi(): Promise<APIRequestContext> {
  return pwRequest.newContext({ baseURL: API + '/' });
}

/** POST /auth/login. Returns the bearer token (dev builds use bearer mode). */
export async function login(api: APIRequestContext, email: string, password: string, otp?: string): Promise<string> {
  const r = await api.post('auth/login', { data: { email, password, ...(otp ? { otp } : {}) } });
  if (!r.ok()) throw new Error(`login ${email} failed: ${r.status()} ${await r.text()}`);
  return (await r.json()).data.access_token as string;
}

export class Client {
  constructor(public api: APIRequestContext, public token: string) {}
  private h() {
    return { Authorization: `Bearer ${this.token}` };
  }
  async get(url: string, params?: Record<string, string | number>) {
    return this.api.get(url.replace(/^\//, ''), { headers: this.h(), params });
  }
  async post(url: string, data?: unknown) {
    return this.api.post(url.replace(/^\//, ''), { headers: this.h(), data });
  }
  async patch(url: string, data?: unknown) {
    return this.api.patch(url.replace(/^\//, ''), { headers: this.h(), data });
  }
  async json<T = any>(r: Awaited<ReturnType<Client['get']>>): Promise<T> {
    if (!r.ok()) throw new Error(`${r.url()} -> ${r.status()} ${await r.text()}`);
    const b = await r.json();
    return (b && typeof b === 'object' && 'data' in b ? b.data : b) as T;
  }
  async createAsset(name: string, extra: Record<string, unknown> = {}) {
    return this.json<{ asset_id: string }>(await this.post('assets', { name, vendor: '', product: '', version: '', criticality: 'MEDIUM', ...extra }));
  }
  async upload(assetId: string, filePath: string) {
    const r = await this.api.post('configurations/upload', {
      headers: this.h(),
      multipart: { asset_id: assetId, file: { name: path.basename(filePath), mimeType: 'text/plain', buffer: fs.readFileSync(filePath) } },
      timeout: 120_000,
    });
    return this.json<any>(r);
  }
  async audit(assetId: string, configId: string) {
    const r = await this.post('audits', {
      asset_id: assetId, configuration_id: configId, frameworks: ['CIS', 'NIST', 'STIG', 'ISO27001'],
      run_cve: true, run_pqc: true, run_security_analysis: true, generate_report: false,
    });
    return this.json<{ audit_id: string; status: string }>(r);
  }
  async results(auditId: string) {
    return this.json<any>(await this.get(`audits/${auditId}/results`));
  }
  /** upload + audit one corpus-style file; returns ids and results */
  async auditFile(name: string, filePath: string) {
    const a = await this.createAsset(name);
    const cfg = await this.upload(a.asset_id, filePath);
    const aud = await this.audit(a.asset_id, cfg.configuration_id);
    return { asset_id: a.asset_id, configuration_id: cfg.configuration_id as string, detected_vendor: cfg.detected_vendor as string, audit_id: aud.audit_id };
  }
  async createUser(role: Role, prefix = role.toLowerCase(), mustChange = false) {
    const email = `${uniq(prefix)}@example.com`;
    await this.json(await this.post('admin/users', { email, name: `QA ${role}`, password: USER_PASSWORD, role, must_change_password: mustChange }));
    return { email, password: USER_PASSWORD, role };
  }
}

export async function adminClient(): Promise<Client> {
  const api = await newApi();
  return new Client(api, await login(api, ADMIN_EMAIL, ADMIN_PASSWORD));
}

export async function loginClient(email: string, password = USER_PASSWORD): Promise<Client> {
  const api = await newApi();
  return new Client(api, await login(api, email, password));
}

export function corpusFiles(): string[] {
  return fs.readdirSync(CORPUS_DIR).filter((f) => f.endsWith('.cfg')).sort();
}

/**
 * Creates a brand-new organisation with one ADMIN whose password must be changed at first login, through the
 * product's own CLI (the same path an operator uses). Local test database only.
 */
export function createFreshOrg(): { email: string; password: string; orgId: string } {
  const orgId = `ORG-QA-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
  const email = `${uniq('fresh-admin')}@example.com`;
  const backend = path.join(REPO_ROOT, 'backend');
  const py = fs.existsSync(path.join(backend, '.venv', 'Scripts', 'python.exe'))
    ? path.join(backend, '.venv', 'Scripts', 'python.exe')
    : path.join(backend, '.venv', 'bin', 'python');
  const env = {
    ...process.env,
    DATABASE_URL: process.env.QA_DATABASE_URL ?? 'postgresql://postgres:postgres@localhost:55432/auditor_test_c',
    DATA_ENCRYPTION_KEYS: process.env.QA_FERNET ?? 'dbA2Y93JWXurTbPz93vW1QWBTiFnlf9sRvmVBevlAYs=',
    PASSWORD_HASH_ITERATIONS: '1000',
    ENV: 'development',
  };
  if (!/localhost|127\.0\.0\.1/.test(env.DATABASE_URL)) throw new Error('refusing to touch a non-local database');
  execFileSync(py, ['-m', 'app.cli', 'create-org', orgId, 'QA fresh organisation'], { cwd: backend, env });
  execFileSync(py, ['-m', 'app.cli', 'create-user', email, 'Fresh Admin', 'ADMIN', '--org', orgId], {
    cwd: backend, env, input: USER_PASSWORD + '\n',
  });
  return { email, password: USER_PASSWORD, orgId };
}
