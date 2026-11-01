import { test, expect } from '@playwright/test';
import { adminClient, Client, loginClient } from './helpers/api';
import { seed } from './helpers/seed';
import { heading, seedSession } from './helpers/ui';

test.describe('RBAC: a VIEWER gets a read-only product with friendly messages', () => {
  let viewer: Client;
  let viewerEmail: string;

  test.beforeAll(async () => {
    const admin = await adminClient();
    viewerEmail = (await admin.createUser('VIEWER', 'viewer')).email;
    viewer = await loginClient(viewerEmail);
  });

  test.beforeEach(async ({ page }) => {
    await seedSession(page, viewer.token);
  });

  test('navigation hides upload, integrations and administration', async ({ page }) => {
    await page.goto('/dashboard');
    await heading(page, /security overview/i);
    const nav = page.getByRole('navigation', { name: 'Main' });
    await expect(nav.getByRole('link', { name: 'Dashboard' })).toBeVisible();
    await expect(nav.getByRole('link', { name: 'Findings' })).toBeVisible();
    for (const hidden of ['Upload & audit', 'Integrations', 'Administration']) {
      await expect(nav.getByRole('link', { name: hidden }), hidden).toHaveCount(0);
    }
    // the command palette honours the same rules
    await page.keyboard.press('Control+k');
    const dialog = page.getByRole('dialog', { name: 'Quick search' });
    await dialog.getByRole('combobox').fill('administration');
    await expect(dialog.getByText(/nothing matches/i)).toBeVisible();
    await page.keyboard.press('Escape');
  });

  test('admin-only pages bounce to the dashboard', async ({ page }) => {
    for (const p of ['/admin', '/integrations']) {
      await page.goto(p);
      await expect(page, p).toHaveURL(/\/dashboard/);
    }
  });

  test('no upload actions: audits list, get started, risk acceptance and schedules are read-only', async ({ page }) => {
    await page.goto('/audits');
    await heading(page, /audit results/i);
    await expect(page.getByRole('link', { name: /upload/i })).toHaveCount(0);

    await page.goto('/get-started');
    await expect(page.getByRole('link', { name: 'Upload a config' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: /try a sample config/i })).toHaveCount(0);

    await page.goto('/quick-audit'); // direct URL: server stays the authority
    await page.getByTestId('quick-file-input').setInputFiles({ name: 'x.cfg', mimeType: 'text/plain', buffer: Buffer.from('hostname x\n') });
    await page.getByTestId('quick-run').click();
    await expect(page.getByTestId('quick-error')).toContainText(/do not have permission/i);

    await page.goto('/exceptions');
    await heading(page, /risk acceptance/i);
    await expect(page.getByText('Request an exception')).toHaveCount(0);

    await page.goto('/schedules');
    await heading(page, /recurring audits/i);
    await expect(page.getByText('New recurring audit')).toHaveCount(0);
  });

  test('forbidden actions give a plain-language message, not a raw server error', async ({ page }) => {
    await page.goto('/reports');
    await heading(page, /reports/i);
    await page.getByTestId('report-audit-id').fill(seed().insecure.audit_id);
    await page.getByTestId('report-generate').click();
    const err = page.getByTestId('report-error');
    await expect(err).toBeVisible();
    await expect(err).toContainText(/do not have permission/i);
    await expect(err).toContainText(/AUDITOR/);
    await expect(err).not.toContainText(/Requires role|403|HTTP_/);
  });

  test('server enforces roles and masks secrets for viewers', async () => {
    const admin = await adminClient();
    const s = seed();
    for (const [method, url] of [['post', 'assets'], ['post', 'audits'], ['post', 'reports'], ['get', 'admin/users'], ['get', 'integrations/webhooks'], ['post', 'exceptions']] as const) {
      const r = method === 'post' ? await viewer.post(url, {}) : await viewer.get(url);
      expect(r.status(), `${method} ${url}`).toBe(403);
    }
    const cfgId = s.insecure.configuration_id;
    const asAdmin = await admin.json<any>(await admin.get(`configurations/${cfgId}`));
    const asViewer = await viewer.json<any>(await viewer.get(`configurations/${cfgId}`));
    expect(asAdmin.config_text).toContain('Cisco123');
    expect(asViewer.config_text).not.toContain('Cisco123');
    expect(asViewer.config_text).not.toContain('045802150C2E1D1C5A');
    // other read endpoints derived from the config text must not leak what the viewer's raw view hides
    for (const url of [`configurations/${cfgId}/canonical-ir`, `audits/${s.insecure.audit_id}/results`, `audits/${s.insecure.audit_id}/evidence`]) {
      const body = JSON.stringify(await viewer.json(await viewer.get(url)));
      expect(body, url).not.toContain('Cisco123');
      expect(body, url).not.toContain('045802150C2E1D1C5A');
    }
  });
});
