import { test, expect } from '@playwright/test';
import { createFreshOrg, loginClient } from './helpers/api';
import { heading, uiLogin, watchHealth } from './helpers/ui';

/**
 * Journey 1: a brand-new organisation. The admin is created through the CLI (as an operator would), must change the
 * issued password at first login, then lands on an empty product that guides them: Get started -> Quick audit.
 */
test.describe.serial('Journey: first run of a brand-new organisation', () => {
  let org: { email: string; password: string; orgId: string };

  test.beforeAll(() => {
    org = createFreshOrg();
  });

  test('forced password change, with validation, then dashboard', async ({ page }) => {
    await uiLogin(page, org.email, org.password);
    await expect(page).toHaveURL(/\/change-password/);
    await heading(page, /choose a new password/i);

    // A guarded route cannot be used before the password is replaced.
    await page.goto('/findings');
    await expect(page).toHaveURL(/\/change-password/);

    const cur = page.getByLabel('Current password');
    const next = page.getByLabel('New password', { exact: true });
    const again = page.getByLabel('Repeat new password');
    const submit = page.getByRole('button', { name: /update password/i });

    await cur.fill(org.password);
    await next.fill('short');
    await again.fill('short');
    await submit.click();
    await expect(page.getByRole('alert')).toContainText(/use at least 12 characters/i);

    await next.fill('Brand-New-Passw0rd!2026');
    await again.fill('Brand-New-Passw0rd!2027');
    await submit.click();
    await expect(page.getByRole('alert')).toContainText(/do not match/i);

    // Server-side policy: same as the current password is refused
    await next.fill(org.password);
    await again.fill(org.password);
    await submit.click();
    await expect(page.getByRole('alert')).toContainText(/must differ|weak password/i);

    org.password = 'Brand-New-Passw0rd!2026';
    await cur.fill('Qa-Tester-Passw0rd!77');
    await next.fill(org.password);
    await again.fill(org.password);
    await submit.click();
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 20_000 });
  });

  test('old password no longer works, new one does', async ({ page }) => {
    await page.goto('/login');
    await page.getByTestId('login-email').fill(org.email);
    await page.getByTestId('login-password').fill('Qa-Tester-Passw0rd!77');
    await page.getByTestId('login-submit').click();
    await expect(page.getByTestId('login-error')).toBeVisible();
    await uiLogin(page, org.email, org.password);
    await expect(page).toHaveURL(/\/dashboard/);
  });

  test('empty states guide a new user (no dead ends)', async ({ page }) => {
    const health = watchHealth(page);
    await uiLogin(page, org.email, org.password);
    await heading(page, /security overview/i);

    for (const [path, h, empty] of [
      ['/get-started', /get started/i, /0 of 5 steps done/i],
      ['/assets', /devices/i, /no devices|add|upload/i],
      ['/audits', /audit results/i, /no audits|run an audit|upload/i],
      ['/findings', /findings/i, /no findings to show/i],
      ['/exceptions', /risk acceptance/i, /no exceptions yet/i],
      ['/schedules', /recurring audits/i, /no schedules yet/i],
      ['/reports', /reports/i, /no report yet/i],
    ] as const) {
      await page.goto(path);
      await heading(page, h);
      await expect(page.getByText(empty).first(), `${path} empty state`).toBeVisible({ timeout: 20_000 });
    }
    expect(health.badResponses).toEqual([]);
  });

  test('Get started -> sample config -> quick audit -> results, and the checklist advances', async ({ page }) => {
    test.setTimeout(180_000);
    await uiLogin(page, org.email, org.password);
    await page.goto('/get-started');
    await expect(page.getByText(/0 of 5 steps done/i)).toBeVisible();
    await page.getByRole('link', { name: /try a sample config/i }).click();
    await expect(page).toHaveURL(/quick-audit\?sample=1/);
    await expect(page.getByText('sample-branch-router.cfg')).toBeVisible();
    await page.getByTestId('quick-run').click();

    await expect(page).toHaveURL(/\/audits\/AUD-[^/]+\/results/, { timeout: 150_000 });
    await heading(page, /audit results/i);
    await expect(page.getByText('Executive summary')).toBeVisible();
    await expect(page.getByText('Assessment coverage')).toBeVisible();
    await expect(page.getByText(/% assessed/)).toBeVisible();

    await page.goto('/get-started');
    // The dashboard summary is cached server-side for a few seconds and client-side for longer: wait until
    // the API itself sees the new device, then reload so the checklist reads fresh data (still asserts 2/5).
    const api = await loginClient(org.email, org.password);
    await expect.poll(async () => (await api.json(await api.get('dashboard/summary'))).assets.total, { timeout: 30_000 }).toBeGreaterThan(0);
    await page.reload();
    await expect(page.getByText(/2 of 5 steps done/i)).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole('progressbar', { name: /setup progress/i })).toHaveAttribute('aria-valuenow', '40');
  });
});
