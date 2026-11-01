import { test, expect } from '@playwright/test';
import { loginViaUI } from './pom/login.page';
import { seed } from './helpers/seed';

/**
 * Edge cases: invalid IDs, unknown routes, session expiry, offline.
 * Each test is independent — no shared state, no test order dependency.
 */
test.describe('Feature: Edge cases', () => {
  test('should show error state for unknown audit results', async ({ page }) => {
    await loginViaUI(page);
    await page.goto('/audits/AUD-DOES-NOT-EXIST-999/results');
    await expect(page.getByText(/results unavailable|unable to load|not found/i).first()).toBeVisible({
      timeout: 20_000,
    });
    // Retry button exists (ErrorState) — resilient, no timeout waits
    await expect(page.getByRole('button', { name: /retry/i })).toBeVisible();
  });

  test('should show error state for unknown finding', async ({ page }) => {
    await loginViaUI(page);
    await page.goto('/findings/FND-DOES-NOT-EXIST-999');
    await expect(page.getByText(/unable to load|not found|no data|failed/i).first()).toBeVisible({
      timeout: 20_000,
    });
  });

  test('should handle unknown route by redirecting to dashboard (authed)', async ({ page }) => {
    await loginViaUI(page);
    await page.goto('/this-route-does-not-exist-xyz');
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 15_000 });
  });

  test('should redirect to login when the session expires (401 from the API)', async ({ page }) => {
    await loginViaUI(page);
    await expect(page.getByRole('heading', { name: /security overview/i })).toBeVisible({ timeout: 20_000 });
    // Expire the session server-side-equivalent: every further API call answers 401.
    await page.route('**/api/v1/**', (route) =>
      route.fulfill({ status: 401, contentType: 'application/json', body: '{"success":false,"error":{"code":"HTTP_401","message":"expired"}}' }),
    );
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Devices' }).click();
    await expect(page).toHaveURL(/\/login/, { timeout: 20_000 });
    expect(await page.evaluate(() => localStorage.getItem('sih26155_token'))).toBeNull();
  });

  test('should show a friendly error with Retry when the backend is unreachable', async ({ page }) => {
    await loginViaUI(page);
    await page.route('**/api/v1/assets**', (route) => route.abort('failed'));
    await page.goto('/assets');
    await expect(page.getByRole('heading', { name: /devices/i }).first()).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/unable to load|cannot reach|could not load/i).first()).toBeVisible({ timeout: 30_000 });
    await expect(page.getByRole('button', { name: /retry/i })).toBeVisible();
    // recovery: once the backend is back, Retry loads the data
    await page.unroute('**/api/v1/assets**');
    await page.getByRole('button', { name: /retry/i }).click();
    await expect(page.getByText(/unable to load|cannot reach|could not load/i)).toHaveCount(0, { timeout: 20_000 });
  });

  test('mobile viewport: the Start audit dialog fits the screen', async ({ page }) => {
    await loginViaUI(page);
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto(`/configurations/${seed().insecure.configuration_id}`);
    await page.getByTestId('start-audit-open').click();
    const dialog = page.getByRole('dialog', { name: 'Start audit' });
    await expect(dialog).toBeVisible();
    const confirm = page.getByTestId('start-audit-confirm');
    await confirm.scrollIntoViewIfNeeded();
    const vp = page.viewportSize()!;
    const box = (await confirm.boundingBox())!;
    expect(box.x).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width).toBeLessThanOrEqual(vp.width);
    const m = await page.evaluate(() => ({ doc: document.documentElement.scrollWidth, win: document.documentElement.clientWidth }));
    expect(m.doc).toBeLessThanOrEqual(m.win + 1);
    await page.keyboard.press('Escape');
  });

  test.afterEach(async ({ page }, testInfo) => {
    if (testInfo.status !== 'passed' && testInfo.status !== 'skipped') {
      await page.screenshot({ path: `test-results/${testInfo.title.replace(/\W+/g, '-')}.png` });
    }
  });
});
