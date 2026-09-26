import { test, expect } from '@playwright/test';
import { loginViaUI } from './pom/login.page';

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

  test('should redirect to login on 401 (session expiry)', async ({ page }) => {
    test.fixme(true, 'Flaky in CI - Issue #124: 401 interceptor races with react-query cache');
    await loginViaUI(page);
    await page.route('**/api/**', (route) =>
      route.fulfill({ status: 401, contentType: 'application/json', body: '{"detail":"expired"}' }),
    );
    await page.goto('/assets');
    await expect(page).toHaveURL(/\/login/, { timeout: 20_000 });
    await page.unroute('**/api/**');
  });

  test('should show friendly error when backend unreachable', async ({ page }) => {
    test.fixme(true, 'Flaky in CI - Issue #125: cached dashboard query masks offline ErrorState');
    await loginViaUI(page);
    await page.route('**/api/**', (route) => route.abort('failed'));
    await page.goto('/assets');
    await expect(page.getByText(/unable to load|failed|cannot reach|retry/i).first()).toBeVisible({
      timeout: 20_000,
    });
    await page.unroute('**/api/**');
  });

  // Quarantined: mobile viewport audit-dialog overflow is under investigation.
  test('quarantined: mobile viewport start-audit dialog', async ({ page }) => {
    test.fixme(true, 'Flaky in CI - Issue #123: mobile audit dialog needs overflow fix');
    await loginViaUI(page);
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/configurations/upload');
    await expect(page.getByRole('heading', { name: /upload/i }).first()).toBeVisible();
  });

  test.afterEach(async ({ page }, testInfo) => {
    if (testInfo.status !== 'passed' && testInfo.status !== 'skipped') {
      await page.screenshot({ path: `test-results/${testInfo.title.replace(/\W+/g, '-')}.png` });
    }
  });
});
