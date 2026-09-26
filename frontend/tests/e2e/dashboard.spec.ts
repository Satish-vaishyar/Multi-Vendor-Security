import { test, expect } from '@playwright/test';
import { loginViaUI } from './pom/login.page';
import { DashboardPage } from './pom/dashboard.page';

test.describe('Feature: Dashboard (core happy path)', () => {
  test.beforeEach(async ({ page }) => {
    await loginViaUI(page);
  });

  test('should load KPIs, charts and navigation links', async ({ page }) => {
    const dash = new DashboardPage(page);
    await dash.goto();
    await dash.expectLoaded();
    await dash.expectKpisVisible();

    // Charts or empty-states must render (no infinite loader)
    const loaderGone = page.getByText(/loading security overview/i);
    await expect(loaderGone).toBeHidden({ timeout: 20_000 });

    // Navigation links work
    await expect(page.getByRole('link', { name: /open vulnerabilities/i })).toBeVisible();
    await expect(page.getByRole('link', { name: /open training queue/i })).toBeVisible();
  });

  test('should navigate Run New Audit -> upload page', async ({ page }) => {
    const dash = new DashboardPage(page);
    await dash.goto();
    await dash.expectLoaded();
    await dash.gotoUpload();
  });

  test('should fetch dashboard summary API successfully', async ({ page }) => {
    const respPromise = page.waitForResponse(
      (r) => r.url().includes('/api/') && r.url().includes('dashboard'),
    );
    await page.goto('/dashboard');
    const resp = await respPromise;
    expect([200, 304]).toContain(resp.status());
  });

  test.afterEach(async ({ page }, testInfo) => {
    if (testInfo.status !== 'passed') {
      await page.screenshot({ path: `test-results/${testInfo.title.replace(/\W+/g, '-')}.png` });
    }
  });
});
