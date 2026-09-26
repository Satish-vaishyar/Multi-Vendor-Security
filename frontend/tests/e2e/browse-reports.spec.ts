import { test, expect } from '@playwright/test';
import { loginViaUI } from './pom/login.page';

test.describe('Feature: Findings / Audits / Reports browsing', () => {
  test.beforeEach(async ({ page }) => {
    await loginViaUI(page);
  });

  test('should list audits (or empty state) without errors', async ({ page }) => {
    await page.goto('/audits');
    await expect(page.getByRole('heading', { name: /audits/i }).first()).toBeVisible({
      timeout: 20_000,
    });
    // Either audit rows or the empty state — but never an infinite loader
    const loader = page.getByText(/loading audits/i);
    await expect(loader).toBeHidden({ timeout: 20_000 });
  });

  test('should list findings page', async ({ page }) => {
    await page.goto('/findings');
    await expect(page.getByRole('heading', { name: /findings/i }).first()).toBeVisible({
      timeout: 20_000,
    });
  });

  test('should validate report form requires audit id', async ({ page }) => {
    await page.goto('/reports');
    await expect(page.getByRole('heading', { name: /reports/i }).first()).toBeVisible();
    // Generate button disabled without audit id — independent, no shared state
    await expect(page.getByTestId('report-generate')).toBeDisabled();
    await page.getByTestId('report-audit-id').fill('AUD-DOES-NOT-EXIST-123');
    await expect(page.getByTestId('report-generate')).toBeEnabled();
  });

  test('should surface backend error for bogus report request', async ({ page }) => {
    await page.goto('/reports');
    await page.getByTestId('report-audit-id').fill('AUD-DOES-NOT-EXIST-123');
    const respPromise = page.waitForResponse(
      (r) => r.url().includes('/api/') && r.url().includes('/reports'),
    );
    await page.getByTestId('report-generate').click();
    const resp = await respPromise;
    // Backend may return 404/422/500 — assert the UI surfaces *something*, not a hang
    expect([200, 201, 400, 404, 422, 500]).toContain(resp.status());
    await expect(page.getByTestId('report-error')).toBeVisible({ timeout: 20_000 });
    await expect(page.getByTestId('report-error')).toContainText(/audit not found|not found|audit/i);
  });

  test.afterEach(async ({ page }, testInfo) => {
    if (testInfo.status !== 'passed') {
      await page.screenshot({ path: `test-results/${testInfo.title.replace(/\W+/g, '-')}.png` });
    }
  });
});
