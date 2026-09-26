import { test, expect } from '@playwright/test';
import { loginViaUI } from './pom/login.page';
import { UploadPage, ConfigurationPage } from './pom/upload.page';

test.describe('Feature: Upload Configuration -> Start Audit (critical flow)', () => {
  test.beforeEach(async ({ page }) => {
    await loginViaUI(page);
  });

  test('should upload a config file and reach configuration details', async ({ page }) => {
    const upload = new UploadPage(page);
    await upload.goto();
    await upload.attachSampleConfig(`e2e-sample-${Date.now()}.cfg`);
    const resp = await upload.submitAndWaitForUpload();
    expect([200, 201]).toContain(resp.status());
    await upload.expectUploadAccepted();

    // Single-file upload auto-navigates to /configurations/:id
    await expect(page).toHaveURL(/\/configurations\//, { timeout: 30_000 });
    const cfg = new ConfigurationPage(page);
    await cfg.expectLoaded();
  });

  test('should open Start Audit dialog and start an audit', async ({ page }) => {
    const upload = new UploadPage(page);
    await upload.goto();
    await upload.attachSampleConfig(`e2e-audit-${Date.now()}.cfg`);
    await upload.submitAndWaitForUpload();
    await expect(page).toHaveURL(/\/configurations\//, { timeout: 30_000 });

    const cfg = new ConfigurationPage(page);
    await cfg.expectLoaded();
    await cfg.openStartAuditDialog();
    const auditResp = await cfg.confirmStartAudit();
    expect([200, 201]).toContain(auditResp.status());
    await cfg.expectAuditStarted();

    // Audit progress page shows progress or results link
    await expect(
      page.getByRole('heading', { name: /audit/i }).first(),
    ).toBeVisible({ timeout: 20_000 });
  });

  test('should show validation when submitting with no file', async ({ page }) => {
    const upload = new UploadPage(page);
    await upload.goto();
    await expect(page.getByTestId('upload-submit')).toBeDisabled();
  });

  test.afterEach(async ({ page }, testInfo) => {
    if (testInfo.status !== 'passed') {
      await page.screenshot({ path: `test-results/${testInfo.title.replace(/\W+/g, '-')}.png` });
    }
  });
});
