import { Page, expect } from '@playwright/test';

/** Dashboard POM */
export class DashboardPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/dashboard');
  }

  async expectLoaded() {
    await expect(
      this.page.getByRole('heading', { name: /security overview/i }),
    ).toBeVisible({ timeout: 20_000 });
  }

  async expectKpisVisible() {
    for (const kpi of ['Total Assets', 'Compliance Score', 'Critical Findings']) {
      await expect(this.page.getByText(kpi, { exact: true }).first()).toBeVisible();
    }
  }

  async waitForSummaryApi() {
    return this.page.waitForResponse((r) => r.url().includes('/api/') && r.url().includes('dashboard'));
  }

  async gotoUpload() {
    await this.page.getByRole('link', { name: /run new audit/i }).click();
    await expect(this.page).toHaveURL(/\/configurations\/upload/);
  }
}
