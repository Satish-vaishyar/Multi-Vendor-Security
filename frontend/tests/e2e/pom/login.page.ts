import { Page, expect } from '@playwright/test';

export const DEMO_EMAIL = 'admin@example.com';
export const DEMO_PASSWORD = 'admin123';

/** Login Page Object (POM) — resilient locators: data-testid first, role fallback. */
export class LoginPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/login');
    await expect(this.page.getByTestId('login-form')).toBeVisible();
  }

  async login(email = DEMO_EMAIL, password = DEMO_PASSWORD) {
    await this.page.getByTestId('login-email').fill(email);
    await this.page.getByTestId('login-password').fill(password);
    const loginResponse = this.page.waitForResponse(
      (r) => r.url().includes('/api/') && r.url().includes('/auth/login'),
    );
    await this.page.getByTestId('login-submit').click();
    return loginResponse;
  }

  async loginAndWaitForDashboard(email = DEMO_EMAIL, password = DEMO_PASSWORD) {
    await this.goto();
    const respPromise = this.login(email, password);
    await respPromise;
    await expect(this.page).toHaveURL(/\/dashboard/, { timeout: 20_000 });
  }

  async expectErrorVisible() {
    await expect(this.page.getByTestId('login-error')).toBeVisible({ timeout: 15_000 });
  }
}

/** Auth helpers shared across specs. */
export async function loginViaUI(page: Page, email = DEMO_EMAIL, password = DEMO_PASSWORD) {
  const login = new LoginPage(page);
  await login.loginAndWaitForDashboard(email, password);
}

export async function logoutViaStorage(page: Page) {
  await page.evaluate(() => localStorage.removeItem('sih26155_token'));
}
