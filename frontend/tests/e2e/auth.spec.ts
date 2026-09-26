import { test, expect } from '@playwright/test';
import { LoginPage } from './pom/login.page';
import { loginViaUI } from './pom/login.page';

test.describe('Feature: Authentication', () => {
  test.beforeEach(async ({ page }) => {
    await page.evaluate(() => localStorage.clear()).catch(() => {});
  });

  test('should log in with demo credentials and land on dashboard', async ({ page }) => {
    const login = new LoginPage(page);
    await login.goto();

    // Arrange: prefilled demo creds visible
    await expect(page.getByTestId('login-email')).toHaveValue('admin@example.com');

    // Act: wait for API, not a timeout
    const respPromise = login.login();
    const resp = await respPromise;
    expect(resp.ok()).toBeTruthy();

    // Assert
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 20_000 });
    await expect(page.getByRole('heading', { name: /security overview/i })).toBeVisible({
      timeout: 20_000,
    });
  });

  test('should show error on invalid credentials', async ({ page }) => {
    const login = new LoginPage(page);
    await login.goto();
    await login.login('wrong@example.com', 'badpassword').catch(() => {});
    await login.expectErrorVisible();
    await expect(page).toHaveURL(/\/login/);
  });

  test('should redirect unauthenticated users to /login', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/login/, { timeout: 15_000 });
    await expect(page.getByTestId('login-form')).toBeVisible();
  });

  test('should persist session across reload', async ({ page }) => {
    await loginViaUI(page);
    await page.reload();
    await expect(page.getByRole('heading', { name: /security overview/i })).toBeVisible({
      timeout: 20_000,
    });
    await expect(page).not.toHaveURL(/\/login/);
  });

  test('should log out and guard dashboard again', async ({ page }) => {
    await loginViaUI(page);
    await page.evaluate(() => localStorage.removeItem('sih26155_token'));
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/login/, { timeout: 15_000 });
  });

  test.afterEach(async ({ page }, testInfo) => {
    if (testInfo.status !== 'passed') {
      await page.screenshot({ path: `test-results/${testInfo.title.replace(/\W+/g, '-')}.png` });
    }
  });
});
