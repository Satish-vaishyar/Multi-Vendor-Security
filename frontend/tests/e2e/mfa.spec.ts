import { test, expect } from '@playwright/test';
import { adminClient } from './helpers/api';
import { totp, totpAfter, totpSelfTest } from './helpers/totp';
import { heading, uiLogin } from './helpers/ui';

test('TOTP helper matches the RFC 6238 test vector', () => {
  expect(totpSelfTest()).toBe(true);
});

test.describe.serial('Journey: MFA enrolment and login with a code', () => {
  let email = '';
  let password = '';
  let secret = '';
  let lastStep = 0;
  let recovery: string[] = [];

  test.beforeAll(async () => {
    const admin = await adminClient();
    const u = await admin.createUser('AUDITOR', 'mfa');
    email = u.email;
    password = u.password;
  });

  test('enrol an authenticator in Settings and receive recovery codes', async ({ page }) => {
    await uiLogin(page, email, password);
    await page.goto('/settings');
    await heading(page, /settings/i);
    await expect(page.getByText('Protect your account with an authenticator app (TOTP).')).toBeVisible();
    await page.getByRole('button', { name: 'Set up authenticator' }).click();

    secret = ((await page.locator('p.select-all').first().textContent()) ?? '').trim();
    expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
    await expect(page.getByRole('link', { name: 'Open in authenticator' })).toHaveAttribute('href', /^otpauth:\/\/totp\//);

    // Confirm is disabled until 6 digits; a wrong code is refused
    const code = page.getByLabel('6-digit authentication code');
    const confirm = page.getByRole('button', { name: 'Confirm' });
    await expect(confirm).toBeDisabled();
    await code.fill('000000');
    await confirm.click();
    await expect(page.getByRole('alert')).toContainText(/invalid code/i);

    const t = totpAfter(secret, lastStep);
    lastStep = t.step;
    await code.fill(t.code);
    await confirm.click();
    await expect(page.getByText(/Recovery codes - save them now/)).toBeVisible();
    recovery = await page.locator('ul.font-mono li').allTextContents();
    expect(recovery).toHaveLength(10);
    await expect(page.getByText(/Enabled · 10 recovery codes left/)).toBeVisible();
  });

  test('login now requires a code: missing prompt, wrong code, replayed code, valid code', async ({ page }) => {
    await page.goto('/login');
    await page.getByTestId('login-email').fill(email);
    await page.getByTestId('login-password').fill(password);
    await page.getByTestId('login-submit').click();
    // the form asks for the second factor instead of failing
    const otp = page.getByLabel(/authentication code/i);
    await expect(otp).toBeVisible();
    await expect(page).toHaveURL(/\/login/);

    await otp.fill('123456');
    await page.getByTestId('login-submit').click();
    await expect(page.getByTestId('login-error')).toBeVisible();
    await expect(page).toHaveURL(/\/login/);

    // The step used for enrolment is burnt (replay guard): same code is refused
    await otp.fill(totp(secret, 0, lastStep * 30_000 + 1000));
    await page.getByTestId('login-submit').click();
    await expect(page.getByTestId('login-error')).toBeVisible();

    const t = totpAfter(secret, lastStep);
    lastStep = t.step;
    await otp.fill(t.code);
    await page.getByTestId('login-submit').click();
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 20_000 });
  });

  test('a recovery code works exactly once', async ({ page, browser }) => {
    const first = recovery[0];
    const attempt = async (pg: typeof page, code: string) => {
      await pg.goto('/login');
      await pg.getByTestId('login-email').fill(email);
      await pg.getByTestId('login-password').fill(password);
      await pg.getByTestId('login-submit').click();
      await pg.getByLabel(/authentication code/i).fill(code);
      await pg.getByTestId('login-submit').click();
    };
    await attempt(page, first);
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 20_000 });

    const ctx = await browser.newContext();
    const p2 = await ctx.newPage();
    await attempt(p2, first);
    await expect(p2.getByTestId('login-error')).toBeVisible();
    await expect(p2).toHaveURL(/\/login/);
    await ctx.close();
  });

  test('disable MFA from Settings with password and a code', async ({ page }) => {
    // sign in with another unused recovery code (time-based steps may be exhausted for this 30 s window)
    await page.goto('/login');
    await page.getByTestId('login-email').fill(email);
    await page.getByTestId('login-password').fill(password);
    await page.getByTestId('login-submit').click();
    await page.getByLabel(/authentication code/i).fill(recovery[1]);
    await page.getByTestId('login-submit').click();
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 20_000 });

    await page.goto('/settings');
    await page.getByLabel('Current password').fill(password);
    await page.getByLabel('Authentication or recovery code').fill(recovery[2]);
    await page.getByRole('button', { name: 'Disable' }).click();
    await expect(page.getByText('Protect your account with an authenticator app (TOTP).')).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole('button', { name: 'Set up authenticator' })).toBeVisible();

    // login no longer asks for a code
    await page.context().clearCookies();
    await page.evaluate(() => localStorage.clear());
    await uiLogin(page, email, password);
    await expect(page).toHaveURL(/\/dashboard/);
  });
});
