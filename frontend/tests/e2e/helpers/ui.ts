import { Page, expect } from '@playwright/test';

export const TOKEN_KEY = 'sih26155_token';

/** Real UI login (form). Returns once the app left /login (dashboard or forced password change). */
export async function uiLogin(page: Page, email: string, password: string) {
  await page.goto('/login');
  await expect(page.getByTestId('login-form')).toBeVisible();
  await page.getByTestId('login-email').fill(email);
  await page.getByTestId('login-password').fill(password);
  await page.getByTestId('login-submit').click();
  await expect(page).not.toHaveURL(/\/login/, { timeout: 20_000 });
}

/**
 * Fast login for specs where signing in is not the subject: obtain a token from the API and put it where the
 * app's session store reads it (dev builds use bearer tokens in localStorage).
 */
export async function seedSession(page: Page, token: string) {
  await page.addInitScript(([k, t]) => {
    try { localStorage.setItem(k, t); } catch { /* ignore */ }
  }, [TOKEN_KEY, token]);
}

export async function heading(page: Page, name: RegExp | string) {
  await expect(page.getByRole('heading', { level: 1, name })).toBeVisible({ timeout: 20_000 });
}

/** Collects console errors and failed/5xx network calls so a spec can assert the page was clean. */
export function watchHealth(page: Page) {
  const consoleErrors: string[] = [];
  const badResponses: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error') consoleErrors.push(m.text());
  });
  page.on('pageerror', (e) => consoleErrors.push(`pageerror: ${e.message}`));
  page.on('response', (r) => {
    if (r.status() >= 500) badResponses.push(`${r.status()} ${r.request().method()} ${r.url()}`);
  });
  page.on('requestfailed', (r) => {
    const f = r.failure()?.errorText ?? '';
    if (!/ERR_ABORTED/.test(f)) badResponses.push(`FAILED ${r.method()} ${r.url()} ${f}`);
  });
  return { consoleErrors, badResponses };
}
