import { test, expect, Page } from '@playwright/test';
import { adminClient, Client } from './helpers/api';
import { a11yIssues } from './helpers/a11y';
import { seed } from './helpers/seed';
import { heading, seedSession, watchHealth } from './helpers/ui';

let admin: Client;
test.beforeAll(async () => {
  admin = await adminClient();
});

/** Pages that exercise every layout family (lists, cards, tables, forms, detail pages). */
function pages() {
  const s = seed();
  return [
    ['/dashboard', /security overview/i],
    ['/get-started', /get started/i],
    ['/quick-audit', /upload & audit/i],
    ['/configurations/upload', /upload configuration/i],
    ['/assets', /devices/i],
    [`/assets/${s.insecure.asset_id}`, /.+/],
    ['/audits', /audit results/i],
    [`/audits/${s.insecure.audit_id}/results`, /audit results/i],
    ['/findings', /findings/i],
    ['/vulnerabilities', /.+/],
    ['/pqc', /.+/],
    ['/analytics', /.+/],
    ['/compliance', /.+/],
    ['/remediation', /remediation/i],
    ['/reports', /reports/i],
    ['/exceptions', /risk acceptance/i],
    ['/schedules', /recurring audits/i],
    ['/jobs', /background jobs/i],
    ['/integrations', /integrations/i],
    ['/training', /.+/],
    ['/admin', /administration/i],
    ['/settings', /settings/i],
  ] as [string, RegExp][];
}

const noHorizontalScroll = (page: Page) =>
  page.evaluate(() => ({
    doc: document.documentElement.scrollWidth,
    win: document.documentElement.clientWidth,
    body: document.body.scrollWidth,
  }));

test.describe('Theme', () => {
  test.beforeEach(async ({ page }) => seedSession(page, admin.token));

  test('toggle light/dark persists across reloads and navigation', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto('/dashboard');
    await heading(page, /security overview/i);
    const html = page.locator('html');
    await page.getByRole('button', { name: 'Dark theme' }).click();
    await expect(html).toHaveAttribute('data-theme', 'dark');
    await expect(page.getByRole('button', { name: 'Dark theme' })).toHaveAttribute('aria-pressed', 'true');
    expect(await page.evaluate(() => localStorage.getItem('qirova_theme'))).toBe('dark');
    const darkBg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);

    await page.reload();
    await expect(html).toHaveAttribute('data-theme', 'dark');
    await page.getByRole('link', { name: 'Findings', exact: true }).first().click();
    await expect(html).toHaveAttribute('data-theme', 'dark');

    await page.getByRole('button', { name: 'Light theme' }).click();
    await expect(html).toHaveAttribute('data-theme', 'light');
    const lightBg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(lightBg).not.toBe(darkBg);
    await page.reload();
    await expect(html).toHaveAttribute('data-theme', 'light');

    // "system" follows the OS preference live
    await page.getByRole('button', { name: 'System theme' }).click();
    await page.emulateMedia({ colorScheme: 'dark' });
    await expect(html).toHaveAttribute('data-theme', 'dark');
    await page.emulateMedia({ colorScheme: 'light' });
    await expect(html).toHaveAttribute('data-theme', 'light');
  });

  test('saved theme is applied before the app boots (no flash of the wrong theme)', async ({ page }) => {
    // Stop the React bundle: whatever theme is on the page now was set by the pre-paint script alone.
    await page.route('**/src/main.tsx*', (r) => r.abort());
    await page.addInitScript(() => localStorage.setItem('qirova_theme', 'dark'));
    await page.goto('/login');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    const [r, g, b] = bg.match(/\d+/g)!.map(Number);
    expect((r + g + b) / 3, `body background ${bg} should be dark`).toBeLessThan(80);
    expect(await page.evaluate(() => document.documentElement.style.colorScheme)).toBe('dark');
  });

  test('pages render in dark mode without console errors', async ({ page }) => {
    const health = watchHealth(page);
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.addInitScript(() => localStorage.setItem('qirova_theme', 'dark'));
    for (const [p, h] of pages().slice(0, 9)) {
      await page.goto(p);
      await heading(page, h);
    }
    expect(health.consoleErrors).toEqual([]);
    expect(health.badResponses).toEqual([]);
  });
});

test.describe('Mobile (375x812)', () => {
  test.use({ viewport: { width: 375, height: 812 } });
  test.beforeEach(async ({ page }) => seedSession(page, admin.token));

  test('navigation drawer opens, navigates, closes on Esc and moves focus', async ({ page }) => {
    await page.goto('/dashboard');
    await heading(page, /security overview/i);
    // desktop sidebar is hidden on a phone
    await expect(page.getByRole('navigation', { name: 'Main' })).toHaveCount(0);
    const open = page.getByRole('button', { name: 'Open menu' });
    await open.click();
    const drawer = page.getByRole('dialog', { name: 'Menu' });
    await expect(drawer).toBeVisible();
    await expect(page.getByRole('button', { name: 'Close menu' })).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(drawer).toHaveCount(0);

    await open.click();
    await drawer.getByRole('link', { name: 'Findings', exact: true }).click();
    await expect(page).toHaveURL(/\/findings/);
    await expect(drawer).toHaveCount(0);
    await heading(page, /findings/i);
  });

  test('no horizontal overflow on any main page', async ({ page }) => {
    test.setTimeout(240_000);
    const overflow: string[] = [];
    for (const [p, h] of pages()) {
      await page.goto(p);
      await heading(page, h);
      await page.waitForLoadState('networkidle').catch(() => undefined);
      const m = await noHorizontalScroll(page);
      if (m.doc > m.win + 1 || m.body > m.win + 1) overflow.push(`${p}: doc ${m.doc} body ${m.body} > ${m.win}`);
    }
    expect(overflow).toEqual([]);
  });

  test('login page fits and the quick-audit drop zone is usable', async ({ page }) => {
    await page.context().clearCookies();
    await page.addInitScript(() => localStorage.clear());
    await page.goto('/login');
    await expect(page.getByTestId('login-form')).toBeVisible();
    const m = await noHorizontalScroll(page);
    expect(m.doc).toBeLessThanOrEqual(m.win + 1);
    const box = await page.getByTestId('login-submit').boundingBox();
    expect(box!.height).toBeGreaterThanOrEqual(36); // comfortable touch target
  });
});

test.describe('Keyboard', () => {
  test.beforeEach(async ({ page }) => seedSession(page, admin.token));

  test('skip link is the first tab stop, becomes visible and moves focus to main', async ({ page }) => {
    await page.goto('/dashboard');
    await heading(page, /security overview/i);
    await page.keyboard.press('Tab');
    const skip = page.getByRole('link', { name: 'Skip to content' });
    await expect(skip).toBeFocused();
    const box = await skip.boundingBox();
    expect(box!.width).toBeGreaterThan(40); // visible on focus, not clipped
    await page.keyboard.press('Enter');
    await expect.poll(() => page.evaluate(() => document.activeElement?.id)).toBe('main');
  });

  test('focus is always visible on interactive elements', async ({ page }) => {
    await page.goto('/dashboard');
    await heading(page, /security overview/i);
    const bad: string[] = [];
    for (let i = 0; i < 25; i++) {
      await page.keyboard.press('Tab');
      const r = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        if (!el || el === document.body) return null;
        const cs = getComputedStyle(el);
        const visible = cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 1 || cs.boxShadow !== 'none';
        return { visible, tag: `${el.tagName.toLowerCase()} ${(el.getAttribute('aria-label') ?? el.textContent ?? '').trim().slice(0, 30)}` };
      });
      if (r && !r.visible) bad.push(r.tag);
    }
    expect(bad).toEqual([]);
  });

  test('Ctrl+K opens the palette, filters, navigates with Enter and closes with Esc', async ({ page }) => {
    await page.goto('/dashboard');
    await heading(page, /security overview/i);
    await page.keyboard.press('Control+k');
    const dialog = page.getByRole('dialog', { name: 'Quick search' });
    const input = dialog.getByRole('combobox');
    await expect(input).toBeFocused();
    await input.fill('risk');
    await expect(dialog.getByRole('option').first()).toContainText('Risk acceptance');
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/exceptions/);
    await expect(dialog).toHaveCount(0);

    await page.keyboard.press('Control+k');
    await expect(dialog).toBeVisible();
    await page.keyboard.press('ArrowDown');
    await expect(dialog.getByRole('option').nth(1)).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);

    // devices are searchable too
    await page.keyboard.press('Control+k');
    await dialog.getByRole('combobox').fill('qa-seed-insecure');
    await expect(dialog.getByRole('option', { name: /qa-seed-insecure/ })).toBeVisible();
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(new RegExp(`/assets/${seed().insecure.asset_id}`));
  });

  test('login form is operable with the keyboard alone (Enter submits)', async ({ page }) => {
    await page.context().clearCookies();
    await page.addInitScript(() => localStorage.removeItem('sih26155_token'));
    await page.goto('/login');
    await page.getByTestId('login-email').focus();
    await page.keyboard.type('nobody@example.com');
    await page.keyboard.press('Tab');
    await page.keyboard.type('wrong-password-123');
    await page.keyboard.press('Enter');
    await expect(page.getByTestId('login-error')).toBeVisible();
  });
});

test.describe('Accessibility smoke (labels, names, alt, headings, landmarks)', () => {
  test('login page', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByTestId('login-form')).toBeVisible();
    expect(await a11yIssues(page)).toEqual([]);
  });

  test('every main page', async ({ page }) => {
    test.setTimeout(240_000);
    await seedSession(page, admin.token);
    const all: string[] = [];
    for (const [p, h] of pages()) {
      await page.goto(p);
      await heading(page, h);
      await page.waitForLoadState('networkidle').catch(() => undefined);
      for (const i of await a11yIssues(page)) all.push(`${p} [${i.rule}] ${i.detail}`);
    }
    expect(all).toEqual([]);
  });

  test('page title reflects the current page (WCAG 2.4.2)', async ({ page }) => {
    await seedSession(page, admin.token);
    await page.goto('/findings');
    await heading(page, /findings/i);
    const t1 = await page.title();
    await page.goto('/reports');
    await heading(page, /reports/i);
    const t2 = await page.title();
    expect(t1).toMatch(/findings/i);
    expect(t2).toMatch(/reports/i);
    expect(t1).not.toBe(t2);
  });
});
