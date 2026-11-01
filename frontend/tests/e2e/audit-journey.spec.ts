import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { adminClient, CORPUS_DIR, Client } from './helpers/api';
import { heading, seedSession, watchHealth } from './helpers/ui';

const sha256 = (b: Buffer) => createHash('sha256').update(b).digest('hex');

/**
 * Journey 2: upload a real corpus config in the UI -> vendor detected -> audit -> results with findings and the
 * coverage panel -> finding detail -> remediation plan -> exports (CSV/JSON) -> PDF report (header + SHA-256).
 */
test.describe.serial('Journey: upload, audit, review, fix plan, export, report', () => {
  let admin: Client;
  let auditId = '';
  let findingId = '';

  test.beforeAll(async () => {
    admin = await adminClient();
  });

  test.beforeEach(async ({ page }) => {
    await seedSession(page, admin.token);
  });

  test('quick audit of a corpus config detects the vendor and opens results with a coverage panel', async ({ page }) => {
    test.setTimeout(180_000);
    const health = watchHealth(page);
    await page.goto('/quick-audit');
    await heading(page, /upload & audit/i);
    await expect(page.getByTestId('quick-run')).toBeDisabled();

    await page.getByTestId('quick-file-input').setInputFiles(path.join(CORPUS_DIR, 'cisco_iosxe_branch_insecure.cfg'));
    await expect(page.getByText('cisco_iosxe_branch_insecure.cfg', { exact: true })).toBeVisible();
    const upload = page.waitForResponse((r) => r.url().includes('/configurations/upload'));
    await page.getByTestId('quick-run').click();
    const up = await (await upload).json();
    expect(String(up.data.detected_vendor).toLowerCase()).toContain('cisco');

    await expect(page).toHaveURL(/\/audits\/(AUD-[^/]+)\/results/, { timeout: 150_000 });
    auditId = page.url().match(/\/audits\/([^/]+)\/results/)![1];
    await heading(page, /audit results/i);

    await expect(page.getByText('Executive summary')).toBeVisible();
    await expect(page.getByText('Assessment coverage')).toBeVisible();
    await expect(page.getByText(/\d+(\.\d+)?% assessed/)).toBeVisible();
    await expect(page.getByText(/applicable controls\s+were decided/)).toBeVisible();
    // Compliance score is a real number
    await expect(page.getByText('Compliance score')).toBeVisible();

    // Findings tab lists real findings
    await page.locator('#main').getByRole('button', { name: 'Findings', exact: true }).click();
    const links = page.locator('main a[href^="/findings/"]');
    await expect(links.first()).toBeVisible();
    expect(await links.count()).toBeGreaterThan(3);
    findingId = (await links.first().getAttribute('href'))!.split('/').pop()!;

    // Filter + search narrow the list
    await page.getByLabel('Search findings').fill('zzzz-no-such-finding');
    await expect(page.getByText('No findings match these filters.')).toBeVisible();
    await page.getByLabel('Search findings').fill('');
    await expect(links.first()).toBeVisible();

    expect(health.badResponses).toEqual([]);
  });

  test('vendor appears on the device list', async ({ page }) => {
    await page.goto('/assets');
    await heading(page, /devices/i);
    await page.getByLabel('Search devices').fill('cisco-iosxe-branch-insecure');
    await expect(page.getByText(/cisco/i).first()).toBeVisible();
  });

  test('finding detail explains the problem and links to a remediation plan', async ({ page }) => {
    await page.goto(`/findings/${findingId}`);
    await heading(page, /.+/);
    await expect(page.getByText('Plain-language explanation for the network engineer')).toBeVisible();
    await expect(page.getByText('Evidence', { exact: true })).toBeVisible();
    await expect(page.getByText('Verdict', { exact: true })).toBeVisible();
    await page.getByRole('link', { name: /fix this/i }).click();
    await expect(page).toHaveURL(new RegExp(`/remediation/${findingId}`));
    await heading(page, /remediation/i);
    await expect(page.getByText(/fix steps/i).first()).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole('button', { name: 'Approve choice' })).toBeVisible();
    await expect(page.getByText(/simulation only/i).first()).toBeVisible();
  });

  test('CSV and JSON exports download with the right content', async ({ page }) => {
    await page.goto(`/audits/${auditId}/results`);
    await heading(page, /audit results/i);
    const total = (await admin.results(auditId)).findings.length;

    const [csv] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export CSV' }).click()]);
    expect(csv.suggestedFilename()).toMatch(/\.csv$/);
    const csvText = fs.readFileSync((await csv.path())!, 'utf8');
    const lines = csvText.trim().split(/\r?\n/);
    expect(lines[0].toLowerCase()).toContain('finding_id');
    expect(lines.length).toBeGreaterThan(3);

    const [js] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export JSON' }).click()]);
    expect(js.suggestedFilename()).toMatch(/\.json$/);
    const parsed = JSON.parse(fs.readFileSync((await js.path())!, 'utf8'));
    const items = Array.isArray(parsed) ? parsed : (parsed.findings ?? parsed.items ?? parsed.data?.findings ?? parsed.data?.items ?? parsed.data);
    expect(Array.isArray(items)).toBeTruthy();
    expect(items.length).toBe(total);
  });

  test('PDF report: generate in the UI, download, %PDF header and SHA-256 integrity header', async ({ page }) => {
    test.setTimeout(180_000);
    await page.goto('/reports');
    await heading(page, /reports/i);
    await page.getByTestId('report-audit-id').fill(auditId);
    const created = page.waitForResponse((r) => /\/reports$/.test(r.url()) && r.request().method() === 'POST');
    await page.getByTestId('report-generate').click();
    const reportId = (await (await created).json()).data.report_id as string;
    expect(reportId).toMatch(/^REP-/);
    await expect(page.getByText(`Report ${reportId}`)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Download PDF' })).toBeVisible({ timeout: 120_000 });

    const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download PDF' }).click()]);
    const bytes = fs.readFileSync((await dl.path())!);
    expect(bytes.subarray(0, 5).toString('latin1')).toBe('%PDF-');
    expect(bytes.length).toBeGreaterThan(5_000);
    expect(bytes.subarray(-1024).toString('latin1')).toContain('%%EOF');

    // Integrity: the server's SHA-256 header and the report record match the bytes the user received.
    const r = await admin.get(`reports/${reportId}/download`);
    expect(r.status()).toBe(200);
    expect(r.headers()['content-type']).toContain('application/pdf');
    const header = r.headers()['x-content-sha256'];
    expect(header).toMatch(/^[0-9a-f]{64}$/);
    expect(header).toBe(sha256(bytes));
    const rec = await admin.json(await admin.get(`reports/${reportId}`));
    expect(rec.sha256).toBe(header);
  });

  test('evidence pack and findings exports carry an integrity header (API)', async () => {
    for (const [url, params] of [
      [`reports/export/${auditId}`, { format: 'csv' }],
      [`reports/evidence/${auditId}`, { framework: 'CIS', format: 'json' }],
      ['reports/fleet', { format: 'csv' }],
    ] as const) {
      const r = await admin.get(url, params as Record<string, string>);
      expect(r.status(), url).toBe(200);
      expect(r.headers()['x-content-sha256'], url).toBe(sha256(await r.body()));
    }
  });
});
