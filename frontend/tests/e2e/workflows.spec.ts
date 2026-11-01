import { test, expect } from '@playwright/test';
import path from 'path';
import { adminClient, Client, CORPUS_DIR, loginClient, uniq } from './helpers/api';
import { seed } from './helpers/seed';
import { heading, seedSession } from './helpers/ui';

test.describe('Workflow: risk acceptance with two people (four-eyes)', () => {
  test('requester cannot approve their own request; a second approver can; status becomes active', async ({ browser }) => {
    const admin = await adminClient();
    const requester = await admin.createUser('APPROVER', 'req');
    const approver = await admin.createUser('APPROVER', 'appr');
    const key = `CIS-QA-${uniq('k')}`;
    const reason = 'Compensating control: management plane is isolated on an out-of-band network';
    // The asset dropdown shows the newest 100 assets: use a freshly created one so the test does not
    // depend on where the shared seed asset sits in that list.
    const assetName = uniq('wf-asset');
    await admin.createAsset(assetName);

    // --- requester files the exception through the UI
    const ctxA = await browser.newContext();
    const a = await ctxA.newPage();
    await seedSession(a, (await loginClient(requester.email)).token);
    await a.goto('/exceptions');
    await heading(a, /risk acceptance/i);
    await a.getByLabel('Asset').selectOption({ label: assetName });
    await a.getByLabel('Control / CVE id').fill(key);
    await a.getByLabel('Business reason (min 10 characters)').fill('too short');
    await a.getByRole('button', { name: 'Request' }).click();
    // HTML validation blocks it (minLength) - nothing is created
    await expect(a.getByText(key)).toHaveCount(0);
    await a.getByLabel('Business reason (min 10 characters)').fill(reason);
    await a.getByRole('button', { name: 'Request' }).click();

    const card = a.locator('li').filter({ hasText: key });
    await expect(card).toBeVisible();
    await expect(card.getByText('PENDING', { exact: true })).toBeVisible();
    await expect(card).toContainText(`Requested by ${requester.email}`);

    // --- four-eyes: the same person cannot approve
    await card.getByRole('button', { name: 'Approve' }).click();
    await expect(a.getByText(/four-eyes rule: you cannot approve your own exception request/i)).toBeVisible();
    await expect(card.getByText('PENDING', { exact: true })).toBeVisible();

    // --- a different approver approves
    const ctxB = await browser.newContext();
    const b = await ctxB.newPage();
    await seedSession(b, (await loginClient(approver.email)).token);
    await b.goto('/exceptions');
    const cardB = b.locator('li').filter({ hasText: key });
    await expect(cardB).toBeVisible();
    await cardB.getByRole('button', { name: 'Approve' }).click();
    await expect(cardB.getByText('ACTIVE', { exact: true })).toBeVisible();
    await expect(cardB).toContainText(`approved by ${approver.email}`);

    // --- requester sees it active after reload; API agrees
    await a.reload();
    await expect(a.locator('li').filter({ hasText: key }).getByText('ACTIVE', { exact: true })).toBeVisible();
    const list = await admin.json<{ items: any[] }>(await admin.get('exceptions'));
    const rec = list.items.find((x) => x.finding_key === key);
    expect(rec.status).toBe('APPROVED');
    expect(rec.active).toBe(true);
    expect(rec.decided_by).not.toBe(rec.requested_by);
    await ctxA.close();
    await ctxB.close();
  });

  test('an auditor can request but sees no approve/reject buttons', async ({ page }) => {
    const admin = await adminClient();
    const aud = await admin.createUser('AUDITOR', 'aud');
    const approver = await admin.createUser('APPROVER', 'appr2');
    const assetId = seed().insecure.asset_id;
    const key = `CIS-QA-${uniq('k')}`;
    await (await loginClient(aud.email)).post('exceptions', { asset_id: assetId, finding_key: key, reason: 'Vendor patch scheduled next quarter', days: 30 });
    await seedSession(page, (await loginClient(aud.email)).token);
    await page.goto('/exceptions');
    const card = page.locator('li').filter({ hasText: key });
    await expect(card).toBeVisible();
    await expect(card.getByRole('button')).toHaveCount(0);
    // the approver can reject it; rejected is not active
    const ap = await loginClient(approver.email);
    const list = await ap.json<{ items: any[] }>(await ap.get('exceptions'));
    const id = list.items.find((x) => x.finding_key === key).exception_id;
    expect((await ap.post(`exceptions/${id}/reject`, { comment: 'not enough' })).status()).toBe(200);
    await page.reload();
    await expect(page.locator('li').filter({ hasText: key }).getByText('REJECTED', { exact: true })).toBeVisible();
  });
});

test.describe('Workflow: recurring audit schedule', () => {
  test('create, run now, pause/resume and delete a schedule', async ({ page }) => {
    const admin = await adminClient();
    // The asset dropdown shows the newest 100 assets: create our own before the page loads so the test
    // does not depend on where the shared seed asset sits in that list. "Run now" re-audits the asset's
    // latest configuration, so upload one first.
    const schedAsset = uniq('sched-asset');
    const created = await admin.createAsset(schedAsset);
    await admin.upload(created.asset_id, path.join(CORPUS_DIR, 'cisco_iosxe_branch_insecure.cfg'));
    await seedSession(page, admin.token);
    await page.goto('/schedules');
    await heading(page, /recurring audits/i);

    const create = page.getByRole('button', { name: 'Create schedule' });
    await expect(create).toBeDisabled(); // needs an asset
    const name = uniq('nightly');
    await page.getByLabel('Asset').selectOption({ label: schedAsset });
    await page.getByLabel('Name (optional)').fill(name);
    await page.getByLabel('How often').selectOption({ label: 'Daily' });
    await create.click();

    const row = page.locator('tr').filter({ hasText: name });
    await expect(row).toBeVisible();
    await expect(row).toContainText('Daily');
    await expect(row).toContainText(/CIS, NIST, STIG, ISO27001 \+ CVE/);
    await expect(row).toContainText(/next /);

    await row.getByRole('button', { name: 'Run now' }).click();
    await expect(page.getByText(/audit queued/i)).toBeVisible();

    await row.getByRole('button', { name: 'Pause' }).click();
    await expect(row.getByText('PAUSED', { exact: true })).toBeVisible();
    await row.getByRole('button', { name: 'Resume' }).click();
    await expect(row.getByRole('button', { name: 'Pause' })).toBeVisible();

    // API validation: shortest allowed interval is enforced server-side
    const bad = await admin.post('schedules', { name: 'x', asset_id: seed().insecure.asset_id, interval_minutes: 1 });
    expect(bad.status()).toBeGreaterThanOrEqual(400);
    expect(bad.status()).toBeLessThan(500);

    page.once('dialog', (d) => void d.accept());
    await row.getByRole('button', { name: 'Delete' }).click();
    await expect(page.locator('tr').filter({ hasText: name })).toHaveCount(0);
  });
});

test.describe('Workflow: webhook creation validation', () => {
  let admin: Client;
  test.beforeAll(async () => {
    admin = await adminClient();
  });

  test('private, loopback and metadata destinations are rejected with a readable message; a public one is accepted', async ({ page }) => {
    await seedSession(page, admin.token);
    await page.goto('/integrations');
    await heading(page, /integrations/i);
    const add = page.getByRole('button', { name: 'Add webhook' });

    for (const url of ['http://10.0.0.5/hook', 'https://192.168.1.20/hook', 'http://127.0.0.1:9/hook', 'https://169.254.169.254/latest/meta-data']) {
      await page.getByLabel('Name', { exact: true }).fill('qa-bad-hook');
      await page.getByLabel('HTTPS URL').fill(url);
      await add.click();
      const alert = page.getByRole('alert');
      await expect(alert, url).toBeVisible();
      await expect(alert, url).not.toContainText(/traceback|internal server error|\[object/i);
      await expect(alert, url).toContainText(/not allowed|private|loopback|https|refus|metadata/i);
    }
    // nothing was created
    await expect(page.getByText('qa-bad-hook')).toHaveCount(0);

    // A public literal IP needs no DNS lookup and nothing is sent at creation time.
    const good = uniq('qa-good-hook');
    await page.getByLabel('Name', { exact: true }).fill(good);
    await page.getByLabel('HTTPS URL').fill('https://8.8.8.8/hooks/qa');
    await add.click();
    await expect(page.getByText(/signing secret for/i)).toBeVisible();
    await expect(page.locator('li').filter({ hasText: good })).toBeVisible();

    page.once('dialog', (d) => void d.accept());
    await page.locator('li').filter({ hasText: good }).getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByText(good)).toHaveCount(0);
  });

  test('API enforces the same policy and a non-admin cannot reach integrations', async () => {
    const r = await admin.post('integrations/webhooks', { name: 'x', url: 'http://10.1.2.3/h', events: ['audit.completed'], format: 'json' });
    expect(r.status()).toBe(400);
    const aud = await loginClient((await admin.createUser('AUDITOR', 'aud-wh')).email);
    expect((await aud.get('integrations/webhooks')).status()).toBe(403);
  });
});
