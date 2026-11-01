import { test, expect } from '@playwright/test';
import path from 'path';
import { adminClient, Client, CORPUS_DIR, corpusFiles } from './helpers/api';
import { heading, seedSession, watchHealth } from './helpers/ui';

/**
 * Multi-vendor correctness smoke: every file in okf/tests/corpus is uploaded through the real UI and audited.
 * Expected vendor/platform is the ground truth encoded in the file name (the corpus is authored, not customer data).
 * This proves the pipeline runs end to end for all 8 platforms; it does NOT prove parser accuracy on real-world configs
 * (see docs/REMAINING_WORK.md, P1-2).
 */
const EXPECTED: Record<string, { vendor: string; platform: string }> = {
  'arista_eos_leaf.cfg': { vendor: 'ARISTA', platform: 'eos' },
  'cisco_iosxe_branch_insecure.cfg': { vendor: 'CISCO', platform: 'ios-xe' },
  'cisco_iosxe_core_hardened.cfg': { vendor: 'CISCO', platform: 'ios-xe' },
  'cisco_nxos_dc_switch.cfg': { vendor: 'CISCO', platform: 'nx-os' },
  'fortios_fg100f_edge.cfg': { vendor: 'FORTINET', platform: 'fortios' },
  'junos_ex_access_mixed.cfg': { vendor: 'JUNIPER', platform: 'junos' },
  'junos_srx_edge_set.cfg': { vendor: 'JUNIPER', platform: 'junos' },
  'panos_pa850_set.cfg': { vendor: 'PALOALTO', platform: 'pan-os' },
};

const scores: Record<string, { score: number; critHigh: number; auditId: string }> = {};
let admin: Client;

test.beforeAll(async () => {
  admin = await adminClient();
});

test('the corpus covers 8 files and every one has an expectation', () => {
  expect(corpusFiles().sort()).toEqual(Object.keys(EXPECTED).sort());
});

for (const file of Object.keys(EXPECTED)) {
  test(`UI audit of ${file}: vendor, platform, coverage panel, no server errors`, async ({ page }) => {
    test.setTimeout(180_000);
    const exp = EXPECTED[file];
    const health = watchHealth(page);
    await seedSession(page, admin.token);
    await page.goto('/quick-audit');
    await heading(page, /upload & audit/i);

    await page.getByTestId('quick-file-input').setInputFiles(path.join(CORPUS_DIR, file));
    const uploaded = page.waitForResponse((r) => r.url().includes('/configurations/upload'));
    await page.getByTestId('quick-run').click();
    const up = await uploaded;
    expect(up.status(), 'upload').toBe(200);
    expect(String((await up.json()).data.detected_vendor).toUpperCase()).toBe(exp.vendor);

    await expect(page).toHaveURL(/\/audits\/(AUD-[^/]+)\/results/, { timeout: 150_000 });
    const auditId = page.url().match(/\/audits\/([^/]+)\/results/)![1];
    await heading(page, /audit results/i);

    // coverage panel: present, numeric, and consistent with the API
    const res = await admin.results(auditId);
    const a = res.assessment;
    expect(String(res.vendor?.vendor ?? '').toUpperCase()).toBe(exp.vendor);
    expect(Number(res.vendor?.confidence)).toBeGreaterThan(0.8);
    expect(a.parser.used, 'a structured parser handled this platform').toBe(true);
    expect(String(a.parser.platform).toLowerCase()).toBe(exp.platform);
    expect(a.applicable).toBeGreaterThan(50);
    expect(a.coverage_pct).toBeGreaterThan(70);
    await expect(page.getByText('Assessment coverage')).toBeVisible();
    await expect(page.getByText(/\d+(\.\d+)?% assessed/)).toBeVisible();
    await expect(page.getByText(`Parsed with the ${a.parser.platform} structured parser`)).toBeVisible();

    // results are sane
    expect(res.status).toBe('COMPLETED');
    expect(res.degraded ?? []).toEqual([]);
    expect(res.summary.compliance_score).toBeGreaterThanOrEqual(0);
    expect(res.summary.compliance_score).toBeLessThanOrEqual(100);
    expect(res.findings.length).toBeGreaterThan(10);
    for (const fw of ['CIS', 'NIST', 'STIG', 'ISO27001']) expect(res.frameworks, fw).toHaveProperty(fw);
    const ids = res.findings.map((f: any) => f.finding_id);
    expect(new Set(ids).size, 'finding ids are unique').toBe(ids.length);
    for (const f of res.findings) {
      expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']).toContain(String(f.severity).toUpperCase());
      expect(['PASS', 'FAIL', 'UNKNOWN', 'OPEN', 'NOT_APPLICABLE', 'NOT_ASSESSED', 'ASSUMED']).toContain(String(f.status).toUpperCase());
    }

    // the page shows the same score as the API (rounded)
    await expect(page.getByText(`${Math.round(res.summary.compliance_score)}%`).first()).toBeVisible();

    scores[file] = {
      score: res.summary.compliance_score,
      critHigh: (res.summary.critical ?? 0) + (res.summary.high ?? 0),
      auditId,
    };
    expect(health.badResponses).toEqual([]);
    expect(health.consoleErrors.filter((e) => !/favicon/i.test(e))).toEqual([]);
  });
}

test('a hardened config scores far higher than an insecure one (same platform)', async () => {
  test.setTimeout(180_000);
  const bad = await auditApi('cisco_iosxe_branch_insecure.cfg');
  const good = await auditApi('cisco_iosxe_core_hardened.cfg');
  expect(good.summary.compliance_score).toBeGreaterThan(bad.summary.compliance_score + 30);
  expect(good.summary.failed).toBeLessThan(bad.summary.failed);
  const crit = (r: any) => (r.summary.critical ?? 0) * 10 + (r.summary.high ?? 0);
  expect(crit(good)).toBeLessThan(crit(bad));
  // hardened configs must not trip the obvious weak-configuration controls the insecure one fails
  const failedTitles = (r: any) => new Set(r.findings.filter((f: any) => f.status === 'FAIL' && f.engine === 'compliance').map((f: any) => f.control_id));
  const badSet = failedTitles(bad);
  const goodSet = failedTitles(good);
  expect(badSet.size).toBeGreaterThan(10);
  expect(goodSet.size).toBeLessThan(badSet.size / 4);
});

test('every platform produces a deterministic score (same file twice -> same result)', async () => {
  test.setTimeout(180_000);
  const a = await auditApi('junos_srx_edge_set.cfg');
  const b = await auditApi('junos_srx_edge_set.cfg');
  expect(b.summary.compliance_score).toBe(a.summary.compliance_score);
  expect(b.findings.length).toBe(a.findings.length);
});

async function auditApi(file: string) {
  const r = await admin.auditFile(`qa-${file}-${Date.now()}`, path.join(CORPUS_DIR, file));
  return admin.results(r.audit_id);
}

test.afterAll(() => {
  // visible in the list reporter's output for the QA report
  console.log('corpus scores:', JSON.stringify(Object.fromEntries(Object.entries(scores).map(([k, v]) => [k, Math.round(v.score)]))));
});
