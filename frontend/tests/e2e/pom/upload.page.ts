import { Page, expect } from '@playwright/test';
import path from 'path';
import fs from 'fs';
import os from 'os';

/** Upload → Configuration → Start Audit POM */
export class UploadPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/configurations/upload');
    await expect(this.page.getByRole('heading', { name: /upload configuration/i })).toBeVisible();
  }

  /** Creates a temp Cisco-like config file and attaches it via the file input. */
  async attachSampleConfig(filename = 'sample-router.cfg') {
    const content = [
      'hostname Core-Router-01',
      'enable secret 5 $1$abcd$efgh123456789',
      'ip http server',
      'no ip ssh version 2',
      'snmp-server community public RO',
      'interface GigabitEthernet0/0',
      ' ip address 192.168.1.1 255.255.255.0',
      ' no shutdown',
    ].join('\n');
    const tmp = path.join(os.tmpdir(), filename);
    fs.writeFileSync(tmp, content);
    await this.page.getByTestId('upload-file-input').setInputFiles(tmp);
    await expect(this.page.getByText(filename)).toBeVisible();
    return tmp;
  }

  async submitAndWaitForUpload() {
    const uploadResp = this.page.waitForResponse(
      (r) => r.url().includes('/api/') && r.url().includes('/configurations'),
    );
    await this.page.getByTestId('upload-submit').click();
    return uploadResp;
  }

  async expectUploadAccepted() {
    await expect(
      this.page.getByTestId('upload-success').or(this.page.getByTestId('upload-error')),
    ).toBeVisible({ timeout: 30_000 });
  }
}

export class ConfigurationPage {
  constructor(private page: Page) {}

  async expectLoaded() {
    await expect(this.page.getByRole('button', { name: /start audit/i }).first()).toBeVisible({
      timeout: 20_000,
    });
  }

  async openStartAuditDialog() {
    const btn = this.page.getByTestId('start-audit-open');
    await btn.scrollIntoViewIfNeeded();
    await expect(btn).toBeVisible();
    await btn.click();
    await expect(this.page.getByRole('heading', { name: /start audit/i }).last()).toBeVisible();
  }

  async confirmStartAudit() {
    const auditResp = this.page.waitForResponse(
      (r) => r.url().includes('/api/') && r.url().includes('/audits'),
    );
    await this.page.getByTestId('start-audit-confirm').click();
    return auditResp;
  }

  async expectAuditStarted() {
    await expect(this.page).toHaveURL(/\/audits\//, { timeout: 30_000 });
  }
}
