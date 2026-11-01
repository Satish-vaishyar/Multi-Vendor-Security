import path from 'path';
import { adminClient, CORPUS_DIR } from './helpers/api';

/**
 * Runs once before the suite: seeds the shared (default) organisation with two audited devices (an insecure and a
 * hardened Cisco IOS-XE config) so read-only specs have real findings to browse. Specs that mutate state create
 * their own users/assets, so the suite can be re-run against the same database.
 * The result is handed to the workers through process.env.QA_SEED.
 */
export default async function globalSetup() {
  const admin = await adminClient();
  const insecure = await admin.auditFile('qa-seed-insecure', path.join(CORPUS_DIR, 'cisco_iosxe_branch_insecure.cfg'));
  const hardened = await admin.auditFile('qa-seed-hardened', path.join(CORPUS_DIR, 'cisco_iosxe_core_hardened.cfg'));
  const res = await admin.results(insecure.audit_id);
  const findings: any[] = res.findings ?? [];
  const failed = findings.find((f) => String(f.status).toUpperCase() === 'FAIL' && /compliance/i.test(String(f.engine ?? f.type ?? '')))
    ?? findings.find((f) => String(f.status).toUpperCase() === 'FAIL');
  const seed = {
    insecure,
    hardened,
    findingId: failed?.finding_id as string | undefined,
    controlId: failed?.control_id as string | undefined,
  };
  process.env.QA_SEED = JSON.stringify(seed);
}
