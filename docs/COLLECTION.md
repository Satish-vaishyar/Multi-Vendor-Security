# Live collection (read-only, over SSH)

Instead of uploading a configuration by hand, an administrator can register a device once and let the product pull its
running configuration on demand (and, through the scheduler, on a schedule). It never changes a device.

## What is sent to the device
Only these commands, as SSH *exec* requests (no interactive shell, so there is no way to enter configuration mode):

| Profile | Commands |
|---|---|
| `cisco_ios` (IOS / IOS-XE) | `show running-config`, `show version` |
| `cisco_nxos` | `show running-config`, `show version` |
| `juniper_junos` | `show configuration \| display set`, `show version` |
| `fortinet_fortios` | `show full-configuration`, `get system status` |
| `paloalto_panos` | `show config running`, `show system info` |
| `arista_eos` | `show running-config`, `show version` |

The list lives in `backend/app/core/collector.py` (`PROFILES`). Adding a command is a reviewed code change, never a
runtime setting; a test asserts every command starts with `show`/`get` and contains no state-changing word.

## Security design
* **Host key pinning.** The device's SHA-256 host-key fingerprint is stored on the target and verified *before*
  authentication. A replaced device or a man-in-the-middle is refused and the credential is never offered. There is no
  trust-on-first-use during a run: the administrator scans the key once (`scan-host-key`), confirms the fingerprint
  out of band, and saves it.
* **Credential vault.** Passwords / private keys are encrypted with the field-encryption keys (or the KMS envelope, see
  `SECURITY.md`), never returned by any endpoint, and decrypted only inside the worker for one connection.
* **Who can do what.** Credentials and targets: ADMIN. Running a collection on an approved target: AUDITOR. This split
  matters: whoever edits a target decides which host receives the credential.
* **Network.** Metadata addresses, loopback, link-local, multicast and reserved ranges are refused when the target is
  saved and again at run time. Private ranges are allowed (devices live there); in production set `COLLECT_ALLOWED_CIDRS`
  to your management network so even an administrator cannot point it elsewhere.
* **Limits.** 30 s per command (`COLLECT_TIMEOUT_S`), 8 MB per command output (`COLLECT_MAX_BYTES`).
* **Audit trail.** Credential creation/deletion, target changes and collection requests are written to the audit log.

## Setup
1. Create a **read-only** account on the device (a privilege level / role that can run the show commands above).
2. `POST /api/v1/collection/credentials` `{name, username, secret, auth_type: password|key}` (ADMIN).
3. `POST /api/v1/assets/{id}/collection/scan-host-key` `{host, port}` -> fingerprint; compare it with the device
   (`show ip ssh` / `ssh-keygen -lf`).
4. `PUT /api/v1/assets/{id}/collection` `{host, port, profile, credential_id, host_key}`.
5. `POST /api/v1/assets/{id}/collect` `{audit: true}` -> a job; the worker collects, registers the configuration exactly
   like an upload (same validation, encryption, detection) and optionally audits it. Status and last error are on the
   target (`GET /api/v1/assets/{id}/collection`). Failures are not retried (a wrong credential or a changed host key will
   not fix itself) and appear on the Jobs page.

## What is and is not verified
* Verified by tests: the allow-list, target validation, pin-before-auth ordering, credential encryption and RBAC, the job
  handler, and the protocol against a **real in-process SSH server** (host key, password auth, exec, output cap).
* **Not verified:** behaviour on real devices. Real platforms differ in paging, banners, exec-channel support and
  session limits. Treat the first collection on each platform as a pilot step, and report what breaks.
* Not built: SSH jump hosts, per-device command overrides, certificate-based host trust, scheduled collection from the UI
  (use the scheduler to audit the latest configuration after a collect job).
