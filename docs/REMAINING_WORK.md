# What is still open, and why

Last updated 2026-10-10. Everything that could be built and tested without a customer, a licence, lab hardware or a
third-party tenant has been built. What remains is listed with the exact thing needed to close it. **None of it can be
closed honestly by writing more code alone** - the code and tooling to close each item exists and is named below.

## Built since the last revision (tooling is ready; evidence still needs the outside input)
| Item | What now exists | What it still needs |
|---|---|---|
| Real-customer accuracy (P1-2) | `python -m app.cli anonymize` (verdict-preserving, tested on all 8 sample configs), `python -m app.cli corpus-eval` (parse coverage, vendor detection, **false-compliant** count, pilot-bar exit code), `docs/PILOT_KIT.md` | 20-50 real configs per vendor from design partners |
| Licensed control catalogues (P1-5/6) | `catalogue-import` (DISA STIG XCCDF, CSV, JSON), mandatory licence/source, unmapped entries report UNKNOWN never PASS, `catalogue-coverage`, `docs/CATALOGUES.md` | The customer's licensed copy (CIS SecureSuite, ISO 27001) and reviewed condition mappings |
| Lab-verified fixes (P1-9) | `remediation-verifications` API: before/after/rollback configurations are re-audited by the product; a fix is "lab-verified" only with that evidence, per organisation | Lab images or a maintenance window, and someone to apply the fixes (NX-OS templates stay excluded until then) |
| Live collection (P2-1) | Read-only SSH collector (command allow-list, pinned host key checked before auth, encrypted credential vault, ADMIN-only targets, allowed-CIDR guard), job + API, tested against a **real in-process SSH server**; `docs/COLLECTION.md` | One real device per platform to find the quirks (paging, banners, session limits) |
| SSO (OIDC) | Authorization-code + PKCE, JWKS-verified ID tokens, group-to-role mapping, no silent account takeover, break-glass admin; 22 tests against an in-process fake IdP | A real IdP tenant (Entra ID / Okta / Keycloak) to try once; SAML if a customer needs it |
| Row-level security | `rls-enable/disable/status`, per-connection tenant binding, the **entire backend suite passes as a non-bypass role with RLS on** (`TEST_RLS=1`) | Running the API as a non-bypass role in the real database (Supabase `postgres` bypasses RLS) |
| KMS-backed keys | Envelope encryption: Vault Transit and AWS KMS (SigV4, stdlib), `kms-wrap`, production validation; tested with fake key services and the AWS signing-key vector | One run against a live Vault / AWS account |

## Still open
| Item (register id) | Why it is open | What is needed to close it |
|---|---|---|
| Real-world pilot | No customer has run it | 2-3 design partners (`docs/PILOT_KIT.md`) |
| Gated remediation execution (P2-3) | Pushing config to production devices needs a change-approval policy, dry-run diff, rollback proof | A signed-off change workflow and lab; ship read-only until then |
| Syslog (RFC 5424) output | Webhook formats (JSON, Slack, Teams, CEF, Jira, ServiceNow) are done; raw syslog needs a TCP/TLS sender | Requirement from a SIEM customer |
| EPSS + vendor PSIRT feeds, DB-backed CVE KB (P1-7) | KB freshness needs a real sync from the deployment network; PSIRT feeds have per-vendor formats | Run the sync in the target environment; decide feeds |
| i18n / full accessibility audit | Skip-link, labels and contrast were handled; a WCAG audit needs assistive-tech testing | Accessibility review |
| CI pipeline | Written (tests, SBOM) but never executed on a hosted runner | Push to a repository and make the pipeline green |
| Per-tenant IdP / SAML | One OIDC provider per deployment | A customer that needs it |

## Operator actions required before any real deployment

1. Run migrations against *your* database (never done by the development agent): `python -m app.cli migrate`
   (005 - 016). Optional afterwards: `rls-enable`.
2. Set secrets: `JWT_SECRET`, `DATA_ENCRYPTION_KEYS` (or a KMS provider and `DATA_ENCRYPTION_KEYS_WRAPPED`), `METRICS_TOKEN`,
   `ADMIN_PASSWORD`, explicit `CORS_ORIGINS`, `TRUSTED_HOSTS`; run `python -m app.cli check-config` and fix every problem it prints.
3. `python -m app.cli encrypt-existing` once, if configurations were stored before encryption was enabled.
4. Run at least one worker (`python -m app.worker`) and set `CVE_AUTO_SYNC_HOURS=24`; run an initial CVE sync for
   PAN-OS, EOS and the other vendors. Live collection also runs in the worker.
5. Have every admin enrol MFA (Settings -> Two-factor authentication) or configure SSO.
6. Push the repository to CI and make the pipeline green (it has been written but never executed).
