# Security & Operations Guide

How the product protects customer data, and what an operator must do to run it safely.
Companion to [`product_readiness_gaps.md`](product_readiness_gaps.md).

## 1. Threat model in one page

| Asset | Threat | Control |
|---|---|---|
| Device configurations (passwords, SNMP communities, keys, topology) | DB leak, provider access, insider read | Encrypted in the app before the DB (Fernet/AES); VIEWERs see masked text; evidence lines are redacted before they are stored |
| Customer isolation | One tenant reading/overwriting another | `org_id` on every table, enforced centrally in `persist.py`; upserts refuse cross-org overwrite; JWT carries the org |
| Account takeover | Brute force, stolen token | PBKDF2-600k, per-account lockout, per-IP throttle, 60-min tokens, server-side revocation on logout / password change / role change / disable |
| Privilege misuse | A low-privilege user changing what audits say | RBAC matrix (`app/core/rbac.py`) applied to every `/api/v1` route; approvals are stamped with the authenticated actor |
| Repudiation | "I didn't approve that" | Append-only `audit_log` (DB trigger rejects UPDATE/DELETE), incl. denied attempts |
| Data exfiltration to AI vendors | Configs sent to a third-party LLM | Off by default; local model supported; secrets redacted before any LLM call |
| Supply chain | Tampered ML artifact (pickle = code execution) | SHA-256 manifest (+ optional HMAC) verified before every model load; `strict` in production |
| Malicious config text | Regex injection / ReDoS via learned mappings | Learned patterns are escaped, anchored, length-limited and self-match-tested |

## 2. Roles

| Role | Can |
|---|---|
| VIEWER | read everything in the own org (configs masked) |
| AUDITOR | + upload configs, run audits & reports, manage assets, request AI suggestions |
| APPROVER | + approve/reject learned mappings and remediation, delete assets |
| ADMIN | + manage users, CVE sync, bulk maintenance, read the audit log |

## 3. First deployment checklist

1. Generate secrets
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"     # JWT_SECRET
   python -m app.cli gen-key                                   # DATA_ENCRYPTION_KEYS
   ```
2. Fill `backend/.env` from `.env.example`: `ENV=production`, `REQUIRE_AUTH=true`, strong `ADMIN_PASSWORD`,
   explicit `CORS_ORIGINS` / `TRUSTED_HOSTS`, `DATABASE_URL`, `DATA_ENCRYPTION_KEYS`.
3. `python -m app.cli check-config` must print `configuration OK for production`. The server also refuses to
   start otherwise.
4. Apply the database schema: `python -m app.cli migrate` (idempotent, tracked in `schema_migrations`).
5. Existing data from before encryption existed: `python -m app.cli encrypt-existing`.
6. Create tenants/users: `python -m app.cli create-org ORG-ACME "Acme Ltd"` and
   `python -m app.cli create-user alice@acme.com "Alice" ADMIN --org ORG-ACME` (password via prompt/stdin).
7. Terminate TLS in front of the frontend container (load balancer/ingress). Do not publish port 8000.
8. Back up `DATA_ENCRYPTION_KEYS` **separately from the database**. Losing it makes stored configs unreadable.

## 4. Key rotation
Prepend a new key: `DATA_ENCRYPTION_KEYS=<new>,<old>` and restart; old rows still decrypt. Then run
`python -m app.cli reencrypt` and, once finished, drop the old key.

## 5. AI / LLM data handling
* Default: **no external calls**. The system runs deterministically; unknown lines go to the human training queue.
* Local model: point `FEATHERLESS_BASE_URL` at an OpenAI-compatible server on your network
  (e.g. `http://localhost:11434/v1`). No key and no opt-in flag needed; nothing leaves the host.
* External model: requires both `FEATHERLESS_API_KEY` and `ALLOW_EXTERNAL_LLM=true`. Secrets are redacted and
  every call is logged (endpoint, model, size) by the `llm_gateway` logger.

## 6. ML artifacts
Models are pickles; loading one executes code, so every load goes through `models/src/artifact_guard.py`.
After retraining, regenerate the manifest through code review: `python models/scripts/sign_artifacts.py`
(set `ARTIFACT_SIGNING_KEY` to authenticate it). Mount `models/` read-only in production.

## 7. Sessions and multi-factor authentication
* **Cookie sessions (web client).** The production frontend build (`VITE_COOKIE_AUTH=true`) logs in with
  `X-Auth-Mode: cookie`; the server then puts the JWT in an **httpOnly, SameSite=Strict, Secure** cookie
  (`qirova_session`, path `/api`) and returns an empty `access_token` in the body, so page scripts - and therefore an
  XSS bug - cannot read it. State-changing requests must carry `X-CSRF-Token` equal to the readable `qirova_csrf`
  cookie (double-submit). API clients keep using `Authorization: Bearer` unchanged. Logout clears both cookies and
  revokes the token server-side. Development builds stay on bearer tokens.
* **TOTP MFA (RFC 6238).** Any user can enrol an authenticator app (Settings -> Two-factor authentication). Login then
  asks for a code; a wrong code counts toward the account lockout; each time-step is accepted once (replay guard);
  10 single-use recovery codes are stored only as SHA-256 hashes; the secret is encrypted at rest. Enabling/disabling
  signs out all other sessions. Disabling needs password + a valid code; an admin can reset a user who lost both
  (`POST /api/v1/admin/users/{id}/mfa-reset`). Roles in `MFA_REQUIRED_ROLES` (default `ADMIN`) must enrol: with `MFA_ENFORCE=true` (the production default) such an account can only reach `/auth/*`
  until it has enrolled; SSO users are exempt (the identity provider owns their second factor). Set `MFA_ENFORCE=false` to only prompt.

## 8. Single sign-on (OpenID Connect)
Works with any OIDC provider (Entra ID, Okta, Keycloak, Google Workspace). Authorization-code flow with PKCE (S256),
`state` + `nonce` held in a short-lived signed httpOnly cookie, ID-token signature verified against the provider's JWKS
(asymmetric algorithms only - `HS*` and `none` are refused), `iss` / `aud` / `azp` / `exp` / `nonce` checked, unverified
e-mails refused. Set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`
(`https://<api-host>/api/v1/auth/sso/callback`) and `OIDC_FRONTEND_URL`.
* **Roles come from the IdP groups** on every login: `OIDC_ROLE_MAP='{"net-admins":"ADMIN","auditors":"AUDITOR"}'`
  (`OIDC_GROUPS_CLAIM`, default `groups`). The highest mapped role wins; no mapped group and no `OIDC_DEFAULT_ROLE` means
  no access. A demotion bumps the account's token version, so existing sessions die immediately.
* **No silent account takeover:** an existing local account with the same e-mail is refused unless
  `OIDC_LINK_EXISTING_USERS=true`. `OIDC_ALLOWED_DOMAINS` restricts e-mail domains; `OIDC_AUTO_PROVISION=false` requires
  users to be created first. `SSO_ONLY=true` refuses password login for everyone except ADMIN (break-glass).
* SSO sessions use the httpOnly cookie, so the production (cookie-mode) frontend build is required. MFA is the
  provider's job; local TOTP is not asked for SSO users.
* One identity provider and one default tenant per deployment (`OIDC_ORG_ID`); per-tenant IdPs and SAML are not built.
* **Not yet tested against a real IdP tenant.** The flow is covered by 22 tests against an in-process fake IdP that signs
  real RS256 tokens (`tests/test_sso.py`); a pilot must still try it with the customer's provider.

## 9. Key management (envelope encryption)
`KEY_PROVIDER=env` (default) keeps the Fernet data keys in `DATA_ENCRYPTION_KEYS`. For KMS-backed keys set
`KEY_PROVIDER=vault` (HashiCorp Vault Transit: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_TRANSIT_KEY`, optional
`VAULT_NAMESPACE`) or `aws-kms` (`AWS_REGION`, `KMS_KEY_ID`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional
`AWS_SESSION_TOKEN`). Then store only **wrapped** keys: `python -m app.cli kms-wrap` generates a new data key, wraps it,
prints the wrapped form (never the plain key) for `DATA_ENCRYPTION_KEYS_WRAPPED`; leave `DATA_ENCRYPTION_KEYS` empty
(production start-up refuses both). Keys are unwrapped into process memory at start-up; the master key never leaves the
key service, so a database dump plus a stolen env file still cannot decrypt anything. Rotate the master key in the key
service; rotate a data key by wrapping a new one, prepending it, and running `python -m app.cli reencrypt`.
Tested against fake key services including the AWS SigV4 signing-key vector; **not yet exercised against a live Vault or
AWS account** - do that once in staging.

## 10. Row-level security (defence in depth)
Tenant isolation is enforced in the application layer (every query carries `org_id`) and now optionally in Postgres:
`python -m app.cli rls-enable` adds a `tenant_isolation` policy (`org_id = current_setting('app.org_id')`) and `FORCE ROW
LEVEL SECURITY` on every table that has an `org_id` (not `audit_log` / `organizations`). With `RLS_ENABLED=true` the API
binds the caller's tenant on each connection checkout (`'*'` = explicit system scope for login lookup, worker, scheduler,
retention, metrics). A forgotten `WHERE org_id` can then no longer leak or modify another tenant's rows.
* **The API must connect as a plain role.** Superusers and roles with `BYPASSRLS` (the Supabase `postgres` role) ignore
  policies. Create one: `CREATE ROLE auditor_app LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS;` then
  `GRANT USAGE ON SCHEMA public TO auditor_app; GRANT ALL ON ALL TABLES IN SCHEMA public TO auditor_app;
  GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO auditor_app;` and use it in `DATABASE_URL`. Keep migrations and
  `rls-enable` on the owner role. `python -m app.cli rls-status` reports whether the connecting role bypasses RLS.
* **What it does not cover:** SQL injection that can run arbitrary statements could still change `app.org_id`. The
  application uses bound parameters everywhere; RLS is a second wall against logic bugs, not a replacement for it.
* The whole backend suite also runs in this mode (`TEST_RLS=1 python -m pytest`), which is how the cross-tenant system
  paths (login, worker queue, scheduler, retention, metrics) were found and fixed.

## 11. Live collection over SSH
Read-only, opt-in, admin-controlled. Details: [`COLLECTION.md`](COLLECTION.md). Summary: only an allow-list of `show`/`get`
commands per platform is ever sent; the device host key is pinned and checked **before** a credential is offered;
credentials are encrypted at rest and never returned by any API; targets and credentials are ADMIN-only (an auditor
cannot aim a credential at a machine they control); metadata / loopback / link-local targets are refused and
`COLLECT_ALLOWED_CIDRS` can confine collection to the management network.

## 12. Known limitations (honest list)
* SAML is not supported; OIDC is untested against a real identity provider (see section 8).
* KMS providers are untested against a live Vault / AWS account (section 9); RLS needs a non-bypass DB role (section 10).
* The login IP throttle is per process; the account lockout is database-wide.
* Bulk upload buffers files in memory (limit 20 x 5 MB).
* Live collection is validated against an in-process SSH server, not real network devices (see `COLLECTION.md`).

## 13. Abuse limits and edge hardening (security review)
Full methodology, findings and residual risks: [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md). Operator-relevant controls:
* **Request size** - bodies are capped while they stream in (`MAX_JSON_BODY_BYTES` 8 MB, `MAX_UPLOAD_BODY_BYTES` 110 MB,
  413 otherwise); nginx enforces the same ceilings per location. A configuration may have at most `MAX_CONFIG_LINES` lines.
* **Rate limiting** - expensive endpoints (audit, report, upload, AI suggestion, CVE sync) draw from a token bucket per
  organisation and per user (`RATE_LIMIT_EXPENSIVE_PER_MIN` / `_BURST`, 429 + `Retry-After`). It is per API process;
  nginx adds `limit_req` per client address (login: 10/min).
* **Client address** - nginx *overwrites* `X-Forwarded-For` with the connecting address and uvicorn trusts forwarded headers
  only from private ranges, so login throttling and the audit log cannot be spoofed. If a load balancer sits in front of
  nginx, configure nginx `set_real_ip_from` for it (see the comment in `frontend/nginx.conf`).
* **Webhooks** - the destination is resolved and validated once and the connection is made to that exact address (no
  DNS-rebinding window); redirects are never followed; cloud-metadata, CGNAT, NAT64/6to4-embedded and private addresses are refused.
* **Sessions** - the CSRF token is an HMAC bound to the session, code guesses (login, MFA enable/disable,
  password change) share one lockout counter, and accounts flagged `must_change_password` can do nothing but change it.
* **Containers** - the API image has no compiler and runs as a fixed non-root uid; the web image is nginx-unprivileged on
  8080 with a read-only root filesystem; secrets are kept out of the build context by the root `.dockerignore`.
