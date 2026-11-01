# Security review - adversarial pass over the backend, edge and containers

Scope: FastAPI backend (`backend/app`), the OKF layer it imports (`okf/`), `frontend/nginx.conf` + frontend security
headers, both Dockerfiles, `docker-compose.yml`, `.github/workflows/ci.yml`, and the dependency trees. Performed locally
against a disposable Postgres (`auditor_test_a`); no production / Supabase database was touched, nothing was committed, and
no third-party service received tenant data. Regression tests: `backend/tests/test_pentest.py` (ids `PT-nn` below).

Companion documents: [`SECURITY.md`](SECURITY.md) (what exists / how to operate), `product_readiness_gaps.md` (lead-owned).

## 1. Method

1. **Read first**: `docs/SECURITY.md`, then every module on the request path (`security.py`, `rbac.py`, `tenancy.py`,
   `persist.py`, `mfa.py`, `urlcheck.py`, `events.py`, every router, report generation, the parsers and the OKF code they call).
2. **Enumerate, don't sample**: the OpenAPI document (`app.openapi()`, 100+ operations) drives the sweeps, so a route added
   later is covered automatically:
   * anonymous request to every `/api/v1` operation -> must be 401;
   * for every role below the RBAC-matrix minimum -> must be 403, and at the minimum a GET must not be 403;
   * tenant B's ADMIN replays **every operation that carries an id** against tenant A's real objects (asset, configuration,
     audit, finding, report, signoff, training item, remediation approval, job, batch, schedule, webhook, exception, user,
     snapshot, fleet/CVE job) -> never 2xx with tenant data, and no tenant-A marker in any response; every list endpoint as B
     must not show A's rows;
   * every GET with a SQL / traversal / template / NUL payload in each query parameter and path id (200+ requests) -> never 5xx,
     never slow (time-based injection), tables intact; sort/order/filter parameters are whitelisted.
3. **Exploit, then fix, then pin**: each issue was reproduced (timings quoted below are measured), fixed with the smallest
   change in the right layer, and locked with a test that fails on the old code.
4. **Adversarial inputs at the documented limits**: 5 MB configs of single lines, repeated keywords, blank lines, PEM headers
   and one-token lines were timed against detection, redaction, every vendor parser and the heuristic/ML gap-fill; a 36-token x
   9-target matrix at 100 KB vs 400 KB flags anything super-linear (final run: none).
5. **Infrastructure as code** is linted by tests (`test_*dockerfile*`, `test_nginx_*`, `test_compose_*`, `test_ci_*`) so a
   regression to a wildcard proxy header, a root container or a token-writing CI job fails the suite.
6. **Dependencies**: `pip-audit` (locked, non-dev set; torch-cpu cannot be resolved on PyPI and is skipped) and `npm audit --omit=dev`.

## 2. Findings

Severity is the impact in a multi-tenant deployment holding customer device configurations.
Status: **fixed** (code + test), **accepted** (conscious trade-off, documented), **open** (needs an operator/product decision).

| Id | Sev | Area | Finding | Status | Test |
|---|---|---|---|---|---|
| PT-01 | High | AuthZ | `PATCH /assets/{id}` took an arbitrary JSON object: an AUDITOR could set `status=DELETED` (bypassing the APPROVER-only DELETE), overwrite `created_at`, stamp any key into the record | fixed - typed model, unknown keys ignored, `status` not editable | `test_patch_cannot_bypass_the_delete_privilege` |
| PT-02 | - | AuthZ | Cross-tenant IDOR sweep over every id-bearing route and every list endpoint, 4 mass-assignment probes (assets, users, webhooks, exceptions, remediation, schedules, training) | **no vulnerability found**; pinned | `test_idor_every_object_route_is_tenant_scoped`, `test_list_endpoints_never_show_another_tenants_rows`, `test_mass_assignment_cannot_set_owner_role_status_or_actor` |
| PT-03 | Low | AuthZ | `GET /configurations/{id}/unknowns` writes rows into the human-review queue, so a read-only VIEWER could add queue items | fixed - the write needs AUDITOR+, VIEWER still reads | `test_viewer_cannot_enqueue_training_items_through_a_get` |
| PT-04 | High | Tenancy | `POST /admin/retention/run` was documented as cross-tenant: any tenant's ADMIN could purge (and via dry-run, count) every other tenant's audit log, snapshots, PDFs and webhook history | fixed - the API call is scoped to the caller's org; the platform-wide purge stays in the worker/CLI | `test_retention_endpoint_is_scoped_to_the_callers_org` |
| PT-05 | - | Disclosure | Every GET (as VIEWER and ADMIN) scanned for `password_hash`, `pbkdf2$`, `mfa_*`, `secret_enc`, `auth_header_enc`, `whsec_`, the JWT secret, ciphertext prefixes; VIEWER config reads scanned for raw secrets | **none found**; pinned | `test_secret_material_never_appears_in_any_response` |
| PT-06 | Low | Injection | A NUL byte in a query string, path id or JSON string reached the driver and returned HTTP 500 | fixed - 400 at the edge (URL) and a `DataError` handler (bodies) | `test_nul_bytes_are_a_client_error_not_a_server_error` |
| PT-07 | Low | Upload | Client filename stored verbatim (directory parts, CR/LF, NUL, unbounded length) | fixed - basename, control chars stripped, 255 chars; the name is never used as a path | `test_upload_filenames_are_metadata_only[*]` |
| PT-08 | Med | Injection | Tenant text (asset name, vendor, finding titles, evidence) went raw into ReportLab `Paragraph()` markup: `<img src=file://...>` / `<img src=http://...>` made the PDF builder fetch/open resources and **fail the whole report**; `<a href>` planted live links in an "official" PDF | fixed - `safe_markup()` allow-lists the report's own tags; applied to the audit report and the fleet/evidence packs | `test_report_markup_injection_cannot_reach_the_pdf_engine` |
| PT-09 | **High** | DoS (regex/quadratic) | A single 5 MB config line needed **hours** (60 KB = 2.6 s -> quadratic): open-ended `.*` in the curated YAML mappings and in the offline heuristic rules, `shlex` on one huge token in the FortiOS/Junos parsers (3 MB = >100 s); `redact_secrets` on blank lines (`^\s*` crosses newlines: 40,000 newlines = 44 s, 5 MB = ~hours; PEM rule likewise); job hostname regexes; `difflib` on repetitive configs; the unknown-line ML scorer on 1M lines | fixed - bounded gaps (`.{0,100}`), 1 KiB match window, `[ \t]*` anchors, shlex only for lines <= 4 KiB, `MAX_CONFIG_LINES`=100k, diff input cap 20k lines, scorer cap 2k lines. 5 MB adversarial files now parse in <= ~30 s worst case (typically 1-5 s) | `test_pathological_5mb_configs_*`, `test_regex_dos_regressions_at_unit_level`, `test_config_diff_skips_inputs_*` |
| PT-10 | Med | Auth | Unknown e-mail verified against a 1,000-iteration dummy hash vs 600,000 for real accounts: login latency enumerated accounts | fixed - dummy hash uses the configured cost | `test_unknown_user_and_wrong_password_cost_the_same` |
| PT-11 | Med | Auth | A stolen session could brute-force the 6-digit code via `/auth/mfa/enable` / `/mfa/disable`, or the current password via `/auth/change-password`, with no limit | fixed - all share the account lockout counter (and 429 while locked) | `test_mfa_enable_and_disable_endpoints_are_rate_limited_by_lockout`, `test_mfa_code_guesses_count_toward_lockout_at_login` |
| PT-12 | Med | Auth | MFA replay guard and recovery-code burn were read-then-write: two parallel requests could both accept one captured code | fixed - compare-and-set / conditional JSONB removal | `test_totp_code_and_recovery_code_are_single_use_even_under_concurrency` |
| PT-13 | Med | Config | `ENV=prod` (typo) silently selected *development*, disabling every production guard | fixed - unknown `ENV` aborts start-up; production also rejects non-HS* algorithms, absurd token lifetimes and <210k PBKDF2 iterations; warns on default admin e-mail / private webhooks / limiter off | `test_environment_typo_fails_closed`, `test_production_config_guards` |
| PT-14 | Med | Session | Cookie-mode CSRF token was random and unbound: a cookie planted from a sibling sub-domain ("cookie tossing") satisfied double-submit | fixed - token = HMAC(secret, session id), checked against the session it rides on | `test_cookie_session_flags_and_signed_csrf` |
| PT-15 | High | SSRF | Webhook delivery validated the host, then let the HTTP client resolve it again (DNS rebinding); CGNAT 100.64/10 (Alibaba metadata 100.100.100.200), NAT64 / 6to4-embedded v4, Azure wire server were not blocked | fixed - one resolution, connection pinned to the validated IP (Host + SNI preserved), `is_global` required, embedded-v4 unwrapped, metadata set refused even with `WEBHOOK_ALLOW_PRIVATE`; redirects never followed | `test_ssrf_guard_*`, `test_delivery_uses_the_validated_address_and_survives_dns_rebinding`, `test_delivery_does_not_follow_redirects`, `test_delivery_rechecks_the_destination_*` |
| PT-16 | Med | DoS | No limit on how often a tenant could trigger audits, reports, uploads, AI suggestions or CVE syncs | fixed - token bucket per org and per user (cost-weighted), `RATE_LIMIT_EXPENSIVE_*`, 429 + `Retry-After` | `test_expensive_endpoints_are_rate_limited_per_org_and_per_user`, `test_token_bucket_math_and_cost_table` |
| PT-17 | Med | DoS | `POST /vulnerabilities/sync` (ADMIN) accepted unbounded `pages` / `since_days` / product lists: a tenant admin could make the API hammer NVD and rewrite the shared CVE KB for as long as they liked | fixed - clamped (<=10 pages, <=2000 per page, <=3650 days, <=50 products); cost 10 in the limiter | `test_cve_sync_inputs_are_bounded` |
| PT-18 | High | DoS | Version regexes `junos[^\d]*`, `eos[^\d]*`, `ios-xe software.*version` ... were quadratic on a config repeating the platform word | fixed - bounded gaps (backend + OKF fingerprint) | `test_regex_dos_regressions_at_unit_level` |
| PT-19 | Med | DoS | No application-level body cap (uploads were buffered by the multipart parser before any check) | fixed - ASGI middleware: 413 by `Content-Length`, or by counting streamed chunks and aborting early; 8 MB JSON / 110 MB multipart | `test_body_limit_is_enforced_while_streaming_not_after_buffering`, `test_oversized_requests_get_413_through_the_real_app` |
| PT-20 | Low | Disclosure | 422 responses echoed the submitted values (passwords, config text) and exception objects | fixed - only `loc`/`msg`/`type` | `test_validation_errors_and_logs_never_echo_secrets` |
| PT-21 | Low | Disclosure | `/readyz` returned the raw driver error (host, user) to anyone | fixed in production | `test_readyz_does_not_leak_driver_errors_in_production` |
| PT-22 | Low | Auth | A lone-surrogate password crashed the hasher (HTTP 500) | fixed - rejected by the policy | `test_weak_and_unencodable_passwords_are_rejected` |
| PT-23 | Low | Headers | `Content-Disposition` used unquoted ids / a user-influenced framework name | fixed - quoted + sanitised | `test_crlf_in_request_id_and_filenames_cannot_split_headers` |
| PT-24 | **High** | Infra | nginx *appended* to `X-Forwarded-For` and uvicorn ran with `--forwarded-allow-ips "*"`, so the **leftmost, client-chosen** address became `request.client`: login throttling and the audit-log IP were trivially spoofable | fixed - nginx overwrites the header, uvicorn trusts private ranges only | `test_nginx_config_is_hardened`, `test_backend_dockerfile_is_hardened` |
| PT-25 | **High** | Infra | No root `.dockerignore` although the build context is the repo root: `COPY okf` / `COPY models` baked `okf/.env`, virtualenvs and caches into the image (and the context sent `backend/.env` to the daemon) | fixed | `test_dockerignore_keeps_secrets_out_of_the_build_context` |
| PT-26 | Low | Infra | Backend runtime image carried `build-essential`, pip, uv; code and venv were writable by the service user | fixed - multi-stage, root-owned read-only code, fixed uid 10001 | `test_backend_dockerfile_is_hardened` |
| PT-27 | Med | Infra | nginx master ran as root with 4 re-added capabilities; no timeouts, one global 110 MB body limit for every route, no edge rate limits, dotfiles/source maps servable | fixed - nginx-unprivileged on 8080, no caps, per-location limits (login 10/min, API 8 MB, upload 110 MB), timeouts, shared header snippet, dotfile/`.map` 404 (**config could not be syntax-checked here: no nginx binary/image offline**) | `test_nginx_config_is_hardened`, `test_frontend_dockerfile_runs_unprivileged` |
| PT-28 | Low | Infra | compose: no `pids_limit`, writable web root fs, worker inherited an HTTP healthcheck that can never pass | fixed | `test_compose_has_no_exposed_backend_*` |
| PT-29 | Low | CI | checkouts persisted the token in `.git/config`; `uvx pip-audit` unpinned | fixed (`persist-credentials: false`, `pip-audit@2.7.3`) | `test_ci_workflow_is_least_privilege` |
| PT-30 | High (build-time) | Deps | `source-map-js` <= 1.2.1 event-loop DoS (via postcss) | fixed - lockfile patch bump 1.2.1 -> 1.2.2 (only that entry changed); `npm audit --omit=dev`: 0 | n/a (audit) |
| PT-31 | Low | DoS | `remediation/apply` `updated_config_text` and `detection/vendor` `config_text` bypassed the 5 MB upload ceiling | fixed - field limits | `test_oversized_requests_get_413_through_the_real_app` (+ validation) |
| PT-32 | Med | AuthZ | `must_change_password` was only a UI hint: an admin-created account kept full API access on its temporary password forever | fixed - such accounts can only reach `/auth/*` until the password is changed | `test_must_change_password_accounts_can_only_change_the_password` |

### Accepted / open

| Id | Sev | Item | Status |
|---|---|---|---|
| A-01 | Low | Account lockout is observable (`429` vs `401`): an attacker who sends 5 bad guesses learns an e-mail exists, and can lock a known account for 15 minutes (lockout-DoS). Mitigated by the per-IP throttle and nginx `limit_req`; the alternative (never revealing the lock) hurts legitimate users | accepted |
| A-02 | Low | E-mail addresses are one global namespace, so an ADMIN creating a user learns whether that address already exists in *another* tenant | accepted (inherent to e-mail-only login; fix = per-org login names) |
| A-03 | Med | Login IP throttle, the expensive-endpoint limiter and the dashboard cache are per process; with N workers the ceiling is N x. nginx `limit_req` is per node | accepted; move to Redis/Postgres counters if you scale out |
| A-04 | Med | No Postgres row-level security: tenant isolation is application-enforced (heavily tested, but one missing `org_id` predicate in new SQL would leak) | open (defence in depth) |
| A-05 | Low | CSP keeps `style-src 'unsafe-inline'` (runtime-injected component styles); `script-src` is strictly `'self'` | accepted |
| A-06 | Low | Base images and CI actions are pinned by tag, not by digest/commit SHA (digests cannot be resolved offline) | open - pin before first release (Dependabot/pinact) |
| A-07 | Low | Frontend renders reference URLs from the knowledge base as `href` without a scheme check (`FindingDetails`, `Remediation`); CSP blocks `javascript:` execution and the data is KB-sourced, not tenant-supplied | accepted |
| A-08 | Med | JWTs are HS256 with one shared secret and live 60 min (server-side revocation exists); no refresh-token rotation, no SSO, MFA is not enforced for ADMIN | open (product decision) |
| A-09 | Low | The shared CVE knowledge base is global: any tenant ADMIN can trigger a (bounded, NVD-only) sync that rewrites it for everyone | accepted; restrict to a platform operator when you have one |
| A-10 | Info | Local `backend/.env` and `okf/.env` contain live-looking Supabase/LLM credentials. They are git-ignored, absent from history, and now excluded from image builds, but they exist on this workstation - rotate them if the machine or a backup is ever shared | open (operator) |

## 3. What was *not* tested (be wary of these)

* **nginx**: the new `nginx.conf` / `security-headers.conf` could not be syntax-checked (no nginx binary or image available
  offline) and behaviour (limits, regex locations, the `include` of the header snippet, unprivileged startup) is untested. Run
  `docker compose up --build` and `nginx -t` before relying on it; the lint tests only check intent.
* **Docker builds**: neither image was built here (no network pulls). The multi-stage backend build and the
  `nginx-unprivileged` + `read_only` frontend are the likeliest places for a first-build surprise.
* **TLS, HSTS preload, real browser CSP enforcement, cookie behaviour behind a real HTTPS terminator**, and WebSocket/H2 specifics.
* **Load / multi-process behaviour**: the limiters are per process; concurrency was tested only for the MFA race (8 threads).
* **Supabase / pooler specifics, replication, backups, `DATA_ENCRYPTION_KEYS` rotation under load.**
* **Frontend XSS by manual UI review** was limited to grep-level checks (`dangerouslySetInnerHTML`, `innerHTML`, `eval`: none;
  token storage; external links). No browser-driven pentest.
* **Social/organisational controls**, SSO, incident response, log shipping and alerting.
* The ML artefacts are pickles; their SHA-256 manifest check (`artifact_guard`) was read, not attacked.
* An external-LLM deployment (`ALLOW_EXTERNAL_LLM=true`) was not exercised: redaction is covered by the existing suite.
* `backend/tests/test_remediation_gen.py` contains raw control bytes (`\x08`) that this review did not introduce (pre-existing; likely `\b` typed into a non-raw string) - worth a look.

## 4. Residual risks, ranked

1. **Regex/CPU abuse is bounded, not eliminated.** The worst measured adversarial 5 MB inputs now take seconds, and
   `MAX_CONFIG_LINES`, the 1 KiB match window and the rate limiter cap the blast radius, but audits still run synchronously in
   the API for `POST /audits`. Prefer `/jobs/audit` (worker) in production and give workers a CPU/time limit (container `cpus`,
   a watchdog around `run_audit`).
2. **Application-only tenant isolation** (A-04) - the single most valuable remaining defence-in-depth item.
3. **Per-process limiters** (A-03) behind multiple workers/replicas.
4. **Untested edge config** (section 3) - treat the nginx/compose changes as reviewed, not verified.
5. **Credential hygiene on the dev workstation** (A-10) and non-digest image/action pins (A-06).

## 5. How to re-run

```bash
cd backend
TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:55432/auditor_test_a \
  .venv/Scripts/python -m pytest -q -p no:cacheprovider -W ignore tests/test_pentest.py     # ~3-6 min (5 MB cases)
TEST_DATABASE_URL=... .venv/Scripts/python -m pytest -q -p no:cacheprovider -W ignore --cov=app --cov-report=term   # full suite + coverage gate
cd ../frontend && npm audit --omit=dev
uvx pip-audit@2.7.3 -r <(uv export --frozen --no-dev --no-hashes)
```

## 5. Addendum 2026-10-10 - surfaces added after the review
New code since the pass above: OIDC single sign-on, KMS envelope encryption, Postgres row-level security, live SSH collection,
the lab-verification API and the catalogue/anonymiser tools. The enumerating sweeps in section 1 cover every new route
automatically (anonymous -> 401, below-minimum role -> 403, cross-tenant replay) and pass; the public SSO login endpoints are
the only intentional exceptions and have their own tests (`tests/test_sso.py`: state/nonce/PKCE, wrong key, `alg` confusion,
expired / wrong-audience / wrong-issuer tokens, account takeover refusal, demotion revokes sessions).
Specific decisions worth re-reviewing:
* **Credential exfiltration via collection targets** - closed by design: only ADMIN can edit targets or credentials, the host key
  is pinned and checked before authentication, and metadata / loopback / link-local addresses are refused (`tests/test_collector.py`,
  including a real in-process SSH server for the pin-before-auth ordering).
* **Cross-tenant system paths under RLS** - login lookup, worker queue, scheduler, retention and metrics were running in the
  caller's default tenant and would have silently seen nothing; they now declare the system scope explicitly. The full suite
  passes as a non-bypass role with RLS on (`TEST_RLS=1`).
* **XML** - catalogue import uses `defusedxml` and rejects any DOCTYPE/ENTITY.
* Found and fixed while doing this: a stray control character in a regex in `Reports.tsx` (label formatting), an unauthenticated
  route sweep that needed to know the public SSO endpoints, and tests that assumed the default tenant.
Residual: SSO and KMS are untested against real providers; live collection is untested on real devices (see `REMAINING_WORK.md`).
