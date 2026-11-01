# Product Readiness Gap Register

**Project:** Multi-Vendor Security - AI-Driven Network Security Compliance Auditor (SIH 2026, PS 26155)
**Assessment date:** 2026-10-09
**Basis:** static review of the repository (backend, frontend, okf, models, docs, deployment files) plus one read-only parser check. The full test suite and the live app were **not** run (they need the Supabase DB), so test claims in the repo are unverified here.
**Purpose:** list everything that stands between today's prototype and a product customers will pay for and run in production, ordered by priority, with the fix and a testable "done" condition for each.

Legend: **[NEW]** = gap found during deeper review that was not in the first assessment summary. Effort: S ≤ 1 week, M 1-3 weeks, L 3-8 weeks, XL > 8 weeks (one engineer, rough).

---

## 0. Executive summary

| Area | Today | Needed for a paid product |
|---|---|---|
| Parsing accuracy on real configs | Deterministic rules: ~65 Cisco, 3 Fortinet, 3 Juniper, **0 Palo Alto, 0 Arista**. Other vendors rely on LLM/heuristic gap-fill. | Full per-vendor parsers validated on real configs |
| ML evidence | Trained and scored on **synthetic** ~10-line configs; 1.000 scores are not transferable | Metrics on real, labelled, multi-vendor configs |
| Compliance content | 82 controls, remediation for 3 vendors, 768 CVEs | Full CIS/STIG/NIST/ISO/CERT-In catalogues, all 5 vendors, live CVE feed |
| Security of the product itself | Auth off by default, no RBAC, plaintext configs, no tenancy, default admin password | Secure-by-default, RBAC, encryption, tenant isolation |
| Operations | Synchronous audits, YAML-on-disk learning store, no CI, no monitoring | Queue-based, stateless, observable, backed up |
| Product scope | File upload only; remediation is simulation | Live collection, scheduling, drift, integrations |

**Release gates (a customer can pay only when all are true):**
1. **Gate A (Trust):** all P0 items closed. Safe to put on a customer network or in their cloud.
2. **Gate B (Correctness):** all P1 items closed. Findings on a customer's real devices are right.
3. **Gate C (Value):** all P2 items closed. Saves the customer real time versus manual audit tools.
4. **Gate D (Sell):** P3 items closed. Procurement, support and packaging are in place.


## Progress log - updated 2026-11-01 (merged and pushed to the Orbit repository)

| Item | Status |
|---|---|
| P0-1 secure-by-default auth | ✅ done |
| P0-2 RBAC | ✅ done |
| P0-3 sessions / brute force | ✅ done (httpOnly cookie sessions + CSRF, TOTP MFA with recovery codes, lockout, revocation, OIDC SSO with group-to-role mapping; SSO untested against a real IdP, SAML not built) |
| P0-4 encryption + redaction | ✅ done (field encryption, redaction, scheduled retention, envelope encryption via Vault Transit / AWS KMS; not yet run against a live KMS) |
| P0-5 multi-tenancy | 🟡 app-layer isolation + optional Postgres RLS (whole suite passes as a non-bypass role); needs a non-bypass DB role in the real database; org admin UI left |
| P0-6 audit-id collisions | ✅ done |
| P0-7 external LLM | ✅ done |
| P0-8 pickle integrity | ✅ done (format migration left) |
| P0-9 regex safety | ✅ done |
| P0-10 learned mappings in DB | ✅ done |
| P1-1 / P1-3 / P1-4 parsers, fail-open, coverage | ✅/🟡 done (see items) |
| P1-9 remediation | 🟡 documented templates + evidence-based lab-verification workflow (before / after / rollback re-audited by the product); no template is lab-verified until a lab run is recorded |
| P2-2 history / drift / schedules | 🟡 done (history, drift, trends, recurring audits); alerts + live fetch open |
| P2-4 integrations | ✅ done: signed webhooks, Slack, Teams, CEF, Jira, ServiceNow (raw syslog only on demand) |
| P2-6 job queue / scale | 🟡 done (queue, workers, bulk audit, UI, recurring schedules, webhook push); horizontal scale-out untested |
| P1-7 CVE feed | ✅ done (vendor-aware version compare, NVD incremental sync, CISA KEV, auto-sync job) |
| P1-8 analytics | ✅ done (YAML rule DSL, observed vs assumed basis) |
| P1-2 real-config accuracy | 🟡 tooling done (anonymiser that preserves verdicts, `corpus-eval` with false-compliant metric and pilot-bar exit code, pilot kit); needs real configs |
| P1-5 / P1-6 licensed control catalogues | 🟡 importer done (STIG XCCDF / CSV / JSON, mandatory licence + source, unmapped = UNKNOWN never PASS, coverage report); needs the customer's licensed copy + reviewed mappings |
| P2-5 reporting | ✅ done (risk acceptance with four-eyes, report packs, CSV/JSON export, integrity hash, sign-off) |
| P2-1 live collection | 🟡 read-only SSH collector done (allow-list, pinned host key before auth, encrypted vault, ADMIN-only targets, UI); tested on an in-process SSH server, not real devices |
| P2-3 gated remediation | ⬜ open (deliberately read-only until a change workflow and lab exist) |
| P3 ops/quality | 🟡 metrics, JSON logs, alerts, SBOM, retention, accessibility, UI redesign, pagination, e2e suite done; CI never executed |

**Before this build can run against your Supabase database you must run `python -m app.cli migrate`**
(applies migrations 005-016: `org_id`, auth/MFA columns, `audit_log`, `revoked_tokens`, risk exceptions, retention, pagination indexes, report packs, SSO link, live collection, fix verifications). `/readyz` reports 503 until you do.
Also set `DATA_ENCRYPTION_KEYS` and run `python -m app.cli encrypt-existing`. See [`SECURITY.md`](SECURITY.md).

Behaviour changes to be aware of: `REQUIRE_AUTH` now defaults to **true**; the external LLM is **off** unless
`ALLOW_EXTERNAL_LLM=true`; tokens last 60 minutes; `/readyz` returns 503 when unhealthy.

### Additional defects found while implementing (not in the original list)

| ID | Finding | Status |
|---|---|---|
| N-1 | **Learned mappings never applied.** They were saved with an upper-case vendor (`CISCO`) but matched against lower-case, so "learn once, audit automatically thereafter" silently did nothing. | ✅ fixed (case-insensitive match, vendor stored lower-case) |
| N-2 | **"100% coverage" was not reproducible.** On an empty database coverage is 88%; the claim depended on rows already in the production DB. Some routes (e.g. `GET /audits`) had no test at all. | 🟡 gate set to an honest 85% floor; raise it by adding route tests |
| N-3 | Two tests were stale and passed only against production data (`test_training_edges`, `test_db_helper_commit`). | ✅ fixed |
| N-4 | Dashboard aggregates only the latest 100 audits / 500 assets (`app/api/v1/misc.py`), so fleet-wide numbers are wrong at scale. | ⬜ open |
| N-5 | The UI loads Inter from Google Fonts: a privacy leak and a blocker for air-gapped installs. | ✅ fixed (self-hosted Inter WOFF2 in `frontend/public/fonts/`, no third-party font requests) |
| N-6 | Playwright E2E tests assume the old default login (`admin123`, no forced password change); they will need updating for the new first-login flow. | ✅ fixed - `QA_ADMIN_PASSWORD`/`QA_ADMIN_EMAIL` env with a strong default + `global-setup.ts`; first-run and MFA flows covered |
| N-7 | `/health` and `/` stay public by design; `/` discloses the service name/version. Acceptable, but remove the group list for hardened installs. | ⬜ open (minor) |
| N-8 | **Every control applied to every vendor.** All 82 controls had an empty `applies_to`, so IOS-only controls (e.g. `service password-encryption`, `no service pad`) were scored against Junos/FortiOS/PAN-OS devices. | ✅ fixed - per-platform not-applicable declarations by each parser |
| N-9 | **Vendor detection was coarse and model-dependent**: every Cisco config was labelled "IOS-XE" (NX-OS never detected) and real FortiOS/PAN-OS/Junos versions were not extracted. | ✅ fixed - deterministic structural fingerprint overrides the statistical model; platform + version extracted |
| N-10 | **Unknown-token queue was flooded**: any line not matched by a regex (hostnames, interfaces, `ip route`...) counted as unknown. | ✅ fixed - parsers report every line they understood (<=2% unexplained on the corpus) |
| N-11 | The audit summary exposed no notion of coverage, so "97% compliant" could hide 60% not assessed. | ✅ fixed - `assessment` block + PDF/UI disclosure |
| N-12 | **Remediation could show another vendor's commands.** With no pack for a vendor the plan fell back to the first pack of ANY vendor (a Palo Alto device could be told to `transport input ssh`). | ✅ fixed - exact vendor only |
| N-13 | The legacy FortiOS fix (`set allowaccess ssh https ping` with no `edit "<interface>"`) was unsafe: applied as written it overwrites or mis-targets interface access and can lock an admin out. | ✅ superseded by per-interface plans that keep other access and include rollback |
| N-14 | Fix plans for NX-OS would have used IOS syntax. | ✅ none generated for NX-OS until real templates exist |
| N-15 | While adding fix targets, a test caught that SNMP community strings (credentials) were being copied into stored audit data. | ✅ fixed - only a config-line reference is stored |

---

## P0 - Blockers (must fix before any customer deployment)

### P0-1. Authentication is off by default and the default admin is weak
- **Status (2026-10-09):** ✅ DONE - auth required by default; app refuses to start in production with default/weak admin password, wildcard CORS/hosts, short JWT secret or `REQUIRE_AUTH=false`; `/docs`, `/redoc`, `/openapi.json`, `/ui` off in production; bootstrap admin created once (weak default => forced password change). Not done: breached-password lookup.
- **Evidence:** `backend/app/core/config.py` (`REQUIRE_AUTH` defaults to `false`, `ADMIN_PASSWORD` defaults to `admin123`); `backend/app/core/security.py` `require_user` returns the seeded admin when auth is off; `.env.example` ships `REQUIRE_AUTH=false`. Also unauthenticated regardless of the flag: `/docs`, `/redoc`, `/openapi.json` (enabled unconditionally in `main.py`) and the legacy `/ui` + `/static` page served from `backend/frontend/`. `TRUSTED_HOSTS` and `CORS_ORIGINS` also default to `*`. Note `docker-compose.yml` does set `REQUIRE_AUTH=true`, which helps only if that file is the deployment path.
- **Risk:** one missed env var exposes every API as admin. Default credentials are published in the repo.
- **Fix:** secure by default (auth required unless an explicit `ALLOW_INSECURE_DEV=true` in a dev-only build); disable `/docs`, `/redoc` and the legacy `/ui` in production or put them behind auth; refuse wildcard hosts/origins in production; refuse to start in production with a default/weak admin password; force password change on first login; password policy (length, breached-password check); remove the admin auto-seed from the request path and use a one-time bootstrap command.
- **Done when:** a fresh deploy with no env tuning rejects unauthenticated requests; startup fails on default credentials; test proves it.
- **Effort:** S

### P0-2. No real RBAC (roles are stored but never enforced)
- **Status (2026-10-09):** ✅ DONE - VIEWER < AUDITOR < APPROVER < ADMIN, one matrix (`app/core/rbac.py`) applied to every `/api/v1` route; verified by a sweep test over the whole OpenAPI surface; approver identity is taken from the token, not the request body. Not done: service-account API keys.
- **Evidence:** `role` is written in `security.py`/`persist.py`, but no route checks it. Docs admit only `ADMIN` exists (`BUILD_STATUS.md` roadmap #3).
- **Risk:** anyone logged in can approve learned mappings (changes what every future audit says), approve remediation, delete data, trigger CVE sync.
- **Fix:** roles Admin / Auditor (run + view) / Approver (training, remediation) / Read-only / Service account (API keys); permission decorators per route; actor stamped on every write; user management API + UI.
- **Done when:** permission matrix test covers every route; a Read-only token gets 403 on every write.
- **Effort:** M

### P0-3. Session/token handling is weak
- **Status (2026-10-09):** 🟡 PARTIAL - done: PBKDF2-600k with transparent upgrade, per-account lockout, per-IP throttle, uniform login errors, 60-min tokens with `jti`, server-side revocation on logout/password change/role change/disable, change-password API+UI, security headers. Remaining: httpOnly-cookie sessions (needs CSRF design + frontend change), refresh tokens, MFA, SSO.
- **Evidence:** `frontend/src/api/client.ts` stores the JWT in `localStorage`; 12-hour token, no refresh, no revocation, no logout invalidation; no login rate limiting or lockout (`api/v1/auth.py`); `jwt` signed with a single shared HS256 secret.
- **Risk:** any XSS steals a 12-hour admin token; brute force on login is unthrottled.
- **Fix:** httpOnly + Secure + SameSite cookies (or short-lived access + rotating refresh token); server-side revocation list; per-IP and per-account rate limiting and lockout; MFA (TOTP) and SSO (OIDC/SAML) for enterprise; strict CSP and security headers.
- **Done when:** token not readable from JS; brute force test is throttled; logout invalidates server-side.
- **Effort:** M (SSO adds L)

### P0-4. Raw device configurations stored in plaintext, no redaction
- **Status (2026-10-09):** 🟡 PARTIAL - done: Fernet field encryption of configs and raw unknown lines before they reach the DB (key rotation + `app.cli encrypt-existing/reencrypt`), secret redaction in stored evidence, in the viewer for VIEWER role, and before any LLM call. Remaining: retention/auto-delete job, KMS-managed keys, encrypting derived blobs (`flat_ir`).
- **Evidence:** `configurations.config_text TEXT NOT NULL` in `schema.sql`; `_register` in `api/v1/configurations.py` stores the full text, and `GET /configurations/{id}` returns it to the UI. Derived data (`canonical_ir`, `flat_ir`, finding evidence lines) can also carry sensitive values copied from the config.
- **Risk:** configs contain SNMP communities, pre-shared keys, password hashes, topology. A DB leak is a network compromise. NTRO/government and BFSI customers will fail this in security review.
- **Fix:** redact secrets at ingestion (keep a hash for evidence), field-level encryption for any retained raw text (KMS-managed keys), configurable retention/auto-delete, encrypted backups, access audit log.
- **Done when:** a DB dump contains no recoverable credentials; retention job tested.
- **Effort:** M

### P0-5. No multi-tenancy / data isolation
- **Status (2026-10-09):** 🟡 PARTIAL - done: `org_id` on every table, enforced centrally in `persist.py` (reads, writes, counts, deletes), cross-org upsert refused, org carried in the JWT, per-tenant learned mappings, tests for isolation. Remaining: Postgres RLS as defence in depth, org-management API/UI (CLI only today).
- **Evidence:** no `tenant_id`/`org_id` in any table or query (confirmed by search); `persist.find()` returns global rows.
- **Risk:** cannot be sold as SaaS or to an MSSP; two customers' data would mix.
- **Fix:** add `org_id` to every table, enforce in the persistence layer (and Postgres row-level security), scope JWTs to an org, per-tenant learned mappings with an opt-in shared global pack.
- **Done when:** cross-tenant read/write tests fail closed; RLS enabled.
- **Effort:** L

### P0-6. Audit ID collisions overwrite data **[NEW]**
- **Status (2026-10-09):** ✅ DONE - audit id = hash(org, asset, config): same config on different assets/orgs no longer collides; re-run on the same asset stays idempotent. Remaining (P2-2): keeping run history instead of upserting.
- **Evidence:** `services/audit_service.py`: `audit_id = "AUD-" + sha256(config_text)[:8]`. Finding IDs derive from it.
- **Risk:** two assets (or two tenants) with the same config text share one audit; the second run silently overwrites the first run's asset, frameworks, and findings. 8 hex chars also risks accidental collisions at scale.
- **Fix:** generate a unique audit ID per run (UUID/ULID); keep config hash as a separate indexed field; keep history (audits become versioned runs per asset).
- **Done when:** identical configs on two assets produce two independent audits; history is retained.
- **Effort:** S-M

### P0-7. Customer configs can leave the customer network via the LLM **[NEW]**
- **Status (2026-10-09):** ✅ DONE - external LLM is off by default; needs `ALLOW_EXTERNAL_LLM=true` AND a key; a local OpenAI-compatible endpoint (Ollama/vLLM) works with no opt-in; secrets are redacted before every call; calls are logged. Remaining: per-tenant policy switch and payload audit trail.
- **Evidence:** `okf/llm_gateway.py` posts unknown config lines to `https://api.featherless.ai/v1` when `FEATHERLESS_API_KEY` is set; `.env.example` documents this; no consent, redaction, or data-processing control.
- **Risk:** disqualifying for government, defence, telecom, BFSI. Also a privacy/regulatory exposure (DPDP Act / GDPR).
- **Fix:** default to no external calls; support a local/self-hosted model (Ollama/vLLM with an open-weights model); redact before any external call; per-tenant policy switch and an explicit audit trail of what was sent; allow-list of egress hosts.
- **Done when:** an air-gapped install runs the full flow; external LLM is opt-in per tenant with logged payloads.
- **Effort:** M-L

### P0-8. Unsafe deserialisation of ML artifacts **[NEW]**
- **Status (2026-10-09):** ✅ DONE (load paths) - every `joblib.load` goes through `artifact_guard.load_verified` (SHA-256 manifest, optional HMAC, `strict` in production); tamper tests. Remaining: move to a non-executable format (ONNX/skops). NOTE: the shipped manifest was generated from the artifacts currently in the repo - they were trusted, not independently verified.
- **Evidence:** `joblib.load` on `.pkl` files in `app/services/integration.py` and `models/src/*`; the pickles are committed to git (`models/artifacts/*.pkl`).
- **Risk:** pickle executes code on load. Anyone able to alter the artifact (supply chain, compromised build, writable volume) gets code execution on the server.
- **Fix:** sign artifacts and verify hashes before load, ship them from a controlled registry (not mutable at runtime), prefer safe formats (ONNX / skops / JSON), read-only mount in the container.
- **Done when:** the app refuses an artifact with a bad signature; artifacts mounted read-only.
- **Effort:** M

### P0-9. Approved mappings are built from raw uploaded text as regex without escaping **[NEW]**
- **Status (2026-10-09):** ✅ DONE - learned patterns are `re.escape`d, anchored, length-limited and must match their originating line; canonical property must exist in the registry; scalar values only; duplicates rejected (409).
- **Evidence:** `api/v1/training.py` `approve()`: `pattern = raw_command.strip().replace(" ", r"\s+")` - regex metacharacters in the config line (`( ) [ ] * + ? | .`) are not escaped.
- **Risk:** (a) the learned rule may not match what it was meant to (silent wrong parsing); (b) a crafted line can create a catastrophic-backtracking pattern that hangs every future audit (ReDoS); (c) a malformed pattern can break registry load for all users.
- **Fix:** `re.escape` tokens (and parameterise IPs/numbers deliberately), validate and compile-test with a timeout/length limit before saving, use a safe regex engine (e.g. `re2`), reject patterns that fail a self-match test on the originating line.
- **Done when:** fuzz test with hostile lines cannot slow or break the registry.
- **Effort:** S

### P0-10. Learned knowledge is stored in files on disk, not in the DB **[NEW]**
- **Status (2026-10-09):** ✅ DONE - approved mappings live in the DB per tenant and are merged with the shipped registry at parse time (all workers converge within seconds, survive redeploys, no files written). Also fixed the case-sensitivity bug (see N-1).
- **Evidence:** approvals write to `okf/knowledge/mappings/learned/*.yaml` (the repo's own `git status` shows `cisco_learned.yaml` modified); the Dockerfile bakes `okf/` into the image; compose has no volume. `approve()` also saves a row in the DB `mappings` table, but `MappingRegistry.load()` (`okf/src/knowledge_extras.py`) reads only the YAML files, so the DB copy is a record, not the source the parser uses.
- **Risk:** learned data is lost on redeploy, not shared across the 2 uvicorn workers or multiple containers, not tenant-scoped, and not atomic (concurrent approvals can corrupt the YAML). It also dirties the git working tree.
- **Fix:** make the DB the source of truth (the `mapping_registry` table already exists in `persist.py`) and have the registry load from it; load into memory with versioned cache invalidation; export/import YAML for review; per-tenant scoping; optimistic locking.
- **Done when:** two containers see the same approved mapping within seconds; redeploy keeps it.
- **Effort:** M

---

## P1 - Correctness and credibility (findings must be right on real devices)

### P1-1. Deterministic parsing is thin outside Cisco
- **Status (2026-10-09):** 🟡 SUBSTANTIALLY DONE (authored-corpus level) - structured, context-aware parsers for Cisco IOS/IOS-XE/NX-OS, Arista EOS, Junos (hierarchical + set), FortiOS and PAN-OS (set/hierarchical/XML) replace the 65/3/3/0/0 regex rules; controls assessed on the corpus went from 0-31 to 59-79 of ~75. Measured capability matrix in [`PARSERS.md`](PARSERS.md). Remaining: real-device validation (P1-2), Panorama/VDOM/VRF/`apply-groups` modelling, cert/key inventory, more NX-OS/EOS settings.
- **Evidence:** mapping rule counts: cisco 65, fortinet 3, juniper 3, generic 2, learned 14; **none** for Palo Alto or Arista, although README/docs claim five deterministic vendors. Read-only check on bundled `test-files/`: Cisco insecure router yielded 12 properties; Juniper 2, Fortinet 1, Palo Alto 1, Arista 2.
- **Risk:** on non-Cisco configs most security settings are missed or guessed by the LLM/heuristic, and a "passed" control may just mean "not detected".
- **Fix:** build structured, hierarchy-aware parsers per vendor (IOS/IOS-XE/NX-OS, EOS, Junos set/hierarchical, FortiOS, PAN-OS XML/set), covering at minimum the properties every control needs; unit-test each property per vendor with positive and negative samples.
- **Done when:** a coverage matrix (property x vendor) shows >90% of controls evaluable on all five vendors; coverage is published in the product.
- **Effort:** XL

### P1-2. Accuracy is measured on synthetic data only
- **Evidence:** `models/datasets/raw_configs/*` are generated (`! cisco insecure synthetic`, ~10 lines); `MODELS_PERFORMANCE.md` reports F1 1.000, FPR 0.000, 1.000 vendor accuracy; `RTM_MODELS.md` notes a "synthetic-key leak" had to be repaired.
- **Risk:** the numbers cannot be quoted to customers; real configs (thousands of lines, banners, certificates, nested contexts) will behave differently. Overclaiming damages trust in diligence.
- **Fix:** assemble a real, anonymised, labelled corpus (lab devices, GNS3/EVE-NG/Containerlab images, vendor sample configs, design-partner configs under NDA); re-split by device/site; report precision/recall per vendor/OS version with confidence intervals; keep a frozen holdout; withdraw or relabel current claims until then.
- **Done when:** published eval on >=500 real configs with per-vendor results.
- **Effort:** L-XL (ongoing)

### P1-3. Silent failure modes (fail-open) hide wrong results **[NEW]**
- **Status (2026-10-09):** ✅ DONE for the audit path - the IR validator now fails CLOSED, vendor-model fallback and parser-extractor failures are recorded as a visible `degraded` list on the audit (results page banner + PDF paragraph), a failing extractor no longer discards other facts, stale-finding cleanup logs instead of passing silently. Remaining: the M2/M3 model fallbacks and DB-level swallows still log only.
- **Status (2026-10-09):** ⬜ OPEN (one related fix: `/readyz` now returns 503 when the DB is down or the schema is outdated).
- **Evidence:** 47 `except Exception` blocks in `backend/app`. Examples: `m5_validate` returns `{"valid": True}` on any error; `m1_predict` falls back to "unknown 0.31"; `m2_score_batch` returns `unknown 0.5` on error; `_register` swallows DB problems; stale-finding cleanup `pass`es silently; the training dedupe `except` hides DB errors.
- **Risk:** a broken validator or missing artifact looks like a clean "valid" result. For an audit product, "couldn't check" must never look like "passed".
- **Fix:** typed errors, fail-closed on validators, explicit `DEGRADED` state on an audit with the reason shown in UI/PDF, structured logging and alerting for each fallback.
- **Done when:** disabling an artifact marks audits degraded and visible; no bare swallow remains without a metric.
- **Effort:** M

### P1-4. "Not detected" vs "not configured" are conflated (false passes) **[NEW]**
- **Status (2026-10-09):** ✅ DONE - three outcomes are now distinct everywhere: *observed in config* (line evidence), *assumed platform default* (labelled, with a note and confidence 0.6) and *not determinable* (UNKNOWN, never PASS). Controls whose properties cannot exist on a platform are NOT_APPLICABLE and leave the score. Every audit, framework score, PDF and finding shows assessment coverage / assumed share.
- **Evidence:** compliance verdicts depend on the flat IR; properties absent from a config are evaluated against rules, and the parser only knows a small rule set (see P1-1). Several analytics rules only fire on explicit `True/False`.
- **Risk:** a control about a feature the parser does not understand can PASS or be N/A with no evidence either way.
- **Fix:** tri-state per property (`PRESENT`, `ABSENT`, `NOT_PARSEABLE`); controls return `UNKNOWN/NOT_ASSESSED` when inputs are not parseable; show assessment coverage % per audit and block "100% compliant" claims below a coverage threshold.
- **Done when:** every report states coverage; unparsed-input controls never show PASS.
- **Effort:** M

### P1-5. Compliance content is too small to claim framework coverage
- **Evidence:** 82 controls across `core`, `extended`, `hardening`, `certin`, `nist_oscal_subset` (counts from the YAML); frameworks JSON files include `*_SCRAPED.json`; only a subset of CIS/STIG/NIST/ISO is represented.
- **Risk:** a customer who runs a CIS benchmark audit expects every applicable CIS item (typically 80-200 per platform). A partial list is misleading unless clearly scoped.
- **Fix:** implement full per-platform benchmark packs (CIS Cisco IOS/IOS-XE/NX-OS, Juniper, Fortinet, Palo Alto, Arista; DISA STIG per platform; NIST 800-53 network-device mappings; ISO 27001 Annex A mapping; CERT-In 2022 directions) with version, source and licensing recorded; show "controls assessed X of Y" per framework; legal review of CIS/STIG redistribution terms.
- **Done when:** per-framework coverage table in-product with authoritative control counts.
- **Effort:** XL

### P1-6. Scraped framework data has unclear provenance and licensing **[NEW]**
- **Evidence:** `okf/knowledge/frameworks/CIS_SCRAPED.json`, `ISO_SCRAPED.json`, `STIG_SCRAPED.json`, plus `okf/scrapers/`.
- **Risk:** ISO and CIS text is copyrighted; shipping scraped content in a commercial product is a legal exposure.
- **Fix:** replace with licensed content or reference-by-ID only (control IDs and your own wording); record source and licence per control; legal sign-off.
- **Done when:** a licence manifest exists and legal has approved it.
- **Effort:** S-M (plus legal)

### P1-7. CVE coverage is a 768-record snapshot
- **Status (2026-10-09):** 🟡 PARTIAL - **matching correctness fixed**, sync hardened, KEV added. A probe of 17 realistic version cases had 6 wrong results (PAN-OS `10.2.3-h4`, Cisco `17.9.4a`, EOS `4.28.4M`, NX-OS `10.3(4a)`, Junos `20.4R3` vs `-S1`, Junos CPE `20.4:r3-s2`); the comparator now understands post-release markers (`a/b` rebuilds, `-hN` hotfixes, `-Sn` service releases, `(n)` NX-OS, train letters), trailing-zero equality, and treats `fixed` as the exclusive bound. NVD ingest keeps the CPE `update` field and `fixed`; KB writes are atomic and upserts O(1); sync supports an incremental `lastModified` window (`since_days`); CISA KEV flags records (`exploited`) and lifts severity one level; workers can auto-refresh (`CVE_AUTO_SYNC_HOURS`, default off). Tests: `okf/tests/test_cve_versions.py`, `test_cve_sync.py`. **Remaining: the shipped KB is still the 768-record snapshot with zero PAN-OS and 13 Arista records - run a real sync (`POST /vulnerabilities/sync` with products, then enable auto-sync) before go-live; EPSS and vendor PSIRT feeds; DB-backed KB; freshness SLA in the UI; golden set >1,000 advisory-derived cases.**
- **Evidence:** `okf/knowledge/vulnerability/cves.json` (768 records, 12 MB, version tag `local-768`); NVD sync exists but is manual-trigger (`POST` in `engines_api.py`) and unscheduled.
- **Risk:** missing a critical CVE on a customer device is the worst possible failure for this module. CPE/version matching for network OSes (IOS train naming, FortiOS, PAN-OS, Junos builds) is error-prone.
- **Fix:** scheduled incremental NVD 2.0 + CISA KEV + EPSS + vendor PSIRT advisory ingest (Cisco, Juniper, Fortinet, Palo Alto, Arista); store in DB with indexes; per-vendor version-normaliser tests from real advisories; mark KEV/exploited CVEs; freshness indicator in UI; expand the 208-case golden set with advisory-derived cases.
- **Done when:** nightly sync, freshness SLA monitored, golden set >1,000 cases passing.
- **Effort:** L

### P1-8. Security analytics is a short list of hard-coded `if` rules
- **Status (2026-10-10):** 🟡 SUBSTANTIALLY DONE - rules moved to a YAML DSL (`backend/app/engines/rules/security_rules.yaml`: 12 signals, 5 attack-path combinations, all/any/not conditions, validated on load). Every result carries `rule_id`, why, fix and `basis` (observed vs assumed default; assumed-only hits drop one severity so a guessed default never yields CRITICAL alone). Signals that duplicate a failed compliance control are flagged and no longer create a second finding; attack paths are now real findings with their contributing evidence. Tests: `tests/test_security_rules.py`. **Remaining: fleet outlier / baseline-deviation rules (needs cross-asset data), UI display of `why`/`basis`.**
- **Evidence:** `app/engines/security.py` (62 lines) checks a dozen booleans plus one combination pattern; README markets "pattern recognition / combination patterns".
- **Risk:** adds little beyond compliance; customers will see duplicate findings.
- **Fix:** move to a rule DSL (YAML) with attack-path/combination logic (exposed mgmt + weak auth + no logging), config-drift and baseline-deviation logic, fleet outlier checks tied to real data; de-duplicate against compliance findings.
- **Done when:** analytics produces distinct, explained, evidence-linked findings; duplicates suppressed.
- **Effort:** M

### P1-9. Remediation content is limited and unvalidated
- **Status (2026-10-09):** 🟡 SUBSTANTIALLY DONE (documentation level) - a fix library of per-vendor templates (Cisco 66, Junos 51, EOS 40, FortiOS 39, PAN-OS 32) plus a context-aware composer: unmet-part detection, least-disruptive ALT choice, real targets (interface, vty range, BGP neighbour + ASN, policy, account), impact / prerequisites / rollback / placeholders, honest `documented` vs `lab-verified` label. Controls with a fix: Cisco 82/82, Junos 67, FortiOS 60, EOS 59, PAN-OS 49. See [`REMEDIATION.md`](REMEDIATION.md). **Remaining: lab verification of every template (the real gap), NX-OS templates, release-specific variants.**
- **Evidence:** `okf/knowledge/remediation/` has only `cisco`, `fortinet`, `juniper` packs (one `base.yaml` each); Palo Alto and Arista fall to generic text ("Set X to Y").
- **Risk:** wrong or generic fix commands can cause outages or give false comfort. Customers will not trust unverified fix steps.
- **Fix:** per-vendor, per-OS-version command packs with prerequisites, impact notes, rollback commands and verification commands; test packs in lab images; mark each pack as "lab-verified on version X".
- **Done when:** every failed control on every supported vendor has a vendor-specific, lab-verified fix and rollback.
- **Effort:** L-XL

---

## P2 - Product value (what makes customers pay and keep paying)

### P2-1. No live collection from devices
- **Evidence:** ingestion is file upload only (`BUILD_STATUS.md` roadmap #1).
- **Fix:** collector service (Netmiko/NAPALM/NETCONF/RESTCONF/vendor APIs; cloud APIs for AWS/Azure/GCP security groups); credential vault integration (HashiCorp Vault, CyberArk); on-prem agent/collector for customers who cannot expose devices; inventory import (CSV, CMDB, NetBox).
- **Done when:** add a device inventory, schedule pull, get audits with no manual upload.
- **Effort:** XL

### P2-2. No scheduling, history, drift or trending
- **Status (2026-10-09):** 🟡 SUBSTANTIALLY DONE - append-only run history, new/resolved/worse comparison with config-vs-knowledge attribution, finding age, masked config diff, 90-day trend (dashboard + asset page), notable-change feed, recurring audits via the job queue (multi-worker safe). See [`HISTORY.md`](HISTORY.md). Remaining: notifications/webhooks (P2-4), SLA targets per severity, live collection so a schedule fetches a fresh config (P2-1).
- **Evidence:** audits are one-off runs; no baseline/compare features beyond a remediation re-audit diff.
- **Fix:** scheduled audits, run history per asset, config diff between runs, drift alerts, compliance trend charts, "new findings since last week" digest, SLA/aging of findings.
- **Effort:** L

### P2-3. Remediation is simulation only, with no change workflow
- **Evidence:** `api/v1/remediation.py` always returns `device_touched: False`.
- **Fix:** keep dry-run as default; add optional gated execution (RBAC, two-person approval, maintenance windows, pre-change backup, automatic rollback, post-change re-audit); push ready-to-run change files (Ansible/Netmiko) and tickets instead of executing where customers do not allow it.
- **Effort:** L-XL

### P2-4. No integrations
- **Status (2026-10-09):** 🟡 PARTIAL - signed webhooks (JSON / Slack / Teams) for `audit.completed`, `finding.new_critical_high`, `job.failed`: HMAC + timestamp replay protection, SSRF guard (re-checked per delivery), encrypted secrets shown once, queue-based retry/backoff, delivery log, auto-disable, tenant isolation, admin-only API + UI. See [`INTEGRATIONS.md`](INTEGRATIONS.md). Remaining: Jira/ServiceNow ticketing, CEF/syslog export, routing rules, API keys for service accounts, CycloneDX/CBOM export.
- **Fix:** Jira/ServiceNow ticketing, Splunk/Sentinel/QRadar export (CEF/syslog/webhooks), Slack/Teams/email notifications, SSO, SIEM-ready JSON, public API keys and webhooks, OpenAPI client SDKs, SBOM/CBOM export (CycloneDX).
- **Effort:** L

### P2-5. Reporting is a single per-device PDF
- **Status (2026-10-10):** 🟡 PARTIAL - **risk acceptance with sign-off**: request (AUDITOR) -> approve/reject by a *different* APPROVER (four-eyes enforced server-side) -> mandatory expiry (`EXCEPTION_MAX_DAYS`, default 180) -> revoke; every step is in the audit log; accepted findings stay visible (never hidden, scores unchanged). **Exports**: findings as CSV (formula-injection safe, Excel-friendly BOM) or JSON with the acceptance beside each finding (`GET /reports/export/{audit_id}`). **Integrity**: SHA-256 of every PDF/export in the API and the `X-Content-SHA256` header. UI: Risk acceptance page + Export buttons. Migration `009`. Tests: `tests/test_exceptions.py`. **Remaining: executive/fleet summary report, per-framework evidence pack, XLSX, white-label branding, scheduled delivery, cryptographic (PKI) signature, exceptions shown inside the PDF, expiry reminders.**
- **Evidence:** `api/v1/reports.py` generates ReportLab PDFs (1,101 lines).
- **Fix:** executive/fleet summary, per-framework audit evidence pack (control, evidence, sign-off), CSV/XLSX/JSON export, white-label/branding, scheduled delivery, digital signature/hash of reports, auditor sign-off workflow with comments and exceptions (risk acceptance with expiry).
- **Effort:** M-L

### P2-6. Asynchronous processing and scale
- **Status (2026-10-09):** 🟡 SUBSTANTIALLY DONE - Postgres job queue (no Redis): audits, reports and fleet batches run in workers (`python -m app.worker`, compose `worker` service) with exactly-once claiming (`SKIP LOCKED`), retry with backoff, crash recovery, cancel/retry, per-org isolation and caps, batch progress API + Background-jobs UI page, bulk onboarding of 500 devices per request. See [`JOBS.md`](JOBS.md). Remaining: streaming upload with proxy-level size limits, scheduled/recurring audits (P2-2), websocket/SSE push, CVE sync + fleet analytics as queue kinds.
- **Evidence:** audits and PDF generation run inline in the request; `docs/tech_stack.md` lists Redis/Celery that were never built; `bulk-upload` is limited to 20 files and uploads read fully into memory (size is checked after `await file.read()`).
- **Fix:** job queue (Celery/RQ/Arq + Redis), progress API and websocket/SSE, streaming upload with size limits at the proxy, batch audits of thousands of devices, worker autoscaling, idempotency keys.
- **Done when:** 5,000-device batch completes with progress and without request timeouts.
- **Effort:** L

### P2-7. Persistence and query layer will not scale **[NEW]**
- **Status (2026-10-09):** 🟡 PARTIAL - done: filter columns, ORDER BY and projections are validated against an allow-list (no string-built SQL from callers), `select` supports offset. Remaining: pagination on every list endpoint, normalised models + Alembic.
- **Evidence:** `core/persist.py` stores whole records as JSONB `data`, rewrites full rows on every update, `find()` returns entire tables with no pagination; `select(...)` interpolates column lists/ORDER BY via f-strings (safe only while callers pass constants - a fragile contract); `GET /training/queue` and others are unpaginated; `audits` embeds large `canonical_ir`/`cve`/`pqc` blobs.
- **Fix:** proper normalised models (SQLAlchemy/SQLModel) with Alembic migrations, pagination and filtering on every list endpoint, indexed search, parameterised/validated ordering, archive policy for old audits, pgvector used for what it is meant for.
- **Effort:** L

### P2-8. Model/AI quality gaps
- **Evidence:** M6 risk Spearman 0.52 and "train acc 0.877" (no held-out figure); M10-M13 quantum modules score 0.46-0.58 and are research-only; M2 coverage 0.329.
- **Fix:** either remove research models from the customer-facing story or isolate them behind an "experimental" flag; add human-feedback loop metrics (acceptance rate of suggestions) as the real KPI; calibrate confidence; model cards and drift monitoring; drop the XGBoost risk model from decisions until validated, keep the transparent rule-based score.
- **Effort:** M

### P2-9. PQC engine depth
- **Evidence:** `app/engines/pqc.py` (476 lines) builds a CBOM from parsed crypto properties; 40 PQC rules.
- **Fix:** align with NIST FIPS 203/204/205 and CNSA 2.0 timelines, include certificate/key inventory (from device certs, TLS endpoints, IPsec/IKE proposals), vendor PQC support matrix per OS version, migration planner with priority and effort.
- **Effort:** M-L

---

## P3 - Operations, engineering quality, go-to-market

### P3-1. No CI/CD, supply-chain or release process
- **Status (2026-10-09):** 🟡 PARTIAL - backend Dockerfile now installs exactly the locked set and fails otherwise (no silent pip fallback). CI is now defined (`.github/workflows/ci.yml`: tests on real Postgres+pgvector with the coverage gate, frontend lint+build, pip-audit / npm audit / gitleaks, image build + Trivy scan) plus Dependabot - **written but not yet executed on GitHub** (first run will likely need small fixes, e.g. torch wheel index in the image build). Remaining: SBOM, signed images, release/versioning process.
- **Evidence:** no `.github/` workflows; no lint/type/security scan gates; `backend/Dockerfile` swallows install failures (`uv sync ... 2>/dev/null || pip install -e .`) so the build can succeed with a different dependency set than the lock file.
- **Fix:** GitHub Actions (tests, coverage, ruff/mypy, frontend lint/build, Playwright), dependency and container scanning (pip-audit, Trivy), SBOM, signed images, semantic versioning and changelog, reproducible build that fails on lock mismatch.
- **Effort:** M

### P3-2. Deployment is a single compose file with no data tier
- **Status (2026-10-09):** 🟡 PARTIAL - done: nginx `client_max_body_size`, security headers/CSP/HSTS, `server_tokens off`, relative API base URL, backend port no longer published, `cap_drop`/`no-new-privileges`, `--proxy-headers`. Remaining: TLS termination (needs your cert/ingress), Helm/K8s, self-hosted Postgres option, read-only root FS (untested).
- **Evidence:** `docker-compose.yml` has backend + frontend only; DB is external Supabase; no Redis, no volumes, `ports: 8000` published directly, no TLS; `frontend/nginx.conf` listens on port 80 only, with no HSTS/CSP/security headers; backend `--workers 2` with a model loaded per worker (memory).
- **Upload size mismatch [NEW]:** `frontend/nginx.conf` sets no `client_max_body_size`, so nginx's 1 MB default applies. The backend accepts up to 5 MB per config (`MAX_BYTES` in `parsers/ingestion.py`), so larger configs through the nginx proxy would fail with HTTP 413 before reaching the app. Not tested here; verify with a 2-3 MB config.
- **API URL mismatch [NEW]:** nginx proxies `/api/` to the backend, but the frontend is built with an absolute `VITE_API_BASE_URL=https://api.yourdomain.com/api/v1` (Dockerfile, `.env.production`, compose default), so a default `docker compose up` build points the browser at a placeholder domain instead of the proxy.
- **Fix:** production packaging: Helm chart / Kubernetes manifests and a hardened compose for on-prem; TLS termination, security headers, network policies; self-hosted Postgres option for air-gapped customers; resource limits; separate model-serving image; image size reduction (models and data are baked into the image).
- **Effort:** M-L

### P3-3. Observability and reliability
- **Status (2026-10-09):** 🟡 PARTIAL - `/readyz` fails with 503 on DB down/outdated schema. Remaining: metrics, tracing, alerting, backups/DR.
- **Evidence:** log lines only; no metrics, tracing, alerting, error reporting; `/readyz` always returns HTTP 200 even if the DB is down (reports `down` in the body).
- **Fix:** Prometheus metrics + Grafana dashboards, OpenTelemetry traces, Sentry, structured JSON logs, readiness that actually fails when dependencies are down, SLOs, backup/restore with tested RPO/RTO, DR runbook.
- **Effort:** M

### P3-4. Audit log and compliance of the product itself
- **Status (2026-10-09):** 🟡 PARTIAL - append-only `audit_log` (DB trigger blocks UPDATE/DELETE) recording logins, failures, every write and denied attempts, plus config/report reads; admin UI + API. Remaining: SIEM export, retention policy, SOC 2/pen-test work.
- **Fix:** immutable audit trail of who did what (logins, uploads, approvals, exports, config views), exportable to SIEM; data-retention and deletion workflows (DPDP/GDPR); SOC 2 / ISO 27001 readiness for the vendor; penetration test and remediation of findings; vulnerability disclosure policy.
- **Effort:** L

### P3-5. Frontend gaps
- **Status (2026-10-09):** 🟡 PARTIAL - role-aware buttons, Administration page (users, roles, audit log), forced password change, logout revokes the token, demo credentials removed from the login page. Remaining: accessibility, i18n, onboarding wizard, self-hosted fonts.
- **Evidence:** 30 page components exist; E2E tests cover a limited journey; no accessibility audit; tokens in localStorage (see P0-3); no i18n; large-table performance unverified.
- **Fix:** accessibility (WCAG 2.1 AA), error/empty/loading states review, virtualised tables, i18n (English + Hindi at least for India market), role-aware UI, onboarding wizard (add first device in minutes), in-app help.
- **Effort:** M

### P3-6. Test quality
- **Status (2026-10-09):** 🟡 PARTIAL - the suite now runs against a disposable local Postgres (never your Supabase DB), 2 stale tests fixed, +40 security/CLI tests. Honest coverage is 88%; the old 100% gate only held against a pre-populated production DB, so `fail_under` is now 88 (measured 89.6%) and must only ratchet up.
- **Evidence:** 100% *statement* coverage gate, but with `# pragma: no cover` on infrastructure paths (middleware, exception handlers, prod guard, static mount) and many tests using fakes; no load, security, fuzz, or real-vendor-config tests; the tests need the live DB.
- **Fix:** disposable Postgres for tests (testcontainers), property-based/fuzz tests for the parsers and regex registry, golden-config regression suite per vendor, load tests (k6/Locust), security tests (authz matrix, SSRF, upload abuse), mutation testing on engine logic. Coverage % is a floor, not proof.
- **Effort:** M-L

### P3-7. Repository hygiene **[NEW]**
- **Status (2026-10-09):** 🟡 PARTIAL - stray `backend/dy` removed. Remaining: untracked decks/docs in the root, dataset/artifact storage, duplicated docs.
- **Evidence:** `backend/dy` (a stray saved HTTP error response) is tracked; untracked `.pptx`, `.docx`, PDF and `session-ses_f1a1.md` sit in the repo root; `git ls-files` shows ~14,000 tracked files, most of them under `models/datasets` (generated) plus pickled artifacts; learned mapping YAML modified by runtime; docs duplicated in `docs/`, `backend/docs/`, `okf/docs`, and the UI exists twice (`frontend/` React app plus the legacy `backend/frontend/index.html`). Headline numbers are not tied to code: the README's "375 controls" is a training-dataset count while the shipped knowledge base has 82, which is easy to misread.
- **Fix:** remove stray files, move datasets/artifacts to Git LFS or an artifact registry, generate datasets in CI, single source of truth for docs, a `CHANGELOG`, and a numbers-from-code script so README counts cannot drift.
- **Effort:** S

### P3-8. Documentation and claims accuracy
- **Evidence:** README says five vendors are parsed deterministically and cites "10/10 features" against the problem statement, while the knowledge base contradicts the former (P1-1); model metrics are presented without the synthetic-data caveat (P1-2).
- **Fix:** an honest "support matrix" and "known limitations" page; customer-facing admin, user, API, and security whitepaper; threat model; data-flow diagram; architecture decision records.
- **Effort:** S-M

### P3-9. Packaging, pricing, support
- **Fix:** editions (Community / Professional / Enterprise / Government on-prem), licence keys and metering per device, installer and upgrade path, SLAs, support portal, customer success playbook, trial/PoC kit with sample configs, training material, partner/MSSP programme.
- **Effort:** M (business work in parallel)

---

## Suggested delivery plan

| Phase | Window | Scope | Exit criteria |
|---|---|---|---|
| 1. Make it safe | Weeks 1-6 | P0-1 to P0-10, P3-7, P3-1 (CI baseline) | Gate A: passes an internal security review; no external calls by default |
| 2. Make it right | Weeks 5-20 | P1-1 to P1-9 (start corpus collection immediately; it is the long pole) | Gate B: published per-vendor accuracy on real configs; coverage shown in every audit |
| 3. Make it valuable | Weeks 16-36 | P2-1 to P2-9, P3-2, P3-3 | Gate C: one design partner running scheduled live audits with ticketing |
| 4. Make it sellable | Weeks 30-44 | P3-4 to P3-6, P3-8, P3-9 | Gate D: security questionnaire answered, pen test passed, price list live |

Run the real-config corpus collection (P1-2) and design-partner recruitment from week 1; they gate everything else and take calendar time, not just engineering time.

---

## Definition of "real product" - acceptance checklist

A customer will pay when they can say yes to each of these:

- [ ] Installs in a customer environment (cloud or air-gapped) with secure defaults and no mandatory external calls.
- [ ] Their own real configs from all their vendors are parsed, and the report states how much of each config was understood.
- [ ] Findings are correct and traceable to the config line, the control, and the framework clause; false-positive/negative rates are published.
- [ ] Controls cover the full framework versions they are audited against (CIS/STIG/NIST/ISO 27001/CERT-In), with licensed content.
- [ ] CVE results are current (KEV/EPSS/vendor advisories) with a visible freshness date.
- [ ] Fix guidance is vendor- and version-specific, tested, with impact and rollback.
- [ ] Audits run on a schedule from live devices, show drift and trend, and scale to their fleet size.
- [ ] Teams, roles, approvals and SSO match their organisation; every action is auditable.
- [ ] Results flow into their ticketing, SIEM and reporting without manual copy/paste; auditors receive a signed evidence pack.
- [ ] Their security team can review the vendor: pen-test report, threat model, SBOM, retention controls, SLAs and support.

## Pricing alignment (indicative, to validate with design partners)

| Gate reached | What can honestly be sold |
|---|---|
| Today (prototype) | Government pilot / PoC or services-led engagement |
| After Gate A + B | Paid pilots and limited production for Cisco-heavy estates |
| After Gate C | Subscription: roughly $20-$60 per device per year (mid-market), $100k+ per year enterprise/telco |
| After Gate D | MSSP and government on-prem licences, multi-year contracts, partner channel |

Market and price figures are rough estimates from public analyst knowledge and comparable products; verify before using externally.