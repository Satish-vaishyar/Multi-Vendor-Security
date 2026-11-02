# RTM - Cloud Provider Security Assessment Module (requirement → implementation → verification)

Source requirements: `CLOUD_PROVIDER_SECURITY_ASSESSMENT_CATALOG.md` (referenced below as **CAT §n**).
Status of this document: **living plan + progress log** (see section 0). Effort figures are estimates for one engineer.

Legend: ⬜ planned · 🟡 in progress · ✅ implemented + tested · ⏸ deferred (needs customer demand / test account)

New locations introduced by the module (nothing existing is renamed or moved):
`cloud/` (scanner service) · `okf-cloud/` (knowledge pack) · `backend/app/api/v1/cloud.py` (thin API) ·
`backend/app/db/migrate_017.sql` · `frontend/src/pages/cloud/` · `docker-compose.cloud.yml` · `.github/workflows/cloud.yml`

---

## 0. Progress log (kept current)

Branching: all work is committed directly to `main` of the Orbit repository, one commit per step (security-review
fixes are separate `fix(cloud)` commits). There are no long-lived feature branches.

| Step | Status | Evidence |
|---|---|---|
| S01 foundation, flag, skeletons | ✅ | `cloud/flags.py`, `okf-cloud/` |
| S02 migration `migrate_017.sql` | ✅ (SQL verified on a scratch PostgreSQL 16; full backend suite not runnable on the dev laptop, see notes) | `backend/app/db/migrate_017.sql` |
| S03 sandboxed scanner + compose overlay | ✅ (profile locked by tests; container not started on the dev laptop, Docker daemon unavailable) | `cloud/Dockerfile`, `docker-compose.cloud.yml` |
| S04 API shell, job kind, CI workflow | ⬜ deferred: edits `backend/` and needs the backend suite (needs PostgreSQL with `citext`) | - |
| S05 safe intake | ✅ | `cloud/intake.py` |
| S06 detection | ✅ | `cloud/detect.py`, `cloud/yamlutil.py` |
| S07 secret scanner | ✅ | `cloud/secret_scan.py` |
| S08 Terraform/OpenTofu parser | ✅ | `cloud/parsers/terraform.py` |
| S09 CloudFormation/SAM parser | ✅ | `cloud/parsers/cloudformation.py` |
| S10 Kubernetes parser | ✅ | `cloud/parsers/kubernetes.py` |
| S11 IR record, findings, validation | ✅ | `cloud/ir.py` |
| S12 okf-cloud pack + rule engine | ✅ 25 controls, 25 properties, 29 catalog section 11 acceptance cases | `cloud/rules/`, `okf-cloud/knowledge/`, `cloud/tests/test_cat11.py` |
| S13 Checkov/Trivy adapters | ✅ parsing, safe runner, engine/version tagging, dedupe (tools are NOT bundled in the image yet: reported as `unavailable`, never as a clean scan) | `cloud/scanners.py` |
| S04/S14 engine side: scan pipeline + `/scan` service endpoint, honest report statement, coverage block | ✅ (`cloud/`); backend glue, DB persistence and UI still ⬜ (need the backend suite / CI) | `cloud/pipeline.py`, `cloud/service.py` |
| S18 per-framework scoring | ✅ | `cloud/scoring.py` |
| S21 exceptions (expiry, separation of duties) | ✅ engine side; DB/API/UI ⬜ | `cloud/exceptions.py` |
| S25 scan-to-scan drift | ✅ engine side | `cloud/drift.py` |
| S26 capability matrix generated from the pack | ✅ | `cloud/capability.py` |
| S20 JSON / CSV / SARIF export | ✅ | `cloud/export.py` |
| S17 relationship graph + effective exposure (note only; evidence state untouched) | ✅ | `cloud/graph.py` |
| S19 remediation snippets (un-applied) + explain-only prompt builder | ✅ | `cloud/remediation.py` |
| S22 deeper Kubernetes rules: hostIPC, hostPath, read-only root FS, RBAC wildcard, cluster-admin and anonymous bindings (CLOUD-K8S-009..014; 31 controls total) | ✅ | `cloud/rules/extractors.py`, `okf-cloud/` |
| S15 Azure ARM parser (parameters/variables defaults, nested resources, copy/condition noted); Bicep NOT compiled (needs a pinned compiler in the image; reported as unsupported) | ✅ ARM, ⏸ Bicep | `cloud/parsers/arm.py` |
| S16 OCI Resource Manager zip pass/fail with line evidence | ✅ | `cloud/tests/test_oci.py` |
| S27/S28 (partial) inbound-firewall rules for DigitalOcean, Linode, Hetzner, Scaleway, Alibaba, Tencent, Huawei, OpenStack Terraform resources; attribute names follow provider docs and are NOT yet validated against pinned schemas (CM-142). IBM, Vultr, OVH, UpCloud and non-network controls are not covered | 🟡 | `cloud/rules/extractors.py` (`_FW_SPECS`) |
| S04/S14 backend API (`/api/v1/cloud/*`: status, scans upload/list/get, findings, export json/csv/sarif), org-scoped store, scanner `/export/{fmt}`. Mounted only when `CLOUD_MODULE_ENABLED` is on (one gated line in `main.py`). Uses a direct upload call instead of a `cloud_scan` job kind (no upload bytes in the job queue). API tests pass locally with fakes; the SQL in `cloud_store.py` and the full backend suite have NOT been run (need PostgreSQL with citext) | 🟡 | `backend/app/api/v1/cloud.py`, `backend/app/core/cloud_store.py`, `backend/tests/test_cloud_api.py` |
| S14/S24 Findings UI: separate `/cloud` page + nav entry (shows 'not enabled' when the flag is off; existing dashboards untouched). Lint (pre-existing warnings only) and production build pass locally; not exercised against a running backend | 🟡 | `frontend/src/pages/CloudSecurity.tsx`, `frontend/src/api/cloud.api.ts` |
| S23 audit-log entry on scan creation; opt-in kept file (encrypted, 90 days, never when a secret is found), recurring scans run by a separate `app.cloud_scheduler` process, cloud events (`cloud.scan.completed/failed`, counts only) delivered through an EXISTING webhook (JSON format only), opt-in link from a scan to an existing asset (read-only reference). New tables only (`migrate_018.sql`); the existing schedules, webhooks and assets modules and tables are not edited. Tested against a real PostgreSQL (26 tests, 100% of the new modules); UI panel in `frontend/src/components/CloudExtras.tsx` | ✅ (verified on a scratch PostgreSQL with stand-ins for the unavailable extensions; the project's CI database image has not run it) | `backend/app/core/cloud_ext.py`, `cloud_runner.py`, `app/cloud_scheduler.py`, `app/api/v1/cloud_ext.py`, `backend/tests/test_cloud_ext.py`, `docker-compose.cloud.yml` |
| S34 (customer rule packs) private pack of CUSTOM-* controls over existing properties, severity overrides, justified disables that are always reported in coverage; no code, mappings or extractors; bounded; on-prem packaging not done | 🟡 | `cloud/rules/customer.py` |
| S30 India provider discovery: evidence framework and decision rule only; NO provider conclusions are written (they need primary sources the study has not collected) | 🟡 | `docs/CLOUD_INDIA_PROVIDER_DISCOVERY.md` |
| S31/S32 foundations (no cloud client, no network): read-only operation guard, authorisation record, un-leakable Secret, static/live reconcile giving PASS_LIVE / FAIL_LIVE / CONFLICT. Real AWS/Azure/GCP connectors need a test cloud account and are not built | 🟡 | `cloud/live.py` |
| S29 (partial) OpenStack Heat security groups, Ansible `ec2_group` tasks, Pulumi stack-export AWS security groups; VMware/NSX, Nutanix and cloud-init are NOT done (no verified schemas / rules) | 🟡 | `cloud/parsers/heat.py`, `ansible.py`, `pulumi.py`, `cloud/tests/test_s29.py` |
| S28 (more) OVH, Vultr, IBM Cloud and UpCloud firewall rules, built from the official provider documentation (cited in `docs/CLOUD_PROVIDER_SOURCES.md`); anything the docs leave open is UNKNOWN | 🟡 (attribute names not yet validated against pinned schemas, CM-142) | `cloud/rules/extractors.py` (`_vultr`, `_ibm`, `_upcloud`), `cloud/tests/test_vendors.py` |
| S29 (more) cloud-init: SSH password auth, clear-text passwords, passwordless sudo, download-piped-to-shell (CLOUD-INIT-001..004; 35 controls total); VMware NSX-T and Nutanix researched but NOT implemented (official argument references could not be retrieved) | 🟡 | `cloud/parsers/cloudinit.py`, `okf-cloud/` |
| S20 PDF report: dependency-free text PDF (statement, coverage, not-assessed list, summary, findings with file/line), redacted, bounded; served by the scanner and the backend export route and offered on the Cloud page | ✅ | `cloud/export.py` (`to_pdf`) |
| S33 org-wide inventory, S31/S32 real connectors | ⬜ blocked: need a test cloud account; not started | - |

Verification status: `cloud/` has its own test suite with a 100% coverage gate (475 tests at the time of writing).
Run it with `cd cloud && uv run --frozen pytest -q --cov`.

### Coverage notes for S12 (what the first rule pack does and does not claim)
* Verified by acceptance tests: NET-001..005, IAM-001..003, STO-001..003, DB-001, K8S-001..003, LOG-002, SEC-001, CFG-001.
* Not yet covered: KEY-001 (needs a customer policy profile), LOG-001 organisation-wide scope (needs live assessment),
  CFG-002 (needs the relationship graph, S17). Findings for these are never reported as PASS.
* Framework mappings in the pack are NIST SP 800-53 Rev. 5 control ids marked `verified: false`; CIS ids are intentionally absent
  and the pack loader rejects unverified CIS entries.
* Catalog fixtures have not yet been validated against pinned provider schemas (CM-142 remains open).

### Decisions and deviations recorded during implementation
* **CM-094 (reuse OKF evaluator by import) changed.** Importing `okf.src.engines` would pull `pydantic` and the okf sources
  into the sandboxed scanner image. The cloud engine implements the same condition DSL and operator semantics
  (`all` / `any` / `{property, operator, value}`; a missing value is UNKNOWN) and a parity test imports the real
  `eval_op` to prove the two agree.
* **GitHub Actions** are disabled for the whole repository at the owner's request (Settings > Actions); re-enable them when asked.
* **Security reviews.** Automated security reviews of the commits produced findings that were fixed as `fix(cloud)` commits:
  intake member accounting, secret-scanner fail-open and ReDoS, Terraform recursion and expansion budgets, plan/state
  redaction, YAML alias expansion and depth limits.
* **Unverifiable here:** backend integration (S04, S14, S23, S24) cannot be proven locally because the project's test
  database needs `pgcrypto` and `citext`; the embedded PostgreSQL available on the dev laptop lacks `citext`. CI is the
  verification point for those steps.
* **Repository housekeeping (requested by the owner).** Dependabot updates were merged into `main` (see below) and GitHub
  Actions workflows were disabled on GitHub (not by editing files) to save Actions credits until the owner re-enables them.
  Note that merging the Actions bumps changed `.github/workflows/ci.yml`, a deliberate exception to CM-155 (which is
  about this module not editing CI).
* **CI baseline.** Before this work, `main` already failed CI: the backend suite passed 634 tests but missed its 100%
  coverage gate (99.92%), and the dependency/secret-scan job failed. Neither is caused by the cloud module.

---

### End-to-end verification (2026-11-02, dev laptop)

Run locally with the real scanner service (flag on), the real backend cloud router and `cloud_store` against a scratch
PostgreSQL (`migrate_017.sql` applied; the rest of the schema is stubbed because the scratch server lacks `pgcrypto`/`citext`),
dev-admin auth (`REQUIRE_AUTH=false`) and the Vite dev server:

* Upload of a Terraform file and of a cloud-init file through the `/cloud` page produced stored scans and findings
  (CLOUD-NET-001 FAIL, CLOUD-INIT-001/004 FAIL); the scan list, findings table and filters render.
* JSON, CSV, SARIF and PDF exports return 200 with the right content types; the PDF button works from the UI.
* With `CLOUD_MODULE_ENABLED=false` the API returns 404 and the page shows "The cloud security module is not enabled."
* Not verified: Docker image builds, the full backend suite, real login/RBAC through the production auth stack, and
  cookie-mode auth. These need Docker and PostgreSQL with `citext`/`pgcrypto`.

## 1. Step plan (34 steps, 6 phases)

| Step | Phase | Deliverable | Depends on | Exit criterion | Effort |
|---|---|---|---|---|---|
| S01 | 0 Foundation | Commit catalog under `docs/`; create `cloud/` and `okf-cloud/` skeletons; `CLOUD_MODULE_ENABLED` flag (default off) | - | Repo builds; flag off = no behaviour change | 1-2 d |
| S02 | 0 | `migrate_017.sql`: `cloud_scans`, `cloud_resources`, `cloud_findings`, `cloud_exceptions`, RLS by `org_id` | S01 | Migration applies/rolls back; RLS test passes | 2-3 d |
| S03 | 0 | Scanner container + sandbox profile (no network, read-only FS, non-root, CPU/mem/time limits); `docker-compose.cloud.yml` | S01 | Container starts; egress blocked in test | 3-4 d |
| S04 | 0 | `cloud.py` API shell, `cloud_scan` job kind, `cloud.yml` CI, stub end-to-end scan | S02,S03 | Stub scan runs; existing suite green at 100% coverage with flag on and off | 2-3 d |
| S05 | 1 MVP | Safe archive intake (zip/tar/gz): size, count, depth, path-traversal, symlink, bomb limits | S04 | Malicious-archive corpus rejected | 4-5 d |
| S06 | 1 | Content-based type detection + provider/format detector | S05 | Detection matrix test (every supported format) | 3 d |
| S07 | 1 | Secret scanner before parsing; masking; redaction in logs/reports | S05 | Planted secrets never appear in any output | 3-4 d |
| S08 | 1 | Terraform/OpenTofu HCL + JSON + plan-JSON parser (offline, no `init`, no module fetch); state opt-in/redacted | S06 | Parses fixtures; variables/locals/count/for_each/dynamic handled or UNKNOWN | 8-10 d |
| S09 | 1 | CloudFormation/SAM parser (intrinsics, transforms, nested stacks → UNKNOWN when unresolved) | S06 | Fixture + edge-case tests | 5-6 d |
| S10 | 1 | Kubernetes/Helm-rendered/Kustomize-output parser | S06 | Fixture + multi-doc YAML tests | 4-5 d |
| S11 | 1 | Cloud Resource IR (CAT §7.2), provenance (file/line/parser/rule versions), evidence-state model (CAT §1.1) | S08-S10 | IR schema validated; every field traceable | 4-5 d |
| S12 | 1 | `okf-cloud` v1: properties, schema-path mappings, controls (AWS/Azure/GCP/K8s per CAT §11) + evaluator reusing `okf/src/engines.py` by import | S11 | All CAT §11 cases green; pass+fail fixture per rule | 10-12 d |
| S13 | 1 | Checkov + Trivy adapters in scanner image; normalise, dedupe, tag engine+version | S12 | Same fixture yields merged, deduped findings | 5-6 d |
| S14 | 1 | Results API + findings UI (`/cloud`) + coverage statement; MVP release gate | S12,S13 | E2E: upload → findings with file/line evidence | 6-8 d |
| S15 | 2 | Azure ARM parser + sandboxed Bicep compile (pinned compiler) | S11 | ARM and Bicep fixtures give same normalised findings | 6-7 d |
| S16 | 2 | OCI (Terraform/Resource Manager zip) parser mapping + rules | S08,S12 | OCI fixtures pass/fail | 4-5 d |
| S17 | 2 | Relationship graph + effective exposure (CAT §7.3); CFG-002 behaviour | S11 | Unattached rule not reported as effective exposure | 8-10 d |
| S18 | 2 | Framework mapping/crosswalk + per-framework scoring (CAT §6.3); `verified` flag on mappings | S12 | Unknown never counted as pass; denominators shown | 5-6 d |
| S19 | 2 | Remediation snippets (un-applied diffs) + LLM explanations through the existing gateway (explain-only) | S12 | Snippets parse/validate; never auto-applied | 5-6 d |
| S20 | 2 | PDF report + JSON/CSV export (CAT §12 wording rules) | S18,S19 | Report contains every CAT §12 field | 5-6 d |
| S21 | 2 | Exceptions workflow (owner, justification, expiry, approval) | S02,S14 | Expired exception re-opens finding | 3-4 d |
| S22 | 2 | Kubernetes deep rules (RBAC, PSS, network policy default-deny, secrets) | S10,S17 | K8S-001..003 + extras green | 5-6 d |
| S23 | 3 Integration | Schedules, webhooks, audit-log entries via existing registries (no edits to those modules) | S14 | Scheduled scan runs; audit trail complete | 3-4 d |
| S24 | 3 | Opt-in link to existing assets; separate cloud page; existing dashboards unchanged | S14 | Existing dashboard numbers identical before/after | 3-4 d |
| S25 | 3 | Scan history and drift between two scans | S14 | Diff test | 3-4 d |
| S26 | 3 | Per-provider, per-resource-family capability matrix (P0-P6) shown in UI | S12 | Matrix generated from tests, not hand-written | 3 d |
| S27 | 4 Providers | Alibaba ROS, IBM, Tencent, Huawei adapters + rules | S12,S26 | Per-provider DoD (CAT §10) | 15-20 d |
| S28 | 4 | DigitalOcean, Linode, Hetzner, Vultr, OVH, Scaleway, UpCloud | S12,S26 | Per-provider DoD | 15-20 d |
| S29 | 4 | OpenStack Heat, VMware/NSX, Nutanix, Ansible/cloud-init, Pulumi export | S12,S26 | Per-platform DoD | 15-20 d |
| S30 | 4 | India provider discovery study (CAT §2.4) → adapter backlog | S26 | Written evidence per candidate; no unverified claims | 5-8 d |
| S31 | 5 Live | Read-only connectors AWS/Azure/GCP with credential vault, customer authorisation | S14 | Works only with read-only role; creds never logged | 15-20 d |
| S32 | 5 | Live evidence, effective policy resolution, PASS_LIVE/FAIL_LIVE/CONFLICT | S31 | Static-vs-live conflict test | 10-15 d |
| S33 | 5 | Org-wide inventory + remaining connectors (OCI, others) | S31 | Inventory matches test account | 15-20 d |
| S34 | 5 | Enterprise: customer rule packs, policy customisation, on-prem packaging | S18 | Private pack loads without code change | 8-10 d |

**Milestones:** usable MVP after **S14** (14 steps) · recommended product release after **S26** (26 steps) ·
catalog-complete after **S34** (34 steps). Estimated total (one engineer): ≈ 25-37 weeks; MVP alone ≈ 6-8 weeks.

---

## 2. Requirement-to-implementation matrix

### A. Product boundary and evidence model (CAT §1)

| Req | Requirement | CAT § | Planned implementation | Step | Verification | Status |
|---|---|---|---|---|---|---|
| CM-001 | Support upload-only (static) and connected (live) assessment modes | 1 | `mode` field on scan; static path S04-S14, live path S31-S32 | S04,S31 | API test per mode | ⬜ |
| CM-002 | Evidence states PASS/FAIL/UNKNOWN_STATIC, N/A, *_LIVE, CONFLICT | 1.1 | Enum in IR + findings table (names already listed in `okf-cloud/okf_manifest.yaml`) | S11 | Schema test | 🟡 |
| CM-003 | Never convert UNKNOWN to PASS | 1.1, 14 | Evaluator returns UNKNOWN on `None`; property test | S12 | CFG-001 test | ✅ |
| CM-004 | Every finding shows source, address, file, line, parser/rule version, timestamp | 1.1 | `source{}` block in IR; stored in `cloud_findings` | S11 | Field-presence test | 🟡 |
| CM-005 | Never claim uploaded config proves deployed state | 1 | Report wording + banner | S20 | Wording test | ⬜ |

### B. Providers and platforms (CAT §2)

| Req | Requirement | CAT § | Planned implementation | Step | Verification | Status |
|---|---|---|---|---|---|---|
| CM-010 | AWS | 2.1 | S08/S09 + `okf-cloud/mappings/aws.yaml` | S12 | Fixture pass/fail | 🟡 |
| CM-011 | Azure | 2.1 | ARM/Bicep + Terraform | S12,S15 | Fixture pass/fail | 🟡 |
| CM-012 | GCP | 2.1 | Terraform + KRM | S12 | Fixture pass/fail | 🟡 |
| CM-013 | OCI | 2.1 | Terraform + Resource Manager zip | S16 | Fixture pass/fail | ⬜ |
| CM-014 | Alibaba Cloud | 2.1 | ROS + Terraform | S27 | Per-provider DoD | ⏸ |
| CM-015 | IBM Cloud | 2.1 | Terraform | S27 | Per-provider DoD | ⏸ |
| CM-016 | Tencent Cloud (no unverified CIS claim) | 2.1 | Terraform | S27 | Claims review | ⏸ |
| CM-017 | Huawei Cloud (no unverified CIS claim) | 2.1 | Terraform | S27 | Claims review | ⏸ |
| CM-020 | DigitalOcean, Linode, Hetzner, Vultr, OVH, Scaleway, UpCloud (Equinix if requested) | 2.2 | Terraform adapters | S28 | Per-provider DoD | ⏸ |
| CM-030 | OpenStack, VMware/NSX, Nutanix, Crossplane | 2.3 | Heat/Terraform adapters | S29 | Per-platform DoD | ⏸ |
| CM-031 | Kubernetes (separate from cloud-account benchmark) | 2.3 | K8s parser + rules | S10,S22 | K8S tests | ⬜ |
| CM-032 | Pulumi / CDK: scan synthesised output, keep provenance | 2.3 | Export-based parsers | S29 | Export fixture | ⏸ |
| CM-033 | Ansible / cloud-init as a separate scanner family | 2.3 | Separate parser family | S29 | Fixture | ⏸ |
| CM-040 | India provider discovery (candidates, not verified integrations) | 2.4 | Study document per candidate | S30 | Evidence recorded | ⏸ |
| CM-041 | Adapter + capability registry; level per provider and resource family | 2, 10 | Registry generated from tests | S26 | Matrix reflects test results | ⬜ |

### C. Upload formats (CAT §3)

| Req | Requirement | CAT § | Planned implementation | Step | Verification | Status |
|---|---|---|---|---|---|---|
| CM-050 | Terraform/OpenTofu `.tf .tfvars .tf.json .hcl`; no `apply`, no module fetch | 3.1 | `cloud/parsers/terraform.py` | S08 | Parser tests | ✅ |
| CM-051 | Terraform plan JSON; planned vs known vs unknown values | 3.1 | Plan-JSON reader | S08 | Unknown-value test | ✅ |
| CM-052 | Terraform state: opt-in only, redacted, not persisted | 3.1 | Guarded flag + redactor | S08 | State not stored test | ✅ |
| CM-053 | CloudFormation/SAM/CDK output | 3.1 | `cfn.py` | S09 | Intrinsic-function tests | ✅ |
| CM-054 | ARM + Bicep (pinned compiler, sandboxed) | 3.1 | `arm.py`, `bicep.py` | S15 | Equivalence test | ⬜ |
| CM-055 | GCP Terraform/KRM/Infra Manager; Deployment Manager not a default | 3.1 | Terraform + KRM parser | S08,S12 | Fixture | ⬜ |
| CM-056 | Alibaba ROS | 3.1 | `ros.py` | S27 | Fixture | ⏸ |
| CM-057 | OCI Resource Manager zip; reject state | 3.1 | Archive root inspection | S16 | State rejected test | ⬜ |
| CM-058 | Kubernetes/Helm/Kustomize | 3.1 | `k8s.py` | S10 | Fixture | ✅ |
| CM-059 | OpenStack Heat | 3.1 | `heat.py` | S29 | Fixture | ⏸ |
| CM-060 | Policy files (Rego, Azure Policy, Sentinel) | 3.1 | Policy-quality scanner | S29 | Fixture | ⏸ |
| CM-061 | Safe archive handling (ZIP/TAR/GZ) | 3.1, 8 | `intake.py` | S05 | Malicious corpus | ✅ |
| CM-062 | Do not process credentials, `.terraform/`, provider binaries, provisioners, undecryptable files as config | 3.2 | Deny-list + content sniff | S05,S07 | Rejection tests | ✅ |
| CM-063 | Secrets scanner runs before parsers; values masked | 3.2, 5.7 | `secrets.py` | S07 | Leak test | ✅ |

### D. Security checks (CAT §5)

| Req | Requirement | CAT § | Planned implementation | Step | Verification | Status |
|---|---|---|---|---|---|---|
| CM-070 | IAM: wildcard admin, public principals, cross-account trust, privilege paths | 5.1 | `okf-cloud/controls/iam.yaml` (+ graph for paths) | S12,S17 | IAM-001..003 | 🟡 |
| CM-071 | Network: 0.0.0.0/0 and ::/0 to management/DB ports, all-ports, default-allow, effective exposure | 5.2 | `controls/network.yaml` + graph | S12,S17 | NET-001..005, CFG-002 | 🟡 |
| CM-072 | Storage/data: public access, encryption, TLS, keys, versioning, snapshots | 5.3 | `controls/storage.yaml` | S12 | STO-001..003, KEY-001 | 🟡 |
| CM-073 | Logging/monitoring: audit trail, retention, tamper protection | 5.4 | `controls/logging.yaml` (static where provable, else UNKNOWN) | S12 | LOG-001, LOG-002 | 🟡 |
| CM-074 | Compute/workload: IMDS, volume encryption, privileged containers | 5.5 | `controls/compute.yaml`, `k8s.yaml` | S12,S22 | K8S-001..003 | 🟡 |
| CM-075 | Managed services: DB, K8s, LB, DNS, secrets manager, serverless | 5.6 | `controls/managed.yaml` | S12,S22 | DB-001 + per-family | 🟡 |
| CM-076 | Secrets/sensitive data in uploads; rotation advice; no secret in LLM context | 5.7 | `secrets.py` + redaction hooks | S07 | SEC-001 | 🟡 |
| CM-077 | Image/package CVE scanning kept separate from config checks | 5.5 | Out of scope until requested | - | - | ⏸ |

### E. Compliance mapping (CAT §6)

| Req | Requirement | CAT § | Planned implementation | Step | Verification | Status |
|---|---|---|---|---|---|---|
| CM-080 | Map to CIS, CIS Controls, NIST CSF/800-53, ISO 27001, PCI, SOC 2, HIPAA, GDPR, STIG; pinned versions; no invented IDs | 6.1 | `okf-cloud/crosswalks/*.yaml`, `verified` flag | S18 | Unverified mappings flagged in UI | ⬜ |
| CM-081 | Rule metadata (id, provider, resource types, severity, mode, logic version, mappings, unknown handling, remediation, references) | 6.2 | Control YAML schema + validator | S12 | Schema validation in CI | ✅ |
| CM-082 | Per-framework/edition/scope scoring; separate Passed/Failed/Unknown/N-A/Not-assessed; no single global % | 6.3 | `cloud/scoring.py` | S18 | Denominator test | ⬜ |
| CM-083 | Exceptions with owner, justification, expiry, approval | 6.3 | `cloud_exceptions` + API/UI | S21 | Expiry test | ⬜ |
| CM-084 | Licensed benchmark text not redistributed; customer-import path | 6.1 | Reuse `catalogue-import` pattern, separate output dir (git-ignored, see `okf-cloud/.gitignore`) | S18 | Import test | 🟡 |

### F. Architecture (CAT §7)

| Req | Requirement | CAT § | Planned implementation | Step | Verification | Status |
|---|---|---|---|---|---|---|
| CM-090 | Pipeline: detect → safety/secrets → parse → IR → rules → graph → evidence → report | 7 | `cloud/pipeline.py` | S04-S14 | End-to-end test | 🟡 |
| CM-091 | External scanners (Checkov, Trivy, optionally KICS/OPA) as independent engines | 7.1 | `cloud/engines/*.py`, pinned in scanner image | S13 | Merge/dedupe test; engine+version recorded | 🟡 |
| CM-092 | Normalised IR keeping `provider_raw`; no attribute dropped | 7.2 | IR dataclass | S11 | Round-trip test | ✅ |
| CM-093 | Relationship graph with edge provenance/certainty | 7.3 | `cloud/graph.py` (NetworkX is already used elsewhere in the repo) | S17 | Edge-certainty test | ⬜ |
| CM-094 | Reuse OKF evaluator semantics without editing `okf/` | 7 | `cloud/rules/engine.py` re-implements the same DSL; parity test imports the real `okf.src.engines.eval_op` (see section 0) | S12 | Parity test over the operator matrix | ✅ |

### G. Upload pipeline and security (CAT §8)

| Req | Requirement | CAT § | Planned implementation | Step | Verification | Status |
|---|---|---|---|---|---|---|
| CM-100 | Size, file-count, depth, path, time limits | 8.1 | `intake.py` limits | S05 | Limit tests | ✅ |
| CM-101 | ZIP-slip, traversal, symlink, bomb, recursion defences | 8.2 | `intake.py` | S05 | Attack corpus | ✅ |
| CM-102 | Content-based type detection; reject binaries | 8.3 | `detect.py` | S06 | Spoofed-extension test | ✅ |
| CM-103 | Ephemeral unprivileged container, read-only FS, no credentials | 8.4 | Scanner container profile | S03 | Container policy test | 🟡 |
| CM-104 | No network; no module/remote/URL/git fetch | 8.5 | Network-off + parser refuses remote refs | S03,S08 | Egress test | 🟡 |
| CM-105 | No provisioners, scripts, hooks or side-effect functions executed | 8.6 | Parsers are static only | S08 | Provisioner fixture inert | ✅ |
| CM-106 | No `terraform init` on untrusted input | 8.7 | Never invoked; schema from pinned mirror data | S08 | Static assertion | ✅ |
| CM-107 | Filename sanitising and tenant path isolation | 8.8, 8.10 | Per-org storage prefix | S05 | Cross-tenant test | 🟡 |
| CM-108 | Encryption at rest/in transit; retention and deletion | 8.9 | Reuse `core/crypto` and retention service via import | S02,S23 | Retention test | ⬜ |
| CM-109 | Secrets redacted from logs, traces, LLM context | 8.11 | Reuse `core/redact` via import | S07 | Log scan test | 🟡 |
| CM-110 | Report rendering safe from HTML/Markdown injection | 8.12 | Escape on output | S14,S20 | Injection test | ⬜ |
| CM-111 | Immutable audit record of upload/scan/view/export/delete | 8.13 | Reuse `core/auditlog` | S14,S23 | Audit-entry test | ⬜ |
| CM-112 | LLM explains only; deterministic rules decide; remediation shown as proposal | 8.1 | Gateway reuse, explain endpoints only | S19 | No-LLM-in-verdict test | ⬜ |

### H. Output, live assessment, definition of done

| Req | Requirement | CAT § | Planned implementation | Step | Verification | Status |
|---|---|---|---|---|---|---|
| CM-120 | Report: providers, formats, versions, mode, counts, findings fields, mappings, remediation, unknowns, coverage, exceptions | 12 | `cloud/report.py` | S20 | Field checklist test | ⬜ |
| CM-121 | Avoid "100% compliant / certified" wording | 12 | Template lint | S20 | Forbidden-phrase test | ⬜ |
| CM-130 | Read-only connectors with explicit authorisation | 1, 9 | `cloud/connectors/` | S31,S33 | Write attempt denied | ⏸ |
| CM-131 | Live evidence, effective IAM/policy, drift, CONFLICT state | 1.1, 9 | Drift engine | S32 | Conflict test | ⏸ |
| CM-132 | History snapshots, ownership, remediation tracking | 9 Wave 5 | History + tracking tables | S25,S34 | Snapshot diff | ⬜ |
| CM-133 | Customer private rule packs and on-prem deployment | 9 Wave 5 | Rule-pack loader; compose packaging | S34 | Private pack test | ⏸ |
| CM-140 | Provider DoD: detection, pinned schema, pass+fail fixture per rule, line evidence, edge-case tests, relationships, coverage matrix, no deploy, docs of known false positives | 10 | Checklist enforced by CI per provider | S26-S29 | CI gate | ⬜ |
| CM-141 | Capability levels P0-P6 per provider and resource family | 10 | Generated matrix | S26 | Matrix test | ⬜ |
| CM-142 | Fixtures validated against pinned provider schemas (catalog fixtures are unvalidated) | 4, 10 | `terraform validate` / `cfn-lint` / bicep build in sandbox, no credentials | S12 | CI fixture-validation job | ⬜ |

### I. Non-disturbance requirements (added by this plan)

| Req | Requirement | Planned implementation | Step | Verification | Status |
|---|---|---|---|---|---|
| CM-150 | With `CLOUD_MODULE_ENABLED=false` the application behaves exactly as today | `cloud/flags.py` (fail-closed, done in S01); conditional router/handler/route registration later | S01,S04 | Flag tests; full existing suite green, flag off and on | 🟡 |
| CM-151 | No writes to existing tables; cloud data only in `cloud_*` tables | New migration only | S02 | Dashboard/finding counts identical before and after | 🟡 |
| CM-152 | No change to `backend/pyproject.toml` / `uv.lock` | Dependencies live in `cloud/` image | S03 | `git diff` shows lockfile untouched | ✅ |
| CM-153 | Backend coverage gate (`fail_under = 100`) stays intact and unlowered | Thin glue fully tested; engine has its own gate | S04,S14 | CI | ⬜ |
| CM-154 | `okf/knowledge/*` unchanged; cloud knowledge in `okf-cloud/` | Separate loader root (skeleton done in S01) | S01,S12 | Existing manifest counts (82 controls, 103 properties) unchanged | 🟡 |
| CM-155 | `docker-compose.yml`, existing Dockerfiles and `ci.yml` unchanged | Override compose file, separate workflow | S03,S04 | `git diff` check | 🟡 |
| CM-156 | Scanner failure cannot affect audits | Separate container and job kind | S04 | Kill-scanner test | ⬜ |
| CM-157 | Only these existing files edited: `main.py` (1 conditional line), `job_handlers.py` (1 entry), `App.tsx` + nav (1 route, 1 flag-gated entry) | Review gate in PR template | S04,S14 | Diff review | ⬜ |

---

## 3. Test-case traceability (CAT §11 → rule → step)

| Case | Rule family | Step | Case | Rule family | Step |
|---|---|---|---|---|---|
| NET-001 SSH IPv4 | network | S12 | STO-003 weak TLS | storage | S12 |
| NET-002 SSH IPv6 | network | S12 | KEY-001 CMK required | storage/keys | S12 |
| NET-003 RDP | network | S12 | LOG-001 org audit log | logging | S12 |
| NET-004 all ports | network | S12 | LOG-002 trail protection | logging | S12 |
| NET-005 public DB listener | network/db | S12 | DB-001 public DB | managed | S12 |
| IAM-001 public principal | iam | S12 | K8S-001 privileged | k8s | S12,S22 |
| IAM-002 wildcard admin | iam | S12 | K8S-002 root user | k8s | S22 |
| IAM-003 cross-account trust | iam/graph | S12,S17 | K8S-003 default-deny | k8s | S22 |
| STO-001 public bucket | storage | S12 | SEC-001 embedded secret | secrets | S07 |
| STO-002 no encryption | storage | S12 | CFG-001 dynamic hides property | evaluator | S12 |
|  |  |  | CFG-002 unattached firewall | graph | S17 |

## 4. Coverage check

- Every requirement CM-001..CM-157 maps to at least one step and one verification.
- Every step S01-S34 delivers at least one requirement.
- Requirements marked ⏸ depend on customer demand or a live test account and are the only ones that can slip without blocking the MVP (S14) or the recommended release (S26).
- Open risks to track: Checkov/Trivy licence and version drift; unverified CIS IDs; the catalog's fixtures need schema validation (CM-142); no live test account for S31-S33.

### Dependabot review (2026-11-01)
- Merged: node 26-slim (#7), nginx-unprivileged 1.31-alpine (#8) - frontend images only; Docker could not be built locally, so unverified by build.
- Closed: python 3.15-slim (#1) - hdbscan publishes wheels up to cp314 only, so the backend image would need a source build. Revisit when cp315 wheels exist.

### Security-review fixes (2026-11-01)
- Backend: `POST /cloud/scans` now requires the AUDITOR role server-side (test: VIEWER gets 403).
- Ansible: unreadable `rules` (templated, non-list, or any non-mapping item) make the ingress Unknown instead of a shorter list.
- Firewall resources: a block list containing a non-mapping or computed element yields UNKNOWN, never a pass.
- PDF: each logical line is redacted before wrapping, so a credential cannot be split across lines and escape redaction.
- cloud-init: only the modules the rules read (users, chpasswd, ssh_pwauth, password, runcmd) are retained; all other modules are reduced to their names, nested key/token/secret-like fields are masked, and runcmd strings are redacted.
- UpCloud: a drop rule that names an address family is not a catch-all, so a later accept for the other family is still evaluated.
