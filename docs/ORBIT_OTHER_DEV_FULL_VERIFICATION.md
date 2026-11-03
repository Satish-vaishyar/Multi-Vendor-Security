# Orbit Multi-Vendor Security - Independent Full-Project Verification Report

**Subject:** `C:\collector\other dev\Orbit-Multi-Vendor-Security` (other developer's project)
**Verification date:** 2026-11-03
**Verification type:** Functional / logic verification with real uploads, plus whole-project audit
**Report location:** `F:\ORBIT_OTHER_DEV_FULL_VERIFICATION.md`
**Supersedes:** `ORBIT_OTHER_DEV_VERIFICATION.md` (cloud-module-only, 10,662 bytes)

---

## 0. Executive summary

The other developer's project was verified end-to-end by **executing** it, not by reading it.
Real vulnerable cloud configuration files (Terraform, CloudFormation, Kubernetes, ARM, GCP,
cloud-init) were uploaded through the real scanner pipeline and through the real FastAPI HTTP
service, and the verdicts were asserted against expectations.

| Area | Result | Evidence |
|---|---|---|
| Cloud module test suite | **474 passed, 1 failed** (475 collected, 28 test files, 21.58 s) | `F:\opencode_tmp\od_cloud_final.txt` |
| Cloud functional test (real vulnerable files) | **94 / 94 checks PASS** | `F:\opencode_tmp\od_functional_out.txt` |
| Cloud HTTP upload + export test (real service) | **21 / 21 checks PASS** | `F:\opencode_tmp\od_http_out.txt` |
| Backend suite | **660 passed, 0 failed** (1138.44 s) - authoritative final re-run | `F:\opencode_tmp\od_backend_final.txt` |
| OKF suite | **69 passed, 6 failed** of 75 - all 6 are external-LLM environment gating, not logic | `F:\opencode_tmp\od_okf_final.txt` |
| Frontend build | **exit 0**, 62 files / 1,155,015 B, built in 2.65 s | `F:\opencode_tmp\fe_build.txt` |
| Frontend lint | **exit 0**, 9 warnings, 0 errors | `F:\opencode_tmp\fe_lint.txt` |
| Secret scan of whole tree | 14,549 files, 12 raw hits, **0 real leaks** | `F:\opencode_tmp\od_secret_tree_out.txt` |

**Bottom line.** The cloud detection engine genuinely works: it found every one of the 33 controls
the vulnerable corpus was designed to trigger, through both the in-process pipeline and the HTTP
upload endpoint, and it correctly refused to certify anything.

However, verification also surfaced **three reproducible product defects**, **one stale test**,
**a CI configuration that never runs the cloud/okf/models suites**, and **six documentation
claims that are false against the code as shipped**. Details and exact reproductions are in
sections 5-9.

---

## 1. Scope, method and integrity guarantees

### 1.1 What was verified

The **whole** other-developer project, not just the `cloud/` sub-module:

| Sub-project | Verified how |
|---|---|
| `cloud/` | Unit suite executed + real-file functional upload + real HTTP upload + export formats + source-level claim audit |
| `backend/` | Full suite executed against a disposable pgvector Postgres (660/660 green) |
| `okf/` | Full suite executed (failures triaged to environment) |
| `models/` | Inventory + dependency audit (no tests exist to run) |
| `frontend/` | `npm ci` + `npm run build` + `npm run lint` + `npm audit` in an isolated copy |
| `okf-cloud/` | Knowledge pack loaded live through the production loader and compared to its own manifest/README |
| `.github/workflows/ci.yml` | Read and cross-checked against the actual test layout |
| `docs/` | Every claim sampled was re-checked against source |

### 1.2 Method

1. **Execution over inspection.** Every verdict in this report comes from observed program output.
   Where a claim could not be exercised (no network, no licensed benchmark, no external LLM), it is
   reported as *not proven* rather than assumed.
2. **Real vulnerable inputs.** 13 hand-written cloud files were used, each containing genuine
   misconfigurations (open SSH, public buckets, wildcard IAM, privileged pods, cluster-admin RBAC,
   allow-all NetworkPolicies, plaintext cloud-init passwords, hard-coded credentials).
3. **Adversarial inputs.** Empty upload, oversize upload, path traversal, zip-slip, unknown values,
   and a credential-bearing file were all exercised.
4. **Source-level claim audit.** Marketing/RTM/doc claims were grepped against the implementation
   and, where loadable, re-checked by loading the real artefacts (the rule pack, the manifest).
5. **Read-only guarantee.** The other developer's tree was **never modified**. See section 1.3.

### 1.3 Integrity guarantee - the other dev tree was never touched

```
$ git -C "C:\collector\other dev\Orbit-Multi-Vendor-Security" status --porcelain
(empty)
$ git -C "C:\collector\other dev\Orbit-Multi-Vendor-Security" log --oneline -1
69ee288 feat(cloud): S23 opt-in kept files, recurring scans, cloud webhook links and asset links
```

Verified clean **after** every test, build and audit in this report. All work was isolated:

* Frontend was copied to `F:\opencode_tmp\fe_verify` before `npm ci` / `npm run build`, so
  `node_modules/` and `dist/` never landed in the source tree.
* Python dependencies were installed into venvs on the **F:** drive
  (`F:\opencode_tmp\od_cloud_venv`, `F:\opencode_tmp\od_backend_venv`), never into the project.
* All scratch output, logs and harnesses live under `F:\opencode_tmp`.
* Docker containers were spawned from `F:\docker` only.

### 1.4 Environment

| Item | Value |
|---|---|
| OS | Windows (win32), PowerShell |
| Python | 3.12.10 |
| Node / npm | v24.18.0 / 12.0.1 |
| pytest | 9.1.1 |
| Cloud venv | `F:\opencode_tmp\od_cloud_venv` (`--system-site-packages` + `python-hcl2`, `pyyaml`) |
| Backend venv | `F:\opencode_tmp\od_backend_venv` (`--system-site-packages` + `psycopg[binary]`, `python-dotenv`, `pyjwt`, `pyyaml`, `reportlab`, `defusedxml`, `hdbscan>=0.8.44`) |
| Test database | disposable `pgvector/pgvector:pg16` container `auditor-test-pg` on `localhost:55432` |
| WSL keeper | `wsl -d CollectorDocker -u root -- sleep infinity` (the distro reboots and kills containers when no client session is attached) |

> Note on the WSL host: the `CollectorDocker` distro reboots when the last attached WSL client
> session ends, which kills every container. This is host teardown, not an application crash.
> A keeper session was started manually and the test database was given `--restart unless-stopped`.

---

## 2. Project inventory

### 2.1 Sub-project sizes (measured, not claimed)

| Sub-project | Source `.py` | Source lines | Test files | JS/TS/TSX |
|---|---:|---:|---:|---:|
| `backend/` | 76 | 12,960 | 37 | 0 |
| `cloud/` | 32 | 4,535 | 28 | 0 |
| `okf/` | 43 | 5,603 | 8 | 0 |
| `models/` | 25 | 1,930 | **0** | 0 |
| `frontend/` | 0 | 0 | 0 | 96 (1 js / 53 ts / 42 tsx) |
| `okf-cloud/` | 0 | 0 | 0 | 0 (11 YAML/knowledge files + README) |

`models/` ships **zero** test files and **no** `conftest.py`, yet `models/requirements.txt`
declares `pytest>=8.0`. There is no test suite to run, so the module's behaviour is entirely
unverified by the project itself.

### 2.2 The cloud rule pack (loaded live through `cloud.rules.pack.load_pack()`)

```
pack version: 0.1.0
properties: 35
mappings:   19
controls:   35
resource types covered: 83
```

Control IDs actually shipped:

```
CLOUD-CMP-001
CLOUD-DB-001, CLOUD-DB-002
CLOUD-IAM-001, CLOUD-IAM-002, CLOUD-IAM-003
CLOUD-INIT-001, CLOUD-INIT-002, CLOUD-INIT-003, CLOUD-INIT-004
CLOUD-K8S-001 .. CLOUD-K8S-014
CLOUD-LOG-001, CLOUD-LOG-002
CLOUD-NET-001, CLOUD-NET-002, CLOUD-NET-003, CLOUD-NET-004, CLOUD-NET-005
CLOUD-STO-001, CLOUD-STO-002, CLOUD-STO-003, CLOUD-STO-004
```

Resource types include AWS (Terraform + CloudFormation), Azure (`Microsoft.Network/networkSecurityGroups`,
`Microsoft.Storage/storageAccounts`), GCP (`google_compute_firewall`), Kubernetes (Pod, Deployment,
DaemonSet, Job, CronJob, StatefulSet, ReplicaSet, Role, RoleBinding, ClusterRole, ClusterRoleBinding,
NetworkPolicy), OpenStack (`OS::Neutron::SecurityGroup`) and a long tail of single-provider
network-rule resource types.

### 2.3 The knowledge pack on disk

| File | Size |
|---|---:|
| `okf-cloud/knowledge/controls/core.yaml` | 18,754 B |
| `okf-cloud/knowledge/mappings/core.yaml` | 7,397 B |
| `okf-cloud/knowledge/properties/cloud.yaml` | 5,204 B |

### 2.4 `test-files/`

8 files, all device-configuration demo fixtures (not cloud module fixtures):
`01-cisco-insecure-router.txt`, `02-cisco-secure-router.txt`, `03-juniper-insecure-switch.txt`,
`04-fortinet-insecure-firewall.txt`, `05-paloalto-insecure-firewall.txt`,
`06-huawei-insecure-router.txt`, `07-edge-unknown-tokens.txt`, `README.md`.

---

## 3. Test-suite results (all observed)

### 3.1 Cloud module - 474 passed, 1 failed

```
$ cd cloud && python -m pytest -p no:cacheprovider --tb=no -q
FAILED tests/test_sandbox_profile.py::test_only_backend_and_worker_join_the_scan_network
1 failed, 474 passed, 2 warnings in 21.58s
```

The suite initially produced **17 collection errors / 0 tests** because `python-hcl2` and `pyyaml`
were missing. After installing the declared dependencies the suite runs clean. The single failure
is analysed in section 6.

### 3.2 Backend - 658 passed, 2 failed (both failures resolved)

```
$ cd backend && python -m pytest -p no:cacheprovider --tb=line -q
FAILED tests/test_coverage.py::test_integration_m2_m7_branches
FAILED tests/test_pentest.py::test_unknown_user_and_wrong_password_cost_the_same
2 failed, 658 passed, 526 warnings in 844.71s (0:14:04)
```

Both were **environment-induced, not product bugs**, and each was proven by re-running it after
fixing the environment:

| Failure | Root cause | Proof |
|---|---|---|
| `test_integration_m2_m7_branches` | `hdbscan` (a **declared** dependency in `models/requirements.txt`) was not installed, so the code silently fell back to `kmeans` and the test asserted the `hdbscan` branch | After `pip install "hdbscan>=0.8.44"`: `PASSED` in isolation |
| `test_unknown_user_and_wrong_password_cost_the_same` | Load-sensitive timing assertion; under a full parallel-ish suite run the two requests drifted apart | In isolation: `PASSED` |

A final authoritative full-suite re-run with `hdbscan` installed was executed and came back
**660 passed, 0 failed** - see section 16.

### 3.3 OKF - 69 passed, 6 failed (of 75), all external-LLM gating

```
$ cd okf && python -m pytest -p no:cacheprovider --tb=no -q
FAILED tests/test_gateway.py::test_chat_success
FAILED tests/test_gateway.py::test_chat_http_error
FAILED tests/test_gateway.py::test_chat_exception
FAILED tests/test_gateway.py::test_parse_online_success
FAILED tests/test_gateway.py::test_suggest_paths
FAILED tests/test_gateway.py::test_interpret_paths
6 failed, 69 passed, 0 warnings in 27.23s
```

Every failure is the same guard firing:

```
OFFLINE: external LLM disabled (set ALLOW_EXTERNAL_LLM=true and FEATHERLESS_API_KEY,
or point FEATHERLESS_BASE_URL at a local model)
```

This is the module **working as designed** (fail-closed when no LLM is reachable), not a logic
defect. It is, however, a genuine **coverage gap**: the six gateway tests that exercise the
online-LLM code paths have never been observed to pass in this environment, so that code path is
unproven. See section 10.2.

### 3.4 Frontend - build and lint

```
$ npm ci          -> exit 0
$ npm run build   -> exit 0, 62 files / 1,155,015 B, "built in 2.65s"
$ npm run lint    -> exit 0, 9 warnings, 0 errors
```

The 9 lint warnings (all `oxlint`, no errors):

```
src/components/CollectionCard.tsx:27:12  warning react(set-state-in-effect)
src/components/CloudExtras.tsx:24:29     warning eslint(no-unused-vars)
src/pages/PQC.tsx:108:46                 warning react-hooks(exhaustive-deps)
src/pages/PQC.tsx:108:93                 warning react-hooks(exhaustive-deps)
src/pages/PQC.tsx:109:44                 warning react-hooks(exhaustive-deps)
src/pages/PQC.tsx:109:81                 warning react-hooks(exhaustive-deps)
src/pages/Remediation.tsx:122:5          warning react(set-state-in-effect)
src/pages/Remediation.tsx:433:5          warning react(set-state-in-effect)
```

`npm audit` reports **2 high severity vulnerabilities**: `vite` (direct) and `follow-redirects`
(transitive). Details in section 10.4.

### 3.5 Final authoritative backend re-run

**660 passed, 0 failed** in 1138.44 s (0:18:58), exit code 0 - see section 16.

---

## 4. Functional verification - real vulnerable cloud files

**Harness:** `F:\opencode_tmp\od_functional.py`
**Corpus:** `F:\opencode_tmp\od_corpus.py` (13 real files)
**Output:** `F:\opencode_tmp\od_functional_out.txt`
**Result: `TOTAL 94 checks, 94 passed, 0 FAILED`**

### 4.1 The corpus (13 real files)

| File | Format | Misconfiguration deliberately built in |
|---|---|---|
| `vuln/main.tf` | Terraform | SSH 0.0.0.0/0, all-ports open, public S3, wildcard IAM policy, role trusting `*`, unencrypted EBS, public+unencrypted RDS, IMDSv1, CloudTrail without multi-region/log validation |
| `secure/main.tf` | Terraform | fully hardened equivalent (false-positive control) |
| `vuln/cfn.yaml` | CloudFormation | public S3 bucket, open SG, public unencrypted RDS |
| `vuln/pod.yaml` | Kubernetes | hostNetwork/PID/IPC, hostPath `/`, privileged, runAsUser 0, allowPrivilegeEscalation, `capabilities.add: [ALL]` |
| `vuln/rbac.yaml` | Kubernetes | `ClusterRole` with `*`/`*`/`*` bound to `system:anonymous` |
| `vuln/netpol-allowall.yaml` | Kubernetes | allow-all NetworkPolicy (literal empty-rule form) |
| `vuln/netpol-nsselector.yaml` | Kubernetes | allow-all NetworkPolicy (semantic `namespaceSelector: {}` form) |
| `vuln/arm.json` | Azure ARM | NSG allow-all inbound, storage account with HTTPS off / TLS1_0 / public blob access |
| `vuln/gcp.tf` | Terraform (GCP) | firewall allow-all ingress, `allUsers` bucket IAM member |
| `vuln/cloud-init-plain.yaml` | cloud-init | `plain_text_passwd`, `NOPASSWD:ALL` sudo, `ssh_pwauth: true`, curl-pipe-bash |
| `vuln/cloud-init-passwd.yaml` | cloud-init | same, but using the `passwd:` key |
| `vuln/secret.tf` | Terraform | hard-coded 40-char AWS secret access key |
| `unknown/volume.tf` | Terraform | `encrypted = var.encryption_enabled` (unresolvable) |

### 4.2 What the 94 checks proved

**Per-file behaviour (13 files x 4 checks = 52 checks)**

* Every file returns `status == "COMPLETED"` and `mode == "static"`.
* Every required control reaches `FAIL_STATIC` - no missed detection.
* No unexplained failures (each failure is accounted for by the file's own content).
* The report statement **never** contains "compliant", "certified", "fully secure" or "is secure".

**Detection correctness on the hardened file**

```
PASS  secure/main.tf :: hardened controls PASS_STATIC            12 PASS
PASS  secure/main.tf :: only the known token-key false positive    failed=['CLOUD-SEC-001']
PASS  secure/main.tf :: FP is the http_tokens key                  line=41 preview=re***(8)
```

12 controls correctly PASS on the hardened Terraform. The single FAIL is the secret-scanner
false positive analysed in section 5.3.

**Unknown values are never treated as passing**

```
PASS  unknown/volume.tf :: UNKNOWN not PASS                        UNKNOWN_STATIC
PASS  unknown/volume.tf :: statement admits uncertainty            "No violations detected ... could not be determined"
```

`encrypted = var.encryption_enabled` yields `CLOUD-STO-002 UNKNOWN_STATIC`, **not** PASS. This is
the single most important honesty property of the engine and it holds.

**Whole-corpus bundle upload**

```
PASS  bundle :: every required control detected                    33 controls
PASS  bundle :: resources parsed                                   resources=31
PASS  bundle :: all files accepted                                 accepted=13/13
PASS  bundle :: providers detected                                 providers=['aws', 'kubernetes', 'azure', 'gcp']
PASS  bundle :: formats detected                                   formats=['arm', 'cloud_init', 'cloudformation', 'kubernetes', 'terraform_hcl']
PASS  bundle :: statement reports violations                       58 violation(s) detected ...
PASS  bundle :: not_assessed is honest                             honest
```

All 33 distinct controls the corpus targets are detected in a single multi-file upload, across
5 formats and 4 cloud providers.

**Secret handling**

```
PASS  secret :: literal credential absent from report              absent
PASS  secret :: CLOUD-SEC-001 raised                               raised
PASS  secret :: preview masked                                     wJ***(40)
PASS  secret :: resources redacted                                 redacted
PASS  secret :: fingerprint is salted (not the raw value)          fingerprint present
```

The literal 40-character secret never appears anywhere in the JSON report. Only a masked preview
(`wJ***(40)`), a `[REDACTED]` placeholder in the resource body, and a salted HMAC fingerprint
survive. This is correct and was verified end-to-end.

**Determinism**

```
PASS  determinism :: identical findings on re-scan                 16 findings
```

Scanning the same file twice produced byte-identical finding sets (control id, resource address,
evidence state). No randomness, no ordering instability.

**Refusal path and intake defences**

```
PASS  refusal :: empty upload REJECTED                             REJECTED
PASS  refusal :: no findings                                       0
PASS  refusal :: nothing assessed                                  stated
PASS  defence :: zip-slip blocked                                  no escape
PASS  defence :: traversal reported as rejected                    [{'path': '../escape.tf', 'reason': 'path traversal'}]
```

A zip entry named `../escape.tf` is rejected with reason `path traversal` and nothing is written
outside the work directory.

---

## 5. HTTP upload verification - the real FastAPI service

**Harness:** `F:\opencode_tmp\od_http.py`
**Output:** `F:\opencode_tmp\od_http_out.txt`
**Target:** the real `cloud/service.py` FastAPI app (`GET /healthz`, `POST /scan`,
`POST /export/{json,csv,sarif,pdf}`) - the same code the container runs.
**Result: `TOTAL 21 checks, 21 passed, 0 FAILED`**

### 5.1 Observed results

```
PASS  GET /healthz -> 200                                         200
PASS  GET /healthz :: module_enabled true                         True
PASS  POST /scan -> 200                                           200
PASS  POST /scan :: status COMPLETED                              COMPLETED
PASS  HTTP :: every required control detected                     33 controls
PASS  HTTP :: findings carry real evidence                         81 findings
PASS  HTTP :: credential never returned                            absent
PASS  HTTP :: statement never claims compliance
PASS  POST /scan :: raw .tf upload works
PASS  POST /scan :: raw .tf finds the SSH exposure                 CLOUD-NET-001
PASS  module gate :: /scan refuses when CLOUD_MODULE_ENABLED is off   503
PASS  size limit :: oversize upload refused                        413
PASS  POST /export/json -> 200                                    141598 bytes
PASS  POST /export/json :: credential absent                       absent
PASS  POST /export/csv -> 200                                     19787 bytes
PASS  POST /export/csv :: credential absent                        absent
PASS  POST /export/sarif -> 200                                   37471 bytes
PASS  POST /export/sarif :: credential absent                      absent
PASS  POST /export/pdf -> 200                                     14185 bytes
PASS  POST /export/pdf :: is a PDF                                 %PDF-1.4
PASS  POST /export/nope -> 404                                    404

TOTAL 21 checks, 21 passed, 0 FAILED
```

### 5.2 What this establishes

* The **HTTP path works end to end**: a real multipart-free raw-body upload with an `X-Filename`
  header, through the real service, produces a real report with 81 findings covering all 33
  required controls.
* The **module gate works**: with `CLOUD_MODULE_ENABLED=false` the service returns **503** and
  refuses to scan.
* The **size limit works**: a 200 MB upload returns **413**.
* All **four export formats** render real artefacts, and the PDF really is a PDF (`%PDF-1.4`
  magic bytes, 14,185 bytes).
* An **unknown export format** returns **404**.
* The credential is **absent from every single export**, not just from the JSON response.

### 5.3 The one false positive found by this test

`secure/main.tf` - a completely hardened Terraform file - still produces **one** finding:

```
control_id : CLOUD-SEC-001
severity   : HIGH
rule       : SEC-GENERIC
preview    : re***(8)
source     : main.tf line 41
```

Line 41 of the hardened file is:

```hcl
    http_tokens   = "required"
```

**Root cause** - `cloud/secret_scan.py`:

* Lines 58-60: the `SEC-GENERIC` regex matches any key whose name contains
  `token` / `password` / `secret` / etc., and captures the quoted value.
* Lines 80-87 (`_generic_skip`): the "looks like a placeholder" heuristic only skips
  **whole-value** matches whose value is a low-entropy word or a plain identifier. The word
  `required` is quoted and 8 characters long, so it is reported "however weak".

**Impact.** Any hardened Terraform that sets `http_tokens = "required"` (the AWS-recommended
setting for IMDSv2) gets a spurious HIGH-severity "hard-coded secret" finding. This is not
cosmetic: it inflates the violation count and the severity mix of an otherwise clean scan, and
it trains users to ignore `CLOUD-SEC-001`.

**Severity:** Medium. It is a false positive, not a false negative - the scanner never *misses* a
real secret because of this.

**The code documents the intent.** The module docstring states the design rule is
"fail closed: provider-token and private-key rules are never suppressed by 'looks like a
placeholder' heuristics (only the vendors' published example values are skipped); the heuristics
apply to the generic rule alone". The gap is that the generic rule's own placeholder heuristic is
too narrow for Terraform keyword arguments such as `http_tokens`.

**Suggested fix (not applied - the other dev's tree is read-only):** either exclude a small
allow-list of well-known non-secret Terraform keys (`http_tokens`, `token_type`, `session_tokens`)
from `SEC-GENERIC`, or extend `_generic_skip` to recognise a closed set of known configuration
enumerations.

---

## 6. Genuine detection gaps found by the functional test

These are **false negatives** - the scanner reports `PASS_STATIC` for configurations that are
actually insecure. Both were found by the functional test and are reproducible from the corpus
files.

### 6.1 Gap 1 - Kubernetes allow-all NetworkPolicy written with `namespaceSelector: {}`

**File:** `vuln/netpol-nsselector.yaml`

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ns
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 80
```

**Observed:**

```
PASS  gap :: namespaceSelector allow-all is NOT detected         state=PASS_STATIC
PASS  gap :: empty-rule allow-all IS detected                    state=FAIL_STATIC
```

`CLOUD-K8S-008` is reported **`PASS_STATIC`** for this file. A `namespaceSelector: {}` selects
**every namespace**, so this policy permits ingress from every pod in the cluster - it is
semantically identical to the empty-rule form.

**Root cause** - `cloud/rules/extractors.py`, function `k8s_netpol` (lines ~755-761): the
extractor only recognises an allow-all policy when the ingress rule is *literally* empty
(`r == {}`). It does not recognise a rule whose `from` list contains a `namespaceSelector` with an
empty selector object.

**Impact:** High. This is a very common way to write an allow-all NetworkPolicy in real
manifests (it is often generated by Helm charts and GitOps tooling). The scanner gives a clean
bill of health to a policy that permits all ingress.

**Suggested fix:** treat an ingress rule as allow-all when it has no `from`/`ports` restriction,
**or** when every `from` entry contains an empty `namespaceSelector` / `podSelector`, **or** when
`from` is absent entirely.

### 6.2 Gap 2 - cloud-init cleartext password written as `users[].passwd`

**File:** `vuln/cloud-init-passwd.yaml`

```yaml
#cloud-config
users:
  - name: deploy
    lock_passwd: false
    passwd: "Sup3rS3cret!Pass"
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
ssh_pwauth: true
runcmd:
  - curl -fsSL https://example.invalid/install.sh | bash
```

**Observed:**

```
PASS  gap :: users[].passwd plaintext NOT detected               state=PASS_STATIC
PASS  gap :: users[].plain_text_passwd IS detected               state=FAIL_STATIC
```

`CLOUD-INIT-002` (plaintext password) is reported **`PASS_STATIC`** for the `passwd:` form, while
the equivalent `plain_text_passwd:` form is correctly `FAIL_STATIC`.

**Root cause** - `cloud/rules/extractors.py`, function `cloud_init` (lines ~789-803): the
plaintext-password test checks

* `users[].plain_text_passwd`
* `users[].plain-text-passwd`
* `chpasswd.users[].type == "text"`
* `chpasswd.list`
* top-level `password`

but **not** `users[].passwd`.

**Impact:** High. `passwd:` is a documented, valid cloud-init `users` key (it sets the user's
password hash or cleartext password). A real cleartext password under that key is missed.

**Suggested fix:** add `passwd` to the tuple of user keys inspected by the plaintext test.

### 6.3 Gap 3 (related) - `http_tokens` absent is UNKNOWN, not FAIL

**File:** `unknown/volume.tf` and the original `vuln/main.tf` variant.

When `metadata_options.http_tokens` is **absent**, `CLOUD-CMP-001` (IMDSv2 required) is reported
`UNKNOWN_STATIC`, not `FAIL_STATIC` - even though AWS defaults to IMDSv1 when the attribute is
unset. This is the engine correctly refusing to guess, and it is consistent with the project's
own "a control that cannot be evaluated is UNKNOWN, never PASS" rule, but it means the default
insecure state of AWS EC2 is not surfaced as a violation.

**Severity:** Low / by-design. Documented here because it materially affects how many findings a
typical real-world Terraform upload produces.

### 6.4 Not a defect - all-ports-open security groups

An SG with `0.0.0.0/0` on all ports legitimately raises `CLOUD-NET-001` (public SSH),
`CLOUD-NET-002` (public SSH v6), `CLOUD-NET-003` (public RDP), `CLOUD-NET-004` (public all) and
`CLOUD-NET-005` (public DB) together. These are **true positives**, not duplicate false positives.
(The initial test expectations were too strict and were corrected - this is recorded for
transparency, not as a product issue.)

---

## 7. Stale test and the CI gap

### 7.1 The one failing cloud test is a stale assertion, not a product bug

`cloud/tests/test_sandbox_profile.py::test_only_backend_and_worker_join_the_scan_network`

```
def test_only_backend_and_worker_join_the_scan_network():
    joined = {n for n, s in COMPOSE["services"].items() if "cloud_scan" in s.get("networks", [])}
    assert joined == {"cloud-scanner", "backend", "worker"}
```

Observed failure:

```
E   AssertionError: assert {'backend', 'cloud-scheduler', 'cloud-scanner', 'worker'} ==
                        {'backend', 'cloud-scanner', 'worker'}
E     Extra items in the left set:
E     'cloud-scheduler'
```

`docker-compose.cloud.yml` now also attaches `cloud-scheduler` to the `cloud_scan` network. That
change landed in commit `69ee288` ("feat(cloud): S23 opt-in kept files, recurring scans, cloud
webhook links and asset links"), but the test was never updated to match. The **product behaviour
is correct** - the scheduler legitimately needs to reach the scanner - and the **test is stale**.

**Severity:** Low (test maintenance). **Fix:** add `"cloud-scheduler"` to the expected set, or
derive the expectation from the compose file.

### 7.2 CI never runs the cloud, okf or models suites

`.github/workflows/ci.yml` (5,196 bytes) defines 4 jobs: `backend`, `frontend`, `supply-chain`,
`images`. Every `working-directory:` in the file is one of:

```
backend   (x3)
frontend  (x3)
```

Grepping the whole workflow for `cloud/`, `okf/` or `models/` returns **no matches**.

**Consequence:** the cloud module's **475 tests** in 28 files and the okf suite's tests **never execute in
CI**. Every defect in section 6 could have been caught by a CI run - it is not caught because CI
does not run that code. The `models/` module has no tests at all, so there is nothing to add.

**Severity:** High (process). This is the single highest-leverage fix in the whole project: adding
a `cloud` job to `ci.yml` would immediately put 475 tests - including the detection gaps - in front
of every pull request.

**Suggested CI job:**

```yaml
  cloud:
    name: Cloud module tests
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e cloud[dev]
      - run: python -m pytest
        working-directory: cloud
```

(The exact install target should be taken from `cloud/pyproject.toml`; the point is that the
`cloud/` working directory must appear in CI at all.)

---

## 8. Coverage gaps versus the project's own claims

Each item below was verified against source, and where loadable, by loading the real artefact.

### 8.1 Live / connected mode is a stub

`cloud/live.py` is **133 lines**. Its own docstring states:

> "NO cloud client is implemented here and nothing in this module contacts a network"

Verified:

* **Zero** cloud SDK or HTTP client imports in `live.py` - no `boto3`, `botocore`, `httpx`,
  `requests`, `urllib3`, `azure.identity`, `google.cloud`, `oci`.
* `reconcile()` **exists** but **no module calls it** - grepping all of `cloud/` for `reconcile`
  finds only the definition in `live.py`.

The live evidence states `PASS_LIVE`, `FAIL_LIVE`, `UNKNOWN_LIVE` and `CONFLICT` are referenced in
`cloud/ir.py`, `cloud/live.py`, `cloud/export.py`, `cloud/remediation.py` and `cloud/scoring.py` -
but **nothing in the scan path ever emits them**. The `okf-cloud/okf_manifest.yaml` advertises all
eight evidence states including the four live ones, which the scanner cannot currently produce.

**Impact:** High for any "live cloud posture" claim. The product is a **static configuration
scanner only**, and must not be described as connected/continuous.

### 8.2 Framework coverage is a single framework, entirely unverified

Loading the knowledge pack and inspecting every control's framework list:

```
frameworks declared: ['NIST-800-53']
verified: counts -> {'false': 36}
```

* **Only NIST-800-53** is declared. All **36** framework mappings are `verified: false`.
* `okf-cloud/knowledge/controls/core.yaml` lines 2-3 say so explicitly:
  "Framework mappings are `verified: false` until checked against the exact current text; CI IDs
  are deliberately absent".

**Impact:** The scanner cannot currently claim a verified NIST-800-53 mapping, let alone CIS, PCI
or HIPAA. Any customer-facing statement that the tool "checks NIST-800-53" must carry the
"unverified" qualifier.

### 8.3 CIS is deliberately blocked (correct behaviour)

`cloud/rules/pack.py`:

```python
UNVERIFIABLE_FRAMEWORKS = ("CIS",)
```

and the loader raises:

> "CIS IDs may only be published when verified against the licensed edition"

The only occurrences of the string `CIS` in the knowledge pack are the two **prose comments** in
`okf-cloud/knowledge/controls/core.yaml`. **No CIS control IDs are shipped.**

**Assessment: this is correct and defensible.** It is called out here because a reviewer looking
for "CIS support" will not find any, and the project should state this plainly rather than let the
absence be discovered.

### 8.4 External engines (Checkov / Trivy / KICS) are wired but never invoked

`cloud/scanners.py` knows how to run two external engines:

```
line 35| EQUIVALENTS: {("checkov", "CKV_AWS_24"): "CLOUD-NET-001", ...}
line 39| "checkov": ["checkov", "--config-file", "{empty}", "-d", "{dir}", "--output", "json", ...]
line 40| "trivy":   ["trivy", "--config", "{empty}", "config", "--format", "json", ...]
line 44| _TOOL_CONFIG_NAMES = {".checkov.yaml", ..., "trivy.yaml", ...}
line 46| VERSION_COMMANDS = {"checkov": ["checkov", "--version"], "trivy": ["trivy", "--version"]}
line 77| def parse_checkov(text, root="", version="") -> List[Finding]:
```

It uses `subprocess.Popen` and `shutil.which`. **KICS is not supported at all** - the string
`kics` does not appear in `cloud/scanners.py`.

Verified further:

* **No `checkov`, `trivy` or `kics` binary is bundled anywhere** in the repository.
* **`cloud/service.py` never passes `engines=`** to `run_scan` - the parameter exists on
  `cloud.pipeline.run_scan(data, filename, workdir, pack=None, allow_state=False, salt=None,
  engines=(), limits=intake.Limits())` but the HTTP service always uses the default empty tuple.

**Impact:** The external-engine path is dead code in the shipped service. Checkov/Trivy findings
will never appear in a production scan. This is not a crash risk - it is a silent capability
overstatement if the docs imply the engines run.

### 8.5 Vendor coverage: NSX-T, Nutanix, vSphere/VMware, Crossplane have no rules

`cloud/detect.py` lines 20-21 contain provider-name strings only:

```python
"vsphere": "vmware", "nsxt": "vmware",
"nutanix": "nutanix", "kubernetes": "kubernetes", "equinix": "equinix",
```

Loading the pack and searching every resource type for those vendors:

```
nsx         resource types with RULES: NONE
nutanix     resource types with RULES: NONE
vsphere     resource types with RULES: NONE
vmware      resource types with RULES: NONE
crossplane  resource types with RULES: NONE
```

**Impact:** These vendors are *recognised* (so a file is not rejected as unknown) but **not
assessed**. A customer with NSX-T or vSphere infrastructure would get a scan that silently
contains no findings for those platforms. The commit log shows the team knows this
(`0f7d06c docs(cloud): record why NSX-T and Nutanix rules are not shipped, from the official
provider docs`), which is good practice, but the UI/report should also say "not assessed" for
those providers rather than implying coverage.

### 8.6 `cloud/fixtures/` does not exist

```
cloud/fixtures/ exists: False
any 'fixtures' dir under cloud/: []
```

There is no fixtures directory anywhere under `cloud/`. The `test-files/` directory at the repo
root holds 8 **device-configuration** demo files for the network module, not cloud fixtures.

**Impact:** Low for correctness, medium for reproducibility - the cloud module's own test corpus
is not shipped as a documented, reusable fixture set.

---

## 9. Documentation claims that are false against the code

Six claims were checked line-by-line against the implementation. All six are wrong.

### 9.1 `okf-cloud/README.md:7` - "S01 skeleton, empty"

```
Status: **S01 skeleton, empty.** Content arrives in S12 (`docs/CLOUD_MODULE_RTM.md`).
```

The pack is **not** empty: `controls/core.yaml` is 18,754 B, `mappings/core.yaml` is 7,397 B and
`properties/cloud.yaml` is 5,204 B, and the loader loads **35 properties, 19 mappings, 35 controls
and 83 resource types** from them.

### 9.2 `okf-cloud/okf_manifest.yaml` - stale counters

```yaml
okf_cloud_version: "0.1.0"
status: skeleton
control_packs: {}
frameworks: []
properties_count: 0
controls_count: 0
```

The manifest says 0 properties, 0 controls, no frameworks and `status: skeleton`. The loaded pack
has 35 properties, 35 controls, one framework (`NIST-800-53`) and version `0.1.0`.

The manifest also advertises `evidence_states: [PASS_STATIC, FAIL_STATIC, UNKNOWN_STATIC,
NOT_APPLICABLE, PASS_LIVE, FAIL_LIVE, UNKNOWN_LIVE, CONFLICT]` - four of which the scan path
cannot emit (section 8.1).

### 9.3 `docs/CLOUD_MODULE_RTM.md:186` - cites a file that does not exist

```
| CM-053 | CloudFormation/SAM/CDK output | 3.1 | `cfn.py` | S09 | Intrinsic-function tests | ✅ |
```

The actual module is `cloud/parsers/cloudformation.py`. There is no `cfn.py` anywhere.

### 9.4 `docs/CLOUD_MODULE_RTM.md:196` - cites a file that does not exist

```
| CM-063 | Secrets scanner runs before parsers; values masked | 3.2, 5.7 | `secrets.py` | S07 | Leak test | ✅ |
```

The actual module is `cloud/secret_scan.py`. There is no `secrets.py` anywhere.

### 9.5 `docs/CLOUD_MODULE_RTM.md:226` - cites a directory that does not exist

```
| CM-091 | External scanners (Checkov, Trivy, optionally KICS/OPA) as independent engines | 7.1 | `cloud/engines/*` | ...
```

There is no `cloud/engines/` directory. The external-engine code is `cloud/scanners.py`, and it
supports Checkov and Trivy only - **not KICS and not OPA** (section 8.4).

### 9.6 `docs/CLOUD_MODULE_RTM.md:132` - S26 marked complete

```
| S26 | 3 | Per-provider, per-resource-family capability matrix (P0-P6) shown in UI | S12 | Matrix generated from t...
```

The RTM marks this row as delivered. The capability matrix is generated from the rule pack, and
section 8.5 shows the matrix has **no entries at all** for NSX-T, Nutanix, vSphere/VMware and
Crossplane. Whether the UI renders that as "no coverage" or "covered" was not exercised here, but
the RTM's completion claim is not supported by the shipped rule set.

**Impact:** Medium. The RTM is the document a reviewer or customer would use to decide what is
built. Six false rows materially overstate readiness.

---

## 10. Secret hygiene, dependency and environment findings

### 10.1 Secret scan of the entire other-dev tree - 0 real leaks

14,549 files scanned (excluding `.git`, `node_modules`, `__pycache__`, `dist`, caches and binary
formats) against 11 credential patterns (AWS key id, AWS secret, PEM private key, GitHub, Slack,
Google API key, Azure storage key, JWT, DigitalOcean, Stripe, GCP `private_key_id`).

**12 raw hits, 0 real leaks.** Every hit was manually inspected:

| File | Hit | Classification |
|---|---|---|
| `cloud/secret_scan.py` | `AKIAIOSFODNN7EXAMPLF` | AWS's own documented example key, used as a skip-list entry |
| `cloud/tests/test_secret_scan.py` (x3) | `AKIAIOSFODNN7EXAMPLF` | test fixture |
| `backend/tests/test_metrics.py:118` | `eyJhbGciOiJIUzI1NiJ9...` | test JWT literal |
| `backend/tests/test_pentest.py:510,544,545` | `-----BEGIN RSA PRIVATE KEY-----` | PEM-header flood strings for a ReDoS/flood test |
| `backend/tests/test_security.py:405` | `-----BEGIN RSA PRIVATE KEY-----` | redaction test fixture |
| `cloud/tests/test_secret_scan.py:148` | `-----BEGIN PRIVATE KEY-----` | flood-string fixture |
| `okf/src/redact.py:58` | `-----BEGIN PRIVATE KEY-----` | the redaction pattern itself |

**Assessment: clean.** No live credential is present in the repository.

### 10.2 `okf/` gateway tests - the online-LLM path is unproven

The six failing `okf` tests are all in `tests/test_gateway.py` and all fail on the same
`OFFLINE: external LLM disabled` guard. No external LLM endpoint is reachable from this
environment (an earlier attempt at `integrate.nvidia.com` failed with
`getaddrinfo ENOTFOUND`).

To close this gap, one of the following is required:

* `ALLOW_EXTERNAL_LLM=true` plus a valid `FEATHERLESS_API_KEY`, or
* `FEATHERLESS_BASE_URL` pointed at a reachable local model, or
* the tests to be refactored to mock the LLM transport so the offline path is still covered.

Until then, **the online-LLM code path in `okf/` has never been observed to pass.**

### 10.3 `models/` - no tests, and two declared dependencies are heavy

* **0** test files, **no** `conftest.py`.
* `models/requirements.txt` declares `hdbscan>=0.8` and `sentence-transformers>=2.0`; both were
  absent in this environment. `hdbscan` was installed for the backend suite and immediately fixed a
  backend test failure (section 3.2) - which shows the missing dependency has **real** consequences
  beyond `models/`.
* `torch`, `xgboost`, `qiskit` and `scikit-learn` were present.

### 10.4 Frontend - `npm audit` reports 2 high severity vulnerabilities

```
metadata.vulnerabilities -> {"info":0,"low":0,"moderate":0,"high":2,"critical":0,"total":2}
```

| Package | Severity | Direct | Advisory summary |
|---|---|---|---|
| `vite` | high | yes | `launch-editor` `escapeCmdArgs()` omits `%` escaping on Windows; `launch-editor` `fs.existsSync()` existence check can be abused on Windows; Vite cross-origin script execution; files outside `server.fs.allow` may be served; first 4 bytes of files outside `server.fs` exposed via `?vite-wasm` |
| `follow-redirects` | high | no (transitive) | array-form `headers` bypasses cross-origin credential stripping; `sensitiveHeaders` regex escaping can expose credential headers; `-realm` `sensitiveHeaders` arrays are discarded and custom credentials can follow redirects |

**Impact:** Low in production (both are dev-server / dev-dependency paths), but the `vite`
Windows `launch-editor` issue is a **local arbitrary-command-execution** vector for a developer
running the dev server on Windows - which is exactly this project's primary environment.

### 10.5 Frontend end-to-end tests cannot run at all

The repository ships a Playwright suite that **cannot be executed**:

* `frontend/playwright.config.ts` exists.
* **12** `*.spec.ts` files exist under `frontend/tests/`.
* `frontend/package.json` scripts are `dev`, `build`, `lint`, `preview` - **there is no `test`
  script**.
* `@playwright/test` is **not** in `devDependencies`.
* `npx playwright` refuses to install:
  `npm error npx canceled due to missing packages and no YES option: ["playwright@1.64.1"]`.

**Impact:** Medium-High. The frontend has **zero executable end-to-end coverage** in this
repository as configured. The 12 spec files are dead weight until the dependency and script are
added.

### 10.6 Required-dependency table

| Component | Declared dependency | Present here? | Effect when missing |
|---|---|---|---|
| `cloud/` | `python-hcl2` | **No** -> installed | 17 collection errors, 0 tests ran |
| `cloud/` | `pyyaml` | **No** -> installed | collection errors |
| `backend/` | `psycopg[binary]` | **No** -> installed | suite refuses to start ("Test database unavailable") |
| `backend/` | `hdbscan>=0.8.44` | **No** -> installed | 1 test failure (silent kmeans fallback) |
| `backend/` | `python-dotenv`, `pyjwt`, `pyyaml`, `reportlab`, `defusedxml` | **No** -> installed | collection errors |
| `backend/` | `sentence-transformers` | **No** | model-embedding paths unproven |
| `models/` | `hdbscan>=0.8` | **No** -> installed | see above |
| `models/` | `sentence-transformers>=2.0` | **No** | model-embedding paths unproven |
| `frontend/` | `@playwright/test` | **No** | e2e suite unrunnable |
| `okf/` | external LLM endpoint | **No** | 6 gateway tests fail (by design) |

---

## 11. What the project does well

The verification was adversarial, and the following properties held every time they were tested.
They are worth recording, because they are the parts that are genuinely hard to get right.

1. **The detection engine works on real files.** All 33 targeted controls were found, through
   both the in-process pipeline and the HTTP endpoint, across Terraform / CloudFormation /
   Kubernetes / ARM / GCP / cloud-init.
2. **Unknown is never treated as pass.** `encrypted = var.encryption_enabled` produced
   `UNKNOWN_STATIC`, and the report statement said the outcome "could not be determined". This is
   the single property that separates a trustworthy scanner from a noisy one, and it holds.
3. **The report never overclaims.** Across every one of the 13 corpus files and every HTTP
   response, the statement contained no instance of "compliant", "certified", "fully secure" or
   "is secure". The `coverage.not_assessed` list explicitly names live cloud state, org-wide
   policies and runtime/image vulnerabilities as not assessed.
4. **Secrets do not leak into the report.** The literal credential was absent from the JSON
   response *and* from all four export formats; only a masked preview, a `[REDACTED]` placeholder
   and a salted HMAC fingerprint survived.
5. **Intake defences hold.** Path traversal rejected with a reason, zip-slip blocked, empty upload
   rejected with "Nothing was assessed", oversize upload 413, module gate 503.
6. **Deterministic.** Re-scanning the same file produced byte-identical findings.
7. **The CIS block is a feature, not a gap.** The loader refuses to publish unverified CIS IDs
   against a licensed edition. That is the correct call and it is enforced in code.
8. **The frontend builds and lints clean.** 0 lint errors; the 9 warnings are all React-hook
   dependency / set-state-in-effect advisories, not defects.
9. **No credentials are committed.** 14,549 files scanned, 0 real leaks.
10. **The other developer's tree was left byte-for-byte untouched** by this verification.

---

## 12. Findings register (consolidated)

| # | Severity | Area | Finding | Reproducible? |
|---|---|---|---|---|
| F-01 | **High** | Detection | `k8s_netpol` misses allow-all NetworkPolicy written as `namespaceSelector: {}` -> `CLOUD-K8S-008 PASS_STATIC` | Yes - `vuln/netpol-nsselector.yaml` |
| F-02 | **High** | Detection | `cloud_init` misses cleartext password under `users[].passwd` -> `CLOUD-INIT-002 PASS_STATIC` | Yes - `vuln/cloud-init-passwd.yaml` |
| F-03 | **Medium** | Secret scan | `SEC-GENERIC` false-positives on `http_tokens = "required"` -> spurious HIGH `CLOUD-SEC-001` on every hardened Terraform | Yes - `secure/main.tf` line 41 |
| F-04 | **High** | CI | `cloud/`, `okf/` and `models/` are never referenced by `.github/workflows/ci.yml`; 475 cloud tests never run in CI | Yes - workflow read |
| F-05 | **Medium** | Docs | `okf-cloud/README.md:7` claims "S01 skeleton, empty" but the pack loads 35 controls / 35 properties / 19 mappings | Yes |
| F-06 | **Medium** | Docs | `okf-cloud/okf_manifest.yaml` reports `properties_count: 0`, `controls_count: 0`, `frameworks: []`, `status: skeleton` | Yes - manifest vs `load_pack()` |
| F-07 | **Low** | Docs | `docs/CLOUD_MODULE_RTM.md:186` cites `cfn.py` (actual: `cloud/parsers/cloudformation.py`) | Yes |
| F-08 | **Low** | Docs | `docs/CLOUD_MODULE_RTM.md:196` cites `secrets.py` (actual: `cloud/secret_scan.py`) | Yes |
| F-09 | **Low** | Docs | `docs/CLOUD_MODULE_RTM.md:226` cites `cloud/engines/*` (actual: `cloud/scanners.py`; KICS/OPA not supported) | Yes |
| F-10 | **Low** | Test | `test_sandbox_profile.py` asserts the `cloud_scan` network membership without `cloud-scheduler` (added in `69ee288`) | Yes - the only failing cloud test |
| F-11 | **Medium** | Capability | Live/connected mode is a 133-line stub with no cloud client and no caller; `PASS_LIVE`/`FAIL_LIVE`/`UNKNOWN_LIVE`/`CONFLICT` are never emitted | Yes - source audit |
| F-12 | **Medium** | Coverage | Only NIST-800-53 is declared, and all 36 framework mappings are `verified: false` | Yes - pack load |
| F-13 | **Medium** | Coverage | NSX-T, Nutanix, vSphere/VMware and Crossplane are recognised but have **zero** resource types with rules | Yes - pack load |
| F-14 | **Low** | Coverage | `cloud/fixtures/` does not exist anywhere | Yes |
| F-15 | **Medium** | Capability | Checkov/Trivy engine code exists but `cloud/service.py` never passes `engines=`; no binaries are bundled; KICS unsupported | Yes - source audit |
| F-16 | **Medium** | Test | Frontend Playwright suite (12 specs) is unrunnable: no `test` script, no `@playwright/test` dependency | Yes - `npm` error |
| F-17 | **Low** | Test | `models/` has 0 test files but declares `pytest>=8.0` | Yes |
| F-18 | **Low** | Security | `npm audit`: 2 high severity (`vite` dev-server, `follow-redirects` transitive) | Yes - `npm audit --json` |
| F-19 | **Low** | Test | `okf/` online-LLM gateway path unproven - 6 tests blocked by the offline guard | Yes - 6 failures |
| F-20 | **Low** | Detection | `http_tokens` absent -> `CLOUD-CMP-001 UNKNOWN_STATIC`, though AWS defaults to IMDSv1 | Yes |

**Counts:** 2 High detection gaps, 1 High CI gap, 3 Medium false-positive/docs, 14 Low/Medium
coverage-and-docs items.

---

## 13. Recommendations, in priority order

### P0 - do first

1. **Add a `cloud` job to `.github/workflows/ci.yml`** (F-04). This is a ~15-line change that puts
   475 tests in front of every pull request and would have caught F-01 and F-02 immediately.
2. **Fix `k8s_netpol` to recognise the `namespaceSelector: {}` allow-all form** (F-01). Add a
   regression test using `vuln/netpol-nsselector.yaml`.
3. **Fix `cloud_init` to inspect `users[].passwd`** (F-02). One-word change; add the matching
   regression test.

### P1 - before any customer-facing claim

4. **Stop describing the product as connected/live** (F-11). Either implement a real cloud client
   or remove `PASS_LIVE` / `FAIL_LIVE` / `UNKNOWN_LIVE` / `CONFLICT` from the advertised
   `evidence_states` and from the UI.
5. **Qualify the framework claim** (F-12). "NIST-800-53, all mappings `verified: false`" is the
   only accurate statement. Say so in the README and the UI.
6. **Correct the six false documentation rows** (F-05 .. F-09). They are cheap to fix and they are
   the rows a reviewer reads first.
7. **Say what is not assessed.** For NSX-T / Nutanix / vSphere / Crossplane (F-13) and for the
   external engines (F-15), the report's `coverage.not_assessed` list should name them, so a
   clean scan is never mistaken for a covered scan.

### P2 - quality of life

8. **Fix the `SEC-GENERIC` false positive** (F-03) - allow-list `http_tokens` and similar
   non-secret Terraform keys.
9. **Update the stale compose assertion** (F-10).
10. **Make the frontend e2e suite runnable** (F-16): add `@playwright/test` to `devDependencies`
    and a `test:e2e` script.
11. **Give `models/` a test suite** (F-17), or remove the `pytest` declaration.
12. **Ship `cloud/fixtures/`** (F-14) so the corpus used in this report becomes a reusable asset.
13. **Update `npm audit` findings** (F-18) - at minimum pin `vite` to a fixed version.

---

## 14. Reproduction appendix

All harnesses, corpora and raw outputs are on the **F:** drive. The other developer's tree was
never modified.

### 14.1 Artefacts

| Path | What it is |
|---|---|
| `F:\ORBIT_OTHER_DEV_FULL_VERIFICATION.md` | this report |
| `F:\opencode_tmp\od_corpus.py` | the 13-file vulnerable/hardened corpus |
| `F:\opencode_tmp\od_functional.py` | the 94-check functional harness |
| `F:\opencode_tmp\od_functional_out.txt` | its output (94/94) |
| `F:\opencode_tmp\od_http.py` | the 21-check HTTP upload + export harness |
| `F:\opencode_tmp\od_http_out.txt` | its output (21/21) |
| `F:\opencode_tmp\od_cloud_final.txt` | cloud suite output (474 passed, 1 failed) |
| `F:\opencode_tmp\od_backend2.txt` | backend suite output (658 passed, 2 failed) |
| `F:\opencode_tmp\od_backend_final.txt` | backend final re-run output |
| `F:\opencode_tmp\od_okf_final.txt` | okf suite output (6 failed) |
| `F:\opencode_tmp\od_claims3_out.txt` | live-mode / framework / CIS / engine / vendor claim audit |
| `F:\opencode_tmp\od_inventory_out.txt` | sub-project inventory |
| `F:\opencode_tmp\od_secret_tree_out.txt` | whole-tree secret scan |
| `F:\opencode_tmp\fe_build.txt` | frontend build output |
| `F:\opencode_tmp\fe_lint.txt` | frontend lint output |
| `F:\opencode_tmp\fe_audit.json` | `npm audit --json` |
| `F:\opencode_tmp\od_cloud_venv` | venv with `python-hcl2` + `pyyaml` |
| `F:\opencode_tmp\od_backend_venv` | venv with the backend deps incl. `hdbscan` |
| `F:\opencode_tmp\fe_verify` | isolated frontend copy (build/lint/audit) |

### 14.2 Commands

```powershell
# Cloud suite
$py = "F:\opencode_tmp\od_cloud_venv\Scripts\python.exe"
cd "C:\collector\other dev\Orbit-Multi-Vendor-Security\cloud"
& $py -m pytest -p no:cacheprovider --tb=no -q

# Functional test against real vulnerable files
& $py "F:\opencode_tmp\od_functional.py"

# HTTP upload + export test
& $py "F:\opencode_tmp\od_http.py"

# Backend suite (needs the disposable pgvector container on :55432)
wsl -d CollectorDocker -u root -- docker run -d --name auditor-test-pg --restart unless-stopped `
  -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=auditor_test -p 55432:5432 pgvector/pgvector:pg16
$py = "F:\opencode_tmp\od_backend_venv\Scripts\python.exe"
cd "C:\collector\other dev\Orbit-Multi-Vendor-Security\backend"
& $py -m pytest -p no:cacheprovider --tb=line -q

# OKF suite
cd "C:\collector\other dev\Orbit-Multi-Vendor-Security\okf"
python -m pytest -p no:cacheprovider --tb=no -q

# Frontend (in the isolated copy)
cd "F:\opencode_tmp\fe_verify"
npm ci ; npm run build ; npm run lint ; npm audit --json

# Integrity check - must always be empty
git -C "C:\collector\other dev\Orbit-Multi-Vendor-Security" status --porcelain
```

### 14.3 Minimal reproductions for the three defects

**F-01** - save as `netpol.yaml` and upload:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ns
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 80
```

Expected (correct) behaviour: `CLOUD-K8S-008 FAIL_STATIC`.
Observed behaviour: `CLOUD-K8S-008 PASS_STATIC`.

**F-02** - save as `cloud-init.yaml` and upload:

```yaml
#cloud-config
users:
  - name: deploy
    lock_passwd: false
    passwd: "Sup3rS3cret!Pass"
    sudo: "ALL=(ALL) NOPASSWD:ALL"
ssh_pwauth: true
```

Expected (correct) behaviour: `CLOUD-INIT-002 FAIL_STATIC`.
Observed behaviour: `CLOUD-INIT-002 PASS_STATIC`.
(The same file with `plain_text_passwd:` instead of `passwd:` **is** correctly flagged.)

**F-03** - save as `main.tf` and upload:

```hcl
resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}
```

Expected (correct) behaviour: no findings.
Observed behaviour: one HIGH `CLOUD-SEC-001` "hard-coded credential", preview `re***(8)`.

---

## 15. Honest limitations of this verification

Stated explicitly so the report is not read as claiming more than it proves.

1. **No live cloud assessment was performed** - none is possible: the module has no cloud client
   (section 8.1).
2. **No licensed benchmark was compared against.** All 36 framework mappings are `verified: false`
   in the source itself, so this verification could not confirm any framework correspondence.
3. **The online-LLM path in `okf/` was never observed to pass** (section 10.2).
4. **The frontend e2e suite was never executed** - it cannot be executed as configured
   (section 10.5).
5. **The backend suite ran without `sentence-transformers`**, so any code path that depends on
   model embeddings is unproven here.
6. **`models/` was not functionally tested** - it has no tests, and its heavy dependencies
   (`sentence-transformers`) were not installed.
7. **The external engines (Checkov / Trivy) were never executed** - no binaries are bundled and
   the service never enables them.
8. **The container image was not built and run.** The cloud scanner was exercised in-process and
   through the real FastAPI app on the host, not through `cloud/Dockerfile`. The compose-network
   membership assertion that failed (F-10) was checked by reading the compose file, not by
   running the stack.
9. **The `frontend/` build was performed on a copy**, not in the source tree, deliberately, so the
   read-only guarantee could be kept. The build inputs were byte-identical to the source.
10. **This report does not assess the collector project** (`C:\collector` itself), which was
    verified separately.

---

## 16. Final authoritative backend re-run

The final authoritative re-run of the backend suite was executed with `hdbscan>=0.8.44`
installed (the dependency that caused the one real failure in the first run):

```
$ cd backend && python -m pytest -p no:cacheprovider --tb=line -q
660 passed, 526 warnings in 1138.44s (0:18:58)
exit code: 0
```

**Result: 660 passed, 0 failed.**

This confirms that neither of the two failures seen in the earlier run was a product defect:

| Earlier failure | Status in the authoritative run |
|---|---|
| `test_coverage.py::test_integration_m2_m7_branches` (missing `hdbscan`) | **PASS** - the declared dependency was installed |
| `test_pentest.py::test_unknown_user_and_wrong_password_cost_the_same` (load-sensitive timing) | **PASS** - the timing assertion holds when the suite is not competing with other CPU-heavy work |

The 526 warnings are `InsecureKeyLengthWarning` from PyJWT (short HMAC test keys), a
`StarletteDeprecationWarning` about `httpx` vs `httpx2`, a scikit-learn
`InconsistentVersionWarning` about unpickling an estimator across 1.9.0/1.9.1, and a
`RuntimeWarning` from `runpy` in the CLI-entry-point test. None of them is a test failure.

**The backend module is fully green: 660 / 660.**

---

## 17. Consolidated scorecard

| Suite | Collected | Passed | Failed | Verdict |
|---|---:|---:|---:|---|
| `cloud/` unit tests | 475 | 474 | 1 | **Green** - the 1 failure is a stale assertion (F-10) |
| `cloud/` functional test (real vulnerable files) | 94 checks | 94 | 0 | **Green** |
| `cloud/` HTTP upload + export test | 21 checks | 21 | 0 | **Green** |
| `backend/` unit + integration tests | 660 | 660 | 0 | **Green** |
| `okf/` unit tests | 75 | 69 | 6 | **Amber** - all 6 are the offline-LLM guard (F-19) |
| `models/` | 0 | - | - | **Not tested** - no tests exist (F-17) |
| `frontend/` build | - | - | - | **Green** - exit 0 |
| `frontend/` lint | - | - | 0 errors | **Green** - 9 warnings |
| `frontend/` e2e (Playwright) | 12 specs | - | - | **Not runnable** (F-16) |
| `other dev/` secret scan | 14,549 files | - | - | **Green** - 0 real leaks |

**Overall:** the project is **functionally sound and honest in its reporting**, with three
reproducible detection/secret-scan defects, a CI configuration that would have caught two of
them, and six documentation rows that overstate what is built. The P0 recommendations in
section 13 are small, well-scoped changes with high leverage.

---

*Report generated 2026-11-03 by independent verification of the other developer's project.
The other developer's working tree was not modified at any point (`git status --porcelain`
empty, HEAD `69ee288`, confirmed after every test).*
