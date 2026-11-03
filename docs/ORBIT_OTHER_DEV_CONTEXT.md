# Context file - verification of the other developer's project

**Purpose:** a complete handoff document. Feed this to a fresh session and it has everything it
needs to continue the work without re-deriving anything.

**Prepared:** 2026-11-03
**Subject project:** `C:\collector\other dev\Orbit-Multi-Vendor-Security` at commit `69ee288`
**Reviewer:** an independent agent (not the original author of that project)

---

## 0. Read this first - the three hard constraints

1. **The other developer's tree is READ-ONLY.** Never edit, never write, never `git apply` into
   `C:\collector\other dev\`. Every fix must be produced in a scratch copy on `F:` and handed
   over as a patch file. `git -C "C:\collector\other dev\Orbit-Multi-Vendor-Security" status --porcelain`
   must print **nothing** at all times.
2. **All scratch work goes on `F:`.** `C:` was down to ~0.49 GB free at the time of writing.
   The `F:` drive holds every venv, every copy of the repo, and every output.
3. **Never claim a pass without observed output.** Every number in the report and in this file
   came from a run whose stdout is captured in `outputs/`. Do not paraphrase; quote.

---

## 1. What the job was

1. **Functionally verify** the whole `Orbit-Multi-Vendor-Security` project - not just `cloud/` -
   by uploading **real** vulnerable and misconfigured cloud files and checking that the detection
   logic actually fires.
2. **Document** everything in a comprehensive `.md` report on the **F: drive**.
3. **Produce a shareable ZIP** for the other developer containing all the test data and all
   generated data he may not have (corpus, harnesses, raw outputs, ready-to-apply fixes).

All three are **done**.

---

## 2. Where everything is

### 2.1 Deliverables (the things to hand over)

| Path | What |
|---|---|
| `F:\ORBIT_OTHER_DEV_VERIFICATION_2026-11-03.zip` | **the shareable package** - 119,822 bytes, 43 files |
| `F:\ORBIT_OTHER_DEV_FULL_VERIFICATION.md` | **the full report** - 62,966 bytes, 17 sections |
| `F:\ORBIT_OTHER_DEV_CONTEXT.md` | this file |
| `F:\opencode_tmp\pkg\ORBIT_OTHER_DEV_VERIFICATION_2026-11-03\` | the unpacked staging folder for the ZIP |

### 2.2 Package layout (43 files)

```
ORBIT_OTHER_DEV_VERIFICATION_2026-11-03/
├── README.md          what's inside, how to run it, honest limitations
├── FINDINGS.md        20 findings triaged, with reproducers
├── ENVIRONMENT.md     versions, venv recipes, pgvector container, WSL keeper
├── REPORT.md          the full 17-section verification report
├── corpus/            14 real cloud files + corpus.zip + EXPECTED.md
├── harnesses/         od_corpus.py, od_functional.py, od_http.py, run_all.py, requirements.txt
├── outputs/           12 raw evidence files (4 junit XMLs + 2 CI-job validation logs)
└── proposed_fixes/    F-01..F-10 patches + ALL-FIXES-combined.patch + ci-cloud-job.yml + README.md
```

### 2.3 Scratch tooling on `F:\opencode_tmp`

| Path | What |
|---|---|
| `od_cloud_venv\` | venv for the cloud module (`--system-site-packages` + `python-hcl2`, `pyyaml`) |
| `od_backend_venv\` | venv for the backend (`--system-site-packages` + `psycopg[binary]`, `python-dotenv`, `pyjwt`, `pyyaml`, `reportlab`, `defusedxml`, `hdbscan>=0.8.44`) |
| `od_corpus.py` | **source of truth** for the 14-file corpus (Python constants) |
| `od_functional.py` | working copy of the functional harness |
| `pkg_od_functional.py` | the packaged harness that shipped (has `EXPECT_FIXES` / `ORBIT_REPO` switches) |
| `od_http.py` | the HTTP upload + export harness |
| `od_verify_patches.py` | applies the 4 patches to a pristine copy and re-runs the suites |
| `od_gen_patches2.py` | generates the patches as an **apply-in-order chain** |
| `od_gen_combined.py` | generates + verifies `ALL-FIXES-combined.patch` |
| `od_regen_outputs.py` | regenerates every captured output as UTF-8 |
| `od_check_pkg.py` | final package consistency checker |
| `od_make_zip.py` | builds + verifies the ZIP by reading it back |
| `od_ziptest.py` | extracts the ZIP to a fresh dir and runs it end-to-end |
| `patchverify\repo\` | patched copy used for verification (git repo, 4 patches applied) |
| `patchtest\repo\` | patched copy used to author the patches |
| `comboverify\repo\` | pristine copy used to verify the combined patch |
| `civerify2\repo\` | full pristine copy used to validate the CI job commands |
| `fe_verify\` | isolated frontend copy (build / lint / audit) |

### 2.4 Host

| Item | Value |
|---|---|
| OS | Windows (win32), PowerShell |
| Python | 3.12.10 |
| pytest | 9.1.1 |
| Node / npm | v24.18.0 / 12.0.1 |
| uv | 0.12.17 (CPython 3.13.15 via uv, pytest 9.2.0) |
| Test DB | `pgvector/pgvector:pg16` container `auditor-test-pg` on `localhost:55432` |

---

## 3. Results (all observed)

| Suite | Collected | Passed | Failed | Notes |
|---|---:|---:|---:|---|
| `cloud/` unit tests, pristine | 475 | 474 | **1** | the one failure is a stale assertion (F-10) |
| `cloud/` unit tests, **patched** | 475 | **475** | **0** | 19.6 s, junit-verified |
| Functional harness, pristine | 99 | 99 | 0 | asserts the gaps are present |
| Functional harness, **patched** | 99 | 99 | 0 | asserts the gaps are closed, zero FPs |
| HTTP upload + export | 21 | 21 | 0 | 82 findings, 33 controls, 4 export formats |
| `backend/` unit tests | 660 | 660 | 0 | 906 s (0:15:06) |
| `okf/` unit tests | 75 | 69 | **6** | all 6 blocked by the offline-LLM guard |
| `frontend/` build | - | pass | 0 | 62 files, 1,155,015 B, 2.65 s |
| `frontend/` lint | - | pass | 0 errors | 9 warnings |
| `npm audit` | - | - | **2 high** | `vite` (direct), `follow-redirects` (transitive) |
| Whole-tree secret scan | 14,549 files | 0 real leaks | - | 12 raw hits, all fixtures |
| `models/` | 0 test files | - | - | no `conftest.py`; `pytest>=8.0` declared anyway |

### 3.1 The three functional defects

| ID | Severity | What | Current | After patch |
|---|---|---|---|---|
| **F-01** | High | `k8s_netpol` misses an allow-all NetworkPolicy written as `namespaceSelector: {}` with **no** `ports` restriction | `CLOUD-K8S-008 PASS_STATIC` | `FAIL_STATIC` |
| **F-02** | High | `cloud_init` misses a clear-text password under `users[].passwd` | `CLOUD-INIT-002 PASS_STATIC` | `FAIL_STATIC` |
| **F-03** | Medium | `SEC-GENERIC` false-positives on `http_tokens = "required"` -> spurious HIGH `CLOUD-SEC-001` | 1 FP on every hardened TF | 0 findings |

Plus **F-10** (Low): the one failing cloud test - a stale compose-network assertion.

> **Important nuance on F-01.** The control is *"NetworkPolicies must not allow all traffic to
> all pods"*. A policy that restricts `ports` is **not** "all traffic", so flagging it would
> itself be a false positive. The corpus carries **both** forms as a regression pair:
> `vuln/netpol-nsselector.yaml` (no ports - must fail) and `secure/netpol-port-scoped.yaml`
> (port-scoped - must stay clean). The first draft of the report used the port-scoped file as
> the gap probe; that was imprecise and was corrected.

### 3.2 The 20 findings

Full detail in `FINDINGS.md` / `REPORT.md` section 12.

| # | Sev | Area | One-line |
|---|---|---|---|
| F-01 | High | Detection | allow-all NetworkPolicy via `namespaceSelector: {}` missed |
| F-02 | High | Detection | clear-text cloud-init password via `users[].passwd` missed |
| F-03 | Medium | Secret scan | `http_tokens` false positive |
| F-04 | High | CI | `cloud/`, `okf/`, `models/` never run in CI (475 tests) |
| F-05 | Medium | Docs | `okf-cloud/README.md:7` says "S01 skeleton, empty" - pack has 35 controls |
| F-06 | Medium | Docs | `okf_manifest.yaml` reports all-zero counters |
| F-07 | Low | Docs | RTM cites `cfn.py` (actual `cloud/parsers/cloudformation.py`) |
| F-08 | Low | Docs | RTM cites `secrets.py` (actual `cloud/secret_scan.py`) |
| F-09 | Low | Docs | RTM cites `cloud/engines/*` (actual `cloud/scanners.py`) |
| F-10 | Low | Test | stale compose-network assertion - the only failing cloud test |
| F-11 | Medium | Capability | live/connected mode is a 133-line stub; no cloud client, no caller |
| F-12 | Medium | Coverage | only NIST-800-53 declared; all 36 mappings `verified: false` |
| F-13 | Medium | Coverage | NSX-T, Nutanix, vSphere/VMware, Crossplane have zero rules |
| F-14 | Low | Coverage | `cloud/fixtures/` does not exist |
| F-15 | Medium | Capability | Checkov/Trivy code exists but `engines=` is never passed |
| F-16 | Medium | Test | 12 Playwright specs, no `test` script, no `@playwright/test` |
| F-17 | Low | Test | `models/` has 0 test files but declares `pytest>=8.0` |
| F-18 | Low | Security | `npm audit`: 2 high severity |
| F-19 | Low | Test | `okf/` online-LLM gateway path unproven (6 blocked tests) |
| F-20 | Low | Detection | `http_tokens` absent -> `UNKNOWN_STATIC`, though AWS defaults to IMDSv1 |

### 3.3 What was deliberately NOT called a defect

| Observation | Why it is correct |
|---|---|
| One SG with `0.0.0.0/0` on all ports raises `CLOUD-NET-001..005` | five distinct true positives, not duplicate FPs |
| `encrypted = var.encryption_enabled` -> `UNKNOWN_STATIC` | the engine refuses to guess; UNKNOWN is never PASS |
| `http_tokens` absent -> `UNKNOWN_STATIC` (F-20) | same rule |
| CIS deliberately blocked | correct - it does not claim CIS coverage |
| zip entry `../escape.tf` rejected with reason `path traversal` | the intake defence works |

---

## 4. The 14-file corpus

Source of truth: `F:\opencode_tmp\od_corpus.py`. Shipped: `corpus/` (standalone files) +
`corpus/corpus.zip` + `corpus/EXPECTED.md` (observed verdict for every file).

| File | Format | Required controls |
|---|---|---|
| `vuln/main.tf` | Terraform | 12 controls (NET/STO/IAM/DB/CMP/LOG) |
| `secure/main.tf` | Terraform | none - the hardened control (FP probe) |
| `vuln/cfn.yaml` | CloudFormation | STO-001, NET-001, DB-001, DB-002 |
| `vuln/pod.yaml` | Kubernetes | K8S-001..007, 009, 010, 011 |
| `vuln/rbac.yaml` | Kubernetes | K8S-012, 013, 014 |
| `vuln/netpol-allowall.yaml` | Kubernetes | K8S-008 (literal empty-rule form - detected) |
| `vuln/netpol-nsselector.yaml` | Kubernetes | **F-01 gap file** - must fail after the fix |
| `secure/netpol-port-scoped.yaml` | Kubernetes | **must stay clean** - false-positive control |
| `vuln/arm.json` | Azure ARM | NET-004, STO-001, STO-003, STO-004 |
| `vuln/gcp.tf` | Terraform (GCP) | NET-004, IAM-001, STO-001 |
| `vuln/cloud-init-plain.yaml` | cloud-init | INIT-001..004 (002 detected) |
| `vuln/cloud-init-passwd.yaml` | cloud-init | **F-02 gap file** - 002 must fail after the fix |
| `vuln/secret.tf` | Terraform | SEC-001 (secret must never leak into the report) |
| `unknown/volume.tf` | Terraform | none - the UNKNOWN-not-PASS probe |

Scanning the corpus as one bundle: 33 controls detected, 32 resources, 14/14 files accepted,
4 providers (`aws`, `kubernetes`, `azure`, `gcp`), 5 formats, 58 violations.

---

## 5. The harnesses

| Harness | Checks | What it proves |
|---|---:|---|
| `od_functional.py` | 99 | per-file status/mode, required controls fail, no unexplained failures, statement never claims compliance, UNKNOWN != PASS, secret masking + salted fingerprint + `[REDACTED]`, determinism, empty-upload refusal, zip-slip defence, bundle coverage |
| `od_http.py` | 21 | `/healthz` 200, `/scan` 200 for zip and raw, module gate 503, oversize 413, exports json/csv/sarif/pdf all 200, PDF magic `%PDF-1.4`, unknown export 404, credential absent from every response |
| `run_all.py` | - | runs both, in both modes, prints one table, auto-detects patched vs unpatched |

### 5.1 The two environment switches

| Variable | Meaning |
|---|---|
| `ORBIT_REPO` | the checkout to test (default `C:\collector\other dev\Orbit-Multi-Vendor-Security`) |
| `EXPECT_FIXES` | `0` = assert the CURRENT behaviour (gaps present, FP present). `1` = assert the behaviour AFTER the patches (gaps closed, zero FPs) |

The two modes are mutually exclusive by construction, which is how `run_all.py` tells a patched
tree from an unpatched one.

```powershell
cd <package>\harnesses
$env:ORBIT_REPO = "C:\path\to\Orbit-Multi-Vendor-Security"
python run_all.py                      # auto-detect
python run_all.py --expect unpatched   # require the gaps
python run_all.py --expect patched     # require the fixes
```

---

## 6. The patches

**Apply order matters.** F-01 and F-02 both edit `cloud/rules/extractors.py`, so the four patches
are a chain of consecutive-state diffs.

| # | Patch | File | Fixes |
|---|---|---|---|
| 1 | `F-01-k8s-netpol-allow-all.patch` | `cloud/rules/extractors.py` | F-01 |
| 2 | `F-02-cloud-init-passwd-key.patch` | `cloud/rules/extractors.py` | F-02 |
| 3 | `F-03-secret-scan-http-tokens-false-positive.patch` | `cloud/secret_scan.py` | F-03 |
| 4 | `F-10-stale-compose-network-assertion.patch` | `cloud/tests/test_sandbox_profile.py` | F-10 |

`ALL-FIXES-combined.patch` is the same four fixes as one diff, verified to produce a tree
**byte-identical** to the chain.

```powershell
git apply --check <patch>; git apply <patch>
```

### 6.1 Source locations of the defects

| Finding | Location |
|---|---|
| F-01 | `cloud/rules/extractors.py`, `k8s_netpol()` ~L755-761 |
| F-02 | `cloud/rules/extractors.py`, `cloud_init()` ~L789-803 |
| F-03 | `cloud/secret_scan.py` - `SEC-GENERIC` regex L58-60, `_generic_skip()` L80-87 |
| F-10 | `cloud/tests/test_sandbox_profile.py` L35 |
| F-04 | `.github/workflows/ci.yml` - only `backend` and `frontend` working dirs |

### 6.2 The CI job

`proposed_fixes/ci-cloud-job.yml` is a ready-to-paste `cloud:` job:

```yaml
  cloud:
    name: Cloud module tests
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@v7
        with:
          enable-cache: true
          cache-dependency-glob: cloud/uv.lock
      - name: Install locked dependencies
        working-directory: cloud
        run: uv sync --frozen
      - name: Tests
        working-directory: cloud
        run: uv run pytest -q
```

**Validated locally with those exact commands:** pristine -> `1 failed, 474 passed`;
patched -> `475 passed`, exit 0. Logs in `outputs/ci_job_validation_*.txt`.

**Caveat:** the cloud tests read two files *outside* `cloud/` - `okf-cloud/okf_manifest.yaml`
and `docker-compose.cloud.yml` - so the job must run against a full checkout.

---

## 7. How the work was actually done (method)

### 7.1 Verification layers

1. **Unit suites** - `pytest` on `cloud/`, `backend/`, `okf/`, with `--junit-xml` so the counts
   are machine-verified rather than parsed off a piped summary line.
2. **Functional** - 14 real files pushed through `cloud.pipeline.run_scan()`.
3. **HTTP** - the real FastAPI app (`cloud/service.py`) driven with `fastapi.testclient.TestClient`.
4. **Secret hygiene** - whole-tree scan of 14,549 files.
5. **Frontend** - `npm ci`, `npm run build`, `npm run lint`, `npm audit --json` in an isolated copy.
6. **Integrity** - `git status --porcelain` before, during and after.

### 7.2 Frontend isolation

The frontend was built in a **copy** at `F:\opencode_tmp\fe_verify`, never in the source tree,
so `node_modules/` and `dist/` could not dirty the read-only checkout.

### 7.3 Patch verification loop

1. copy the pristine tree to `F:\opencode_tmp\patchtest\repo`
2. apply the edits by hand in that copy
3. run the cloud suite + functional + HTTP there
4. generate the patches as a **chain** (`od_gen_patches2.py`) - the first attempt generated each
   patch against the *fully patched* file and F-02 would not apply on top of F-01
5. `od_verify_patches.py` applies the chain to a fresh pristine copy and re-runs everything
6. `od_gen_combined.py` produces the all-in-one and proves it matches the chain byte-for-byte

### 7.4 Package verification loop

1. `od_check_pkg.py` - corpus vs `od_corpus.py`, zip contents, harness identity, every documented
   file present, expected totals present in the outputs
2. `od_make_zip.py` - build the zip, re-read it, `testzip()`, entry-set match, byte-equal content
3. `od_ziptest.py` - extract to a **fresh directory** and run `run_all.py` from there against both
   the pristine and the patched tree

---

## 8. Gotchas that cost time (do not rediscover these)

| Gotcha | What to do |
|---|---|
| PowerShell heredoc payloads get mangled | write scripts with the `write` tool and always read the file back to confirm |
| Shell paths get mangled occasionally | put the path inside a Python script instead of on the command line |
| `shutil.rmtree` on a git working copy fails with `WinError 5` (read-only `.git/objects`) | use `shutil.rmtree(p, onerror=...)` with an `os.chmod(path, 0o700)` handler |
| `piped` pytest summary lines are lossy on Windows | always use `--junit-xml` and read the counts from the XML |
| The Docker daemon is inside WSL; the distro reboots when the last client detaches and kills every container | keep a keeper alive: `wsl -d CollectorDocker -u root -- sleep infinity` |
| The `okf` gateway tests need `ALLOW_EXTERNAL_LLM=true` plus a reachable LLM endpoint | no external LLM was reachable (`getaddrinfo ENOTFOUND integrate.nvidia.com`) |
| The cloud tests read files outside `cloud/` | any isolated copy must also contain `okf-cloud/` and `docker-compose.cloud.yml` |
| `npx playwright` refuses to install | `npm error npx canceled due to missing packages and no YES option` |
| Files written by PowerShell `Set-Content -Encoding UTF8` get a BOM | strip it before shipping |

---

## 9. Open items / what could be done next

Nothing in the original brief is outstanding. If more work is wanted:

1. **Apply the four patches into the other dev's tree** - not done on purpose; that is his call.
2. **Add the CI job** - `proposed_fixes/ci-cloud-job.yml`, validated, ready to paste.
3. **Ship `cloud/fixtures/`** (F-14) - the corpus in the package is the natural fixture set, and
   the repo has no fixtures directory. This would close F-14 and make the corpus permanent.
4. **Add regression tests** for F-01/F-02/F-03/F-10 in the repo's own suite - the harness already
   asserts all four, in both directions. See `proposed_fixes/README.md` §5.
5. **Unverified areas that could be closed with more infrastructure:**
   - `okf/` online-LLM gateway path (needs a reachable LLM endpoint)
   - `models/` (needs a test suite written; `sentence-transformers` not installed)
   - frontend e2e (needs `@playwright/test` + a `test:e2e` script)
   - backend embedding paths (needs `sentence-transformers`)
6. **Re-verify the whole thing** once the patches land upstream - the harnesses make this a
   two-minute job via `run_all.py --expect patched`.

---

## 10. Integrity statement (re-verify at any time)

```powershell
git -C "C:\collector\other dev\Orbit-Multi-Vendor-Security" status --porcelain
# -> must print NOTHING

git -C "C:\collector\other dev\Orbit-Multi-Vendor-Security" rev-parse --short HEAD
# -> 69ee288
```

**Last observed (2026-11-03):** status empty, HEAD `69ee288`. The other developer's tree was
never modified, and no commit was made in it.

For reference, the **reviewer's own** repo `C:\collector` is at commit `5ea388a`
("Parser fixes, live REST/RESTCONF lab, dependency declarations and work status") and is clean.
That commit is **unrelated** to the other developer's project - it is the reviewer's own work.

---

## 11. One-paragraph summary for a new session

> The other developer's `Orbit-Multi-Vendor-Security` (commit `69ee288`) was functionally
> verified end-to-end without ever being modified: 475 cloud tests, a 99-check functional test
> against 14 real vulnerable cloud files, and a 21-check HTTP test against the real FastAPI
> service, plus the backend (660), okf (69/75), and frontend suites. Three genuine defects were
> found and patched - two detection gaps (an allow-all Kubernetes NetworkPolicy written as
> `namespaceSelector: {}` with no `ports` restriction, and a clear-text cloud-init password
> written as `users[].passwd`) and one false positive (`http_tokens = "required"` reported as a
> hard-coded secret) - and all four patches (including the stale compose-network assertion) were
> applied to a pristine copy and re-verified, taking the cloud suite to **475/475** and the
> functional harness to **99/99 with the gap assertions inverted**. The highest-leverage fix is
> not a code change: `cloud/`, `okf/` and `models/` are never referenced by
> `.github/workflows/ci.yml`, so 475 tests never run in CI - that is why these gaps survived.
> Everything is packaged at `F:\ORBIT_OTHER_DEV_VERIFICATION_2026-11-03.zip` (43 files: corpus,
> harnesses, raw outputs, patches, CI job) with the full 17-section report at
> `F:\ORBIT_OTHER_DEV_FULL_VERIFICATION.md`.
