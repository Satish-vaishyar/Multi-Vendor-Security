# Independent verification - fixes, tests and results (2026-11-03)

Inputs: `docs/ORBIT_OTHER_DEV_FULL_VERIFICATION.md` (tester's report, 20 findings), `docs/ORBIT_OTHER_DEV_CONTEXT.md`,
the verification package (corpus, harnesses, proposed patches) and `ORBIT_CLOUD_TPFP_DATASET_PACKAGE` (169 labelled
TP/FP/TN/FN cases). Baseline: commit `69ee288`.

## Status of every finding

| ID | Finding | Status | Where |
|---|---|---|---|
| F-01 | allow-all NetworkPolicy via `namespaceSelector: {}` missed | **Fixed** | `cloud/rules/extractors.py` `_netpol_rule_allows_all` (port-scoped policies stay clean) |
| F-02 | clear-text `users[].passwd` missed | **Fixed** | `extractors.py` `_clear_passwd`; crypt hashes (`$6$...`) are *not* flagged |
| F-03 | `http_tokens = "required"` flagged as a secret | **Fixed, wider than proposed** | `cloud/secret_scan.py`: key allow-list + token-setting suffixes (`_audience`, `_ttl`, ...) + crypt-hash skip |
| F-04 | cloud tests never run in CI | **Fixed** | new `cloud` job in `.github/workflows/ci.yml` (runs the 100 % coverage gate) |
| F-05 | `okf-cloud/README.md` said "skeleton, empty" | **Fixed** | README |
| F-06 | manifest all-zero counters | **Fixed** | `okf-cloud/okf_manifest.yaml`; live states moved to `reserved_evidence_states`; test keeps it in sync with the pack |
| F-07..F-09 | RTM cited non-existent files | **Fixed** | `docs/CLOUD_MODULE_RTM.md` (also 25 -> 35 controls) |
| F-10 | stale compose-network assertion | **Fixed** | `cloud/tests/test_sandbox_profile.py` |
| F-11 | live mode is a stub | **Documented** (not implemented) | manifest + README now say the *_LIVE states are reserved |
| F-12 | only NIST-800-53, all `verified: false` | **Documented** | README, manifest |
| F-13 | NSX-T/Nutanix/vSphere have no rules | **Mitigated** | scans now list `vmware: recognised, but this rule pack has no vmware rules` in `coverage.not_assessed` (`cloud/pipeline.py`) |
| F-14 | no `cloud/fixtures/` | **Fixed** | `cloud/fixtures/` + `tests/test_fixture_corpus.py` |
| F-15 | Checkov/Trivy never invoked | **Documented** (RTM CM-091) | needs a product decision |
| F-16 | Playwright specs unrunnable | **Fixed** | `@playwright/test` devDependency + `test:e2e` script (browsers still need `npx playwright install`) |
| F-17 | `models/` has no tests | Open | out of scope for this change |
| F-18 | `npm audit` 2 high | **Fixed** | lockfile regenerated; `npm audit` reports 0 vulnerabilities |
| F-19 | okf gateway tests need a real key | **Fixed** | `okf/tests/conftest.py` injects a dummy key (HTTP is mocked) -> 75/75 |
| F-20 | `http_tokens` absent -> UNKNOWN | By design | unchanged |

## New issues found while verifying the fixes

1. The proposed F-02 patch flagged **hashed** `passwd: "$6$..."` values (a false positive the TP/FP dataset exposed:
   case `INIT-002-06-passwd-hash`). Fixed: hashes are recognised, kept out of secret redaction and marked `[HASHED]`
   by the cloud-init parser so the extractor can tell hash from clear text.
2. The proposed F-03 patch only covered `http_tokens`; the dataset showed the same false positive on
   `id_token_audience = "openid-connect"` and `session_token_ttl = "15-minutes"`. Fixed via the suffix list. A real
   secret (`auth_token = "..."`, `password = "..."`) is still reported (tests assert this).
3. Enabling the CI job exposed that the cloud package enforces `fail_under = 100`; the new code is fully covered.

## Test evidence (observed 2026-11-03)

| Suite | Before | After |
|---|---|---|
| `cloud/` unit tests | 474 pass / 1 fail | **502 pass / 0 fail, coverage 100 %** |
| Verification functional harness (`EXPECT_FIXES=1`) | n/a | 99 / 99 |
| Verification HTTP harness | 21 / 21 | 21 / 21 |
| TP/FP dataset (169 cases) | TP 110, FP 5, FN 2, P 0.957, R 0.982 | **TP 112, FP 0, FN 0, TN 410, TUNK 41, P = R = F1 = 1.000** |
| `okf/` | 69 / 75 | **75 / 75** |
| `frontend` `npm ci`, lint, build | pass, 2 high advisories | pass (0 lint errors), 0 advisories |

Not re-run: the `backend/` suite (660 green in the tester's run; it does not import `cloud/` code, the cloud service
runs in its own container) and the Playwright e2e specs (need browsers + a running backend).

## Reproduce

```bash
cd cloud && uv sync --frozen && uv run pytest -q --cov
ORBIT_REPO=<repo> EXPECT_FIXES=1 python ORBIT_OTHER_DEV_VERIFICATION_2026-11-03/harnesses/od_functional.py
ORBIT_REPO=<repo> python ORBIT_CLOUD_TPFP_DATASET_PACKAGE/dataset/harnesses/od_tpfp_runner.py   # run on a copy: it writes results/
```

## Observations left for the owner

* A CloudFormation template saved with a `.tf` extension is parsed as Terraform and silently yields 0 resources.
* External engines (Checkov/Trivy) are still not enabled by `cloud/service.py`; live mode is not implemented.
* The large verification/dataset packages are kept untracked locally (90 MB, they embed AWS's published example key).
