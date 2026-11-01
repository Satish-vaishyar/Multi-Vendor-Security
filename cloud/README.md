# cloud/ - Orbit cloud assessment module (scanner side)

Status: **in progress** (S01-S11 done, S12 under way). Plan, traceability and the live progress log:
`../docs/CLOUD_MODULE_RTM.md`; requirements: `../docs/CLOUD_PROVIDER_SECURITY_ASSESSMENT_CATALOG.md`.

## What exists
| Module | Purpose |
|---|---|
| `flags.py` | `CLOUD_MODULE_ENABLED` feature flag, fail-closed (off unless exactly `1/true/yes/on`) |
| `intake.py` | Safe extraction of untrusted uploads (zip/tar): path, link, bomb, size, count and name defences |
| `detect.py`, `yamlutil.py` | Content-based format/provider detection; SafeLoader YAML with line numbers and alias-bomb limits |
| `secret_scan.py` | Secret detection and redaction (findings never contain the secret) |
| `parsers/terraform.py` | Terraform/OpenTofu HCL, JSON, plan JSON, opt-in state; offline, no execution |
| `parsers/cloudformation.py` | CloudFormation / SAM templates |
| `parsers/kubernetes.py` | Rendered Kubernetes manifests; pod-spec helpers |
| `ir.py` | Resource IR, Finding, JSON-safe serialisation with secret redaction, validation |
| `service.py`, `Dockerfile` | Sandboxed scanner service (health check only so far) |

## Isolation rules (RTM CM-150..157)
* Off by default; additive: nothing in `backend/`, `okf/` or `frontend/` imports from here yet.
* Own dependencies, lockfile and tests; `backend/pyproject.toml` and `uv.lock` are not touched.
* Untrusted input is only handled in this package, which runs in a sandboxed container (`../docker-compose.cloud.yml`).
* Unknown stays unknown: anything not statically provable is `Unknown` and never reported as PASS.

## Develop
```bash
cd cloud
uv run --frozen pytest -q --cov --cov-report=term-missing     # 100% coverage gate
```
