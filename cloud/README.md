# cloud/ - Orbit cloud assessment module (scanner side)

Status: **static assessment complete for the supported formats; live assessment is foundations only** (see the RTM for every
step's status and what is not done). Plan, traceability and the live progress log: `../docs/CLOUD_MODULE_RTM.md`; requirements:
`../docs/CLOUD_PROVIDER_SECURITY_ASSESSMENT_CATALOG.md`; India provider evidence framework: `../docs/CLOUD_INDIA_PROVIDER_DISCOVERY.md`.

## What exists
| Module | Purpose |
|---|---|
| `flags.py` | `CLOUD_MODULE_ENABLED` feature flag, fail-closed (off unless exactly `1/true/yes/on`) |
| `intake.py` | Safe extraction of untrusted uploads (zip/tar): path, link, bomb, size, count and name defences |
| `detect.py`, `yamlutil.py` | Content-based format/provider detection; SafeLoader YAML with line numbers and alias-bomb limits |
| `secret_scan.py` | Secret detection and redaction (findings never contain the secret) |
| `parsers/terraform.py` | Terraform/OpenTofu HCL, JSON, plan JSON, opt-in state; offline, no execution |
| `parsers/cloudformation.py`, `arm.py`, `kubernetes.py` | CloudFormation/SAM, Azure ARM (Bicep is not compiled), rendered Kubernetes manifests |
| `parsers/heat.py` | OpenStack Heat (HOT) templates; `get_param` defaults resolved, other intrinsics Unknown |
| `parsers/ansible.py` | Ansible playbooks: only `ec2_group` tasks are read (mapped to the AWS security-group rules); the playbook is never run |
| `parsers/pulumi.py` | `pulumi stack export` JSON: a small explicit type table; unmapped types are reported as not assessed |
| `ir.py` | Resource IR, Finding, JSON-safe serialisation with secret redaction, validation |
| `rules/` | Rule engine, named extractors, strict pack loader, customer packs (`customer.py`) |
| `graph.py`, `remediation.py`, `scoring.py`, `drift.py`, `exceptions.py`, `capability.py` | Effective exposure notes, un-applied fix snippets, framework scoring, scan drift, exception expiry, capability matrix |
| `export.py` | JSON, CSV (formula-neutralised), SARIF and a dependency-free text PDF; everything re-redacted |
| `scanners.py` | Optional Checkov/Trivy adapters (the tools are NOT bundled in the image; reported as unavailable, never clean) |
| `live.py` | Live-assessment foundations only: read-only operation guard, authorisation record, un-leakable `Secret`, static/live reconcile. No cloud client exists |
| `pipeline.py`, `service.py`, `Dockerfile` | Scan pipeline and the sandboxed scanner service (`/healthz`, `/scan`, `/export/{json,csv,sarif,pdf}`) |

## Not implemented (see the RTM for the reason)
Real AWS/Azure/GCP connectors and org-wide inventory (need a test cloud account), Bicep compile, bundled Checkov/Trivy,
pinned provider schemas (CM-142), VMware/NSX, Nutanix, cloud-init rules, IBM/Vultr/UpCloud firewall rules, schedules and
webhooks, opt-in asset links, on-prem packaging.

## Isolation rules (RTM CM-150..157)
* Off by default; additive: the backend mounts the router only when the flag is on, one gated line in `backend/app/main.py`.
* Own dependencies, lockfile and tests; `backend/pyproject.toml` and `uv.lock` are not touched.
* Untrusted input is only handled in this package, which runs in a sandboxed container (`../docker-compose.cloud.yml`).
* Unknown stays unknown: anything not statically provable is `Unknown` and never reported as PASS.

## Develop
```bash
cd cloud
uv run --frozen pytest -q --cov --cov-report=term-missing     # 100% coverage gate (408 tests)
```
