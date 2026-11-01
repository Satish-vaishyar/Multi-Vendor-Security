# cloud/ - Orbit cloud assessment module (scanner side)

Status: **S01 foundation only.** No scanning logic yet. Plan and traceability: `../docs/CLOUD_MODULE_RTM.md`;
requirements: `../docs/CLOUD_PROVIDER_SECURITY_ASSESSMENT_CATALOG.md`.

## Isolation rules (RTM CM-150..157)
* Off by default: `CLOUD_MODULE_ENABLED` must be exactly `1/true/yes/on` (see `flags.py`). Anything else is off.
* Additive: nothing in `backend/`, `okf/` or `frontend/` imports from here yet.
* Own dependencies and tests (`pyproject.toml` here); `backend/pyproject.toml` and `uv.lock` are not touched.
* Untrusted input is only ever handled inside this package, which will run in a sandboxed container (S03).

## Develop
```bash
cd cloud
uv run --with pytest --with pytest-cov pytest -q --cov --cov-report=term-missing
```
