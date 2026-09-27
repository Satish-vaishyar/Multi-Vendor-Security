# OKF - Operational Knowledge Framework (complete section implementation)

Vendor-neutral knowledge layer between Canonical IR and the engines.
Docs: `../docs/okf.md`, `../docs/api.md §30`, `../docs/cve_okf.md`.

## Layout
```
okf/
  llm_gateway.py      <- SINGLE file for ALL LLM calls (Featherless gpt-oss-120b). Nothing else may call an LLM.
  main.py             <- FastAPI service (uvicorn main:app)
  src/                <- schemas, registries, evidence/compliance/risk engines, learning loop, API router
  knowledge/          <- properties, controls, frameworks, crosswalks, remediation, mappings
  scrapers/           <- nist_oscal / cis / stig / iso scrapers + run_all.py
  scripts/demo_audit.py, tests/, data/golden/
```

## Setup
```powershell
cd F:\Multi-vendor\okf
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env   # then add FEATHERLESS_API_KEY=...
python -m scrapers.run_all
python scripts\demo_audit.py
pytest -q
uvicorn main:app --reload
```

## Rule
Deterministic values win; AI fills gaps. LLM never decides compliance - engines do.
