# Implementation traceability — `docs/arch.md` + `docs/api.md` → `backend/` (+`okf/`, `models/`)

## 1. Architecture layers (arch.md §3–10, L1–L10)

| Layer | Spec | Backend code | Reused |
|---|---|---|---|
| L1 Ingestion | validation/sanitize/metadata/SHA-256 (§4) | `app/parsers/ingestion.py`, `POST /configurations/upload` (+bulk) | — |
| L2 Vendor detection | fingerprint→vendor/platform/version/conf (§5) | `app/parsers/vendor_detector.py` (+`POST /detection/vendor`) | `models/src/m1_vendor.py` (rules+LogReg, artifacts `m1_*.pkl`) |
| L3 Parsing + AI policy | two paths; deterministic wins, AI fills gaps (§6–7) | `app/parsers/canonical.py` | `okf/src/knowledge_extras.py:MappingRegistry` (deterministic) + `okf/src/learning_engine.py` → `okf/llm_gateway.py` (gap-fill) |
| L4 Mapping registry | versioned approve/edit/reject (§9) | `POST /training/{id}/approve` persists to `okf/knowledge/mappings/learned/` | OKF registry |
| L5 Canonical IR | heart; vendor-neutral schema (§10–11) | nested IR in every audit; `GET /configurations/{id}/canonical-ir` | OKF property registry (102 props) + M5 gate |
| L6 Four engines | compliance/PQC/security/CVE (§12–25) | `app/services/audit_service.py` runs all 4 per audit | compliance+CVE from OKF; PQC `app/engines/pqc.py`; security `app/engines/security.py` |
| L7 Unified finding + risk | common schema (§27), multi-dim risk (§29), correlation (§30) | unified list in `audit_service.py` (F-*/F-CVE-*/F-SEC-*/F-PQC-*), `GET /findings` | OKF `RiskEngine` + `models/src/m6_risk.py:rule_score` |
| L8 Remediation | vendor commands + Generate→Approve→Apply→Validate (§31–33) | `GET/POST /remediation/{finding_id}[/approve|/apply]` simulation + re-audit diff | OKF `RemediationKB` |
| L9 Evidence graph | raw→token→property→control→finding→risk→remediation (§28) | `GET /audits/{id}/evidence` (line-level provenance) | OKF provenance |
| L10 Reporting + dashboard | 6 pages (§35), tech+exec reports (§34) | `frontend/index.html` (6 tabs), `POST /reports` PDF via ReportLab | — |

Human-in-the-loop training (§8): Training tab → `/training/queue` → `/suggest` → `/approve|/reject` → registry → re-audit. Unknown flow (§44) rejoins the known flow before the engines.

## 2. API groups (api.md, 15 routers under `/api/v1`)

auth (§4) · assets (§5) · configurations (§6–9 + unknowns §33) · audits (§10–12 + evidence §31) ·
compliance (§13) · vulnerabilities (§14–15 incl. `/sync`) · pqc (§16) · analytics (§17–18 incl. fleet) ·
findings (§19–20) · training (§21–25) · remediation (§26–27) · reports (§28) · dashboard (§29) ·
okf (§30) · detection (§32). Canonical-IR contract (§40) is the JSON from
`GET /configurations/{id}/canonical-ir`, consumed by all engines.

## 3. Models (docs/models.md → models/ → backend)

M1 vendor detect (prod) · M2 OOV + M3 mapping assist via OKF gateway/suggest path ·
M4 LLM parser via `llm_gateway` (never verdicts) · M5 IR validator (vocab gate) ·
M6 risk rule_score attached per finding · M7 fleet via `/analytics/fleet` aggregation ·
M8 similarity available in models lib · M9–M13 **not imported** (research only).

## 4. OKF (docs/okf.md + cve_okf.md → okf/ → backend)

All 10 OKF components + 11 CVE engine rows reused through `app/services/integration.py`
(`okf_layer()`, `cve_layer()`): properties/controls/frameworks/crosswalk/evidence/
compliance DSL/remediation/risk/mapping registry/learning engine/CVE KB + CPE +
version-range + correlator + CBOM + NVD sync + blast-radius (exposed via audit + `/vulnerabilities/*`).

## 5. Frontend contract (api.md §34)

`frontend/index.html` uses **only** `fetch()` against `/api/v1/*`. It never imports
backend code, never calls NVD/LLM/PostgreSQL/ML directly. Served at `/ui`.

## 6. Data flow diagrams

Known vendor (arch.md §43): config → ingestion → M1 → deterministic parser →
canonical IR → 4 engines → unified findings → risk → remediation → PDF.
Unknown vendor (§44): … → M1 unknown → AI gap-fill → training approve → registry →
canonical IR → (same downstream).

## 7. Verification

`uv run pytest -q` (39 tests, 100% coverage): auth+dashboard · full audit flow (upload→parse→
canonical→audit→results→evidence→engine reads→findings→training→remediation
dry-run→PDF, asserts insecure<secure ordering) · secure-vs-insecure scoring ·
OKF browser + M1 detection. Plus manual `/ui` walkthrough recorded in test output.

## 8. Credentials

Only `.env` (see `.env.example`): `JWT_SECRET`, `ADMIN_EMAIL/PASSWORD`,
`FEATHERLESS_API_KEY` (LLM, optional), `NVD_API_KEY` (optional),
`OKF_DIR/MODELS_DIR` (defaults fit this repo). Frontend takes no secrets —
it logs in via `/auth/login` and sends `Authorization: Bearer`.

## 9. Production hardening (out of prototype scope)

PostgreSQL (+pgvector) replacing `app/core/store.py`; Redis/Celery for audit/CVE-sync/PDF jobs;
Nginx; RBAC roles beyond ADMIN; secrets manager; Prometheus/Grafana; K8s later
(per `docs/tech_stack.md` — deliberately not added now).
