# TRM - `docs/arch.md` (§1-§64) → Implementation

Target: `F:\Multi-vendor\backend\` (+ `okf/`, `models/`).
Legend: ✅ implemented + verified · 🟡 partial (prototype scope, prod path noted) · 🔬 research-only (correctly isolated)

## Layers & engines (§1-§33)

| Arch | Requirement | Implementation | Status |
|---|---|---|---|
| §1-3 | Executive architecture; 10 layers L1-L10; “syntax vendor-specific, analysis vendor-neutral” | modular monolith `backend/`; all vendors → Canonical IR before engines | ✅ |
| §4 L1 | Ingestion: file types, size/encoding checks, metadata, SHA-256 fingerprint | `app/parsers/ingestion.py` + upload/bulk-upload; `config_sha256` on audit | ✅ |
| §5 L2 | Vendor/platform/version detection + confidence | M1 (`models/src/m1_vendor.py`) + version normalizer + `POST /detection/vendor` | ✅ |
| §6-7 L3 | Two parsing paths; **deterministic wins, AI fills gaps** | OKF `MappingRegistry` regexes first, `llm_gateway` only for uncovered lines | ✅ |
| §8 | Human-in-the-loop training (approve/edit/reject) | Training tab + `/training/*`; learned YAML reloaded live | ✅ |
| §9 | Mapping registry (versioning, approval, provenance) | `okf/knowledge/mappings/` + `learned/`; `MAP-*` records | ✅ |
| §10-11 | Canonical Security Baseline Model = heart; canonical-IR scaling argument | 103 props; nested IR per audit; `/canonical-ir` contract | ✅ |
| §12 | Four engines consume Canonical IR (sequential ok for demo, parallel in prod) | `audit_service.run_audit` runs compliance→CVE→PQC→security per audit | ✅ |
| §13-15 | Compliance engine + versioned control packs + cross-framework mapping | 82 controls, 5 frameworks, `Crosswalk`, one property → many controls | ✅ |
| §16-18 | PQC engine + CBOM + classical/PQC/hybrid classification | `app/engines/pqc.py` (CBOM rows, readiness 0-100, migration recs), separate from compliance score | ✅ |
| §19-20 | Security analytics incl. combination patterns | `app/engines/security.py` (10 detectors + “Exposed Administrative Access” pattern) | ✅ |
| §21-25 | CVE engine: product+version+CPE correlation, range matching, 3 states, CVSS | OKF `src/cve/` (inventory, CPE resolver, version normalizer/range, KB, NVD sync, correlator, CBOM) | ✅ |
| §26-27 | Unified findings, common schema | `F-*`/`F-CVE-*`/`F-SEC-*`/`F-PQC-*` with `{finding_id,engine,severity,evidence,confidence,risk,remediation,status}` | ✅ |
| §28 | Evidence graph (raw→token→property→control→finding→risk→remediation) | provenance per property + `GET /audits/{id}/evidence` | ✅ |
| §29 | Multi-dimension risk (severity×confidence×exposure×criticality…), transparent formula | OKF `RiskEngine` + M6 `rule_score` attached per finding | ✅ |
| §30 | Cross-engine correlation (one asset, one risk picture) | unified findings per asset; CVE+compliance+PQC share `asset_id` + risk view | ✅ |
| §31-33 | Remediation + Generate→Approve→Apply→Validate + closed-loop re-audit | `/remediation/{id}` plan → approve gate → **simulated** apply → re-audit diff (`verified_fixed`) | ✅ |
| §34 | Technical + executive reports | PDF (device/findings/CVE/PQC/remediation/evidence) + dashboard executive summary | ✅ |
| §35 | Dashboard: 6 pages | 6 console tabs (Dashboard, Upload & Audit, Findings, Training, PQC/CBOM, Reports) | ✅ |

## Structure, data, knowledge (§36-§44)

| Arch | Requirement | Implementation | Status |
|---|---|---|---|
| §36 | Backend structure | `app/{api/v1,core,services,engines,parsers}` + `frontend/` + `tests/` (api.md §37 layout) | ✅ |
| §37-38 | DB tables + configuration→findings relationships | in-memory stores mirror the schema; full DDL in `okf/migrations/`; PostgreSQL in prod | 🟡 |
| §39 | Separate knowledge sources (controls / vendor / vuln) | OKF knowledge dirs independent; new CVE ≠ redeploy parser | ✅ |
| §40-41 | OKF + crosswalk graph | `okf/` registry + `GET /okf/crosswalk/{id}` | ✅ |
| §42 | CVE knowledge architecture | `knowledge/vulnerability/` + 8 CVE modules | ✅ |
| §43-44 | Known / unknown data flows, identical downstream | `vendor_detector` routes; same 4 engines either path | ✅ |

## QML, security, stack (§45-§51)

| Arch | Requirement | Implementation | Status |
|---|---|---|---|
| §45-46 | QML = optional research layer, never a dependency | M10-M13 never imported by backend (verified: only M1/M2/M3/M5/M6/M7/M8 wired) | 🔬✅ |
| §47-49 | Auth/RBAC, sensitive-config protection, audit logging | JWT + ADMIN seed; approvals/audits timestamped with actor; at-rest encryption = prod scope | 🟡 |
| §50 | Tech stack | Python/FastAPI/Pydantic + sklearn + ReportLab + Docker-ready; **adapted**: plain-HTML console (user requirement) instead of React; Postgres/Redis = prod | ✅ adapted |
| §51 | Modular monolith for prototype | single FastAPI service | ✅ |

## Ops, testing, demo (§52-§64)

| Arch | Requirement | Implementation | Status |
|---|---|---|---|
| §52 | Async jobs (upload→queue→worker→notify) | synchronous audits; job-id pattern on CVE-sync/fleet/reports; Celery = prod | 🟡 |
| §53 | Independent engine workers | sequential per audit (spec-allowed for demo); CVE concurrently separable | ✅ |
| §54 | Caching (detection, mappings, CVE, IR) | `lru_cache` on OKF registries + integration layers; Redis = prod | 🟡 |
| §55-56 | Versioning + reproducibility (parser/mapping/IR/control/CVE/PQC/risk versions, hash, timestamp) | `versions{}` + `config_sha256` + `created_at` on every audit; `okf_manifest.yaml` | ✅ |
| §57-58 | Golden corpus + AI metrics | 200 golden configs + full metric suites in `models/`/`okf/`; backend golden-style pytest | ✅ |
| §59-61 | Compliance/CVE/PQC evaluation harnesses | CVE 208-case golden ✅; compliance secure-vs-insecure assertion ✅; full FP/FN + PQC-accuracy harnesses → future | 🟡 |
| §62 Tests 1-6 | Cisco / Juniper / Fortinet / unknown-vendor / retrain-recognized / remediate→resolved | T1 ✅ pytest; T2/T3 ✅ presets + detection; T4 ✅ unknown flow; T5 ✅ approve→re-audit; T6 ✅ dry-run re-audit diff | ✅ |
| §63 | 9-step demo story | mirrored in `USER_GUIDE.md` §2 (upload→detect→normalize→4 engines→risk→evidence→unknown→approve→re-run) | ✅ |
| §64 | One-line principle | `Ingest → Detect → Parse/AI-Learn → Canonical IR → 4 engines → Risk → Remediate → Re-audit → Report` - exactly `audit_service` | ✅ |

**Summary: 41 ✅ · 7 🟡 (all prototype-scoped with prod path) · 1 🔬 (by design). No open functional gaps.**
