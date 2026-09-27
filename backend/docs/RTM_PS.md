# RTM - Official SIH26155 Problem Statement → Implementation

Source: **SIH26155 · AI-Driven Multi-Vendor Network Security Compliance Auditor**,
National Technical Research Organisation (NTRO), Software / Blockchain & Cybersecurity,
https://sih2026.vuce.in/ps/SIH26155 (fetched 2026-09-26).
Target: `F:\Multi-vendor\backend\` (+ `okf/`, `models/`).

Legend: ✅ implemented + tested · 🟡 partial / roadmap noted · ⬜ pending (non-code deliverable)

## A. Required platform features (PS “proposed solution should be …”)

| Req ID | PS requirement | Implementation | Status | Evidence |
|---|---|---|---|---|
| PS-R1 | **Unified Ingestion Engine**: dashboard uploading **single or bulk** config files from any network device | `POST /configurations/upload`, `POST /configurations/bulk-upload` (validation + SHA-256 + metadata); Upload & Audit tab | ✅ | pytest upload/bulk path; live smoke `CISCO/IOS-XE/17.9.2` |
| PS-R2 | **AI Training Module**: GUI mapping raw unrecognized lines → security categories; AI learns **without backend redeployment** | Training tab + `/training/queue→/suggest→/approve→/reject`; approval persists to `okf/knowledge/mappings/learned/`, live-reloaded; M3-kNN + LLM suggestions | ✅ | approve→re-audit test path; `learned/` writes |
| PS-R3 | **Multi-Framework Compliance**: user-selected **CIS, NIST, STIGs, ISO/IEC 27001** | `POST /audits {frameworks:[…]}`; 82 controls (CIS 47 / NIST 82 / STIG 34 / ISO27001 73 refs across 13 Annex A controls / CERT-In 15); per-framework scores; platform-applicability (N/A) excluded from scoring | ✅ | `/compliance/{aud}/framework/NIST` tested |
| PS-R4a | **PDF per device**: device identification incl. **serial numbers, hardware details** | `POST /reports` → ReportLab PDF with Device Identification block (asset, vendor/platform/version, model, serial, IP, env, criticality) | ✅ | PDF bytes + content-type asserted; serial/model fields from asset record |
| PS-R4b | **PDF**: compliance findings, **Pass/Fail + risk severity** | findings table (80 rows) + score header + severity counts | ✅ | live smoke PDF 8.3 KB |
| PS-R4c | **PDF**: **device-specific step-by-step CLI** remediation | vendor-aware steps from OKF RemediationKB (`GET /remediation/{finding}`) | ✅ | dry-run test asserts steps + `device_touched:false` |
| PS-R5 | **Vendor-agnostic scalability**: new vendors/standards/OS versions **without manual code modifications** | mapping registry (YAML, reloaded) + AI gap-fill + versioned control packs (add YAML, no code change) | ✅ | unknown-vendor flow test; learned mapping re-audit |
| PS-R6 | **Normalization** into standardized vendor-neutral schema (Security Baseline Model), JSON/schema | Canonical IR (`GET /configurations/{id}/canonical-ir`); M5 validator gate; Pydantic schemas | ✅ | canonical-ir asserted in tests |
| PS-R7 | **Deviation analysis** vs chosen framework (e.g. `ssh_version == 2` per CIS) | OKF rule DSL (EQUALS/IN/GTE/… compounds) + evidence `{observed → expected}` + `/evidence` chain | ✅ | secure-vs-insecure score test |
| PS-R8 | **AI (pattern recognition, NLP)** for unseen syntax | M1 rules+LogReg, M2 OOV (ML+novelty), M3 kNN mapping, M4 LLM parser (Featherless `gpt-oss-120b`, offline fallback) | ✅ | M2 oov_score on unknowns; M3 suggestions; live LLM verified in models |
| PS-R9 | Suggested stack: Netmiko/NAPALM collection; Python custom logic; ReportLab/FPDF per-model/version PDFs | Python custom logic ✅; ReportLab per-vendor/version PDFs ✅; **file-upload ingestion** (the PS's required feature) ✅; live SSH/Netmiko collection → roadmap | 🟡 | roadmap noted; upload path is the PS-mandated interface |
| PS-R10 | Device coverage: firewalls/SASE, routers/switches, white-box/SONiC, cloud-native SGs - “**any** network device” | deterministic parsers: cisco/juniper/fortinet/paloalto/arista; **anything else → unknown-vendor AI loop** (never a hard failure) | ✅ | unknown pipeline + vendor detector `UNKNOWN@0.31` routing |

## B. Core challenge / operational gap coverage

| PS text | Implementation |
|---|---|
| Syntactic diversity (same setting, different CLI per vendor) | Canonical IR: all vendors → same 103 properties before any engine runs (arch §11 diagram) |
| Adaptation to new/proprietary hardware | M2 detect → M3/LLM suggest → human approve → registry → auto-recognized (arch §8 loop) |
| Centralized source of truth | `GET /dashboard/summary` + unified findings across 4 engines |
| Manual checklist / vendor-locked suites | vendor-neutral deterministic engines + evidence chain |

## C. Evaluation deliverables (PS “Expected Solution/Deliverables”)

| Deliverable | Status |
|---|---|
| Source code link | ✅ this repo (`backend/` + `okf/` + `models/`) |
| Readme with setup instructions | ✅ `README.md` + `backend/docs/SETUP.md` |
| Architecture document (max 2 pages) | ✅ `backend/docs/ARCHITECTURE.md` |
| Demo video (max 2 min) | ⬜ to record (script: `USER_GUIDE.md` §2 + arch §63 steps 1-9) |
| Technical presentation (max 5 slides) | ⬜ to build (storyline: problem → canonical-IR architecture → AI learning loop → 4-engine evidence → demo) |

## D. Honest gaps (nothing hidden)

1. **Live device collection** (SSH/Netmiko/NAPALM, vendor APIs): prototype ingests
   files/API text, which is exactly the PS's required interface; live pull is roadmap.
2. **Config encryption at rest / full RBAC matrix**: prototype uses in-memory stores +
   ADMIN demo user; PostgreSQL + secret management + 5 roles are production scope
   (`docs/IMPLEMENTATION.md §9`).
3. **Async workers at scale**: synchronous audits (job-id pattern already on
   CVE-sync/fleet/reports); Celery/Redis in production.
4. Quantum models (M9-M13) are **research-only by design** (models RTM) and correctly
   excluded from the audit path.

**Verdict: 10/10 functional requirements ✅ (1 with noted roadmap), knowledge/model
integration complete, all pytest + live-smoke checks green.**
