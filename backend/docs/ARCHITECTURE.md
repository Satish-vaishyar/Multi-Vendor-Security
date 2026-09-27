# Architecture (SIH26155 evaluation submission - 2 pages)

## 1. What it is

An AI-assisted, vendor-neutral network security auditor for NTRO (SIH26155):
heterogeneous device configs in; a **Canonical Security Baseline Model** in the
middle; Compliance (CIS/NIST/STIG/ISO), PQC-readiness, Security-analytics and
CVE engines; evidence-backed findings, risk, remediation and a per-device PDF out.
Core principle: **configuration syntax is vendor-specific, security analysis is
vendor-neutral** - Cisco, Juniper, Fortinet, Palo Alto, Arista, or an unseen
vendor all become the same 103-property Canonical IR before analysis.

## 2. Architecture

```
Any config → Ingest → M1 vendor detect → Deterministic parse (+AI gap-fill) →
Canonical IR (M5-validated) → ┌ Compliance (OKF, 82 controls, cross-framework)
                               ├ PQC engine → CBOM + readiness (separate score)
                               ├ Security analytics (+ combination patterns)
                               └ CVE engine (CPE + version-range, NVD-synced)
→ Unified findings → Risk (OKF + M6) → Remediation (approve → SIMULATED apply →
re-audit diff) → Evidence chain + PDF report
```

Unknown syntax takes a learning detour - M2 flags it, M3/LLM proposes a mapping,
an admin approves in the Training GUI, the mapping persists without redeployment
(“learn once, audit automatically thereafter”) - then rejoins the identical
downstream. AI interprets syntax; **deterministic engines decide verdicts**.
Quantum models (M10-M13) are isolated research, never in the audit path.
One FastAPI modular monolith (`/api/v1`, 60 routes - 56 under `/api/v1`) + API-only HTML console;
in-memory stores for the prototype (PostgreSQL/Redis/Celery in production).

## 3. PS coverage & evidence

All 10 PS features ship: single/bulk ingestion; training GUI; user-selected
CIS/NIST/STIG/ISO; per-device PDF (serial/hardware ID, Pass/Fail + severity,
device-specific CLI fixes); no-redeploy scalability; JSON-schema normalization;
deviation analysis with line-level evidence; pattern-recognition/NLP adaptation;
live SSH pull is the only roadmap item (file/API ingestion is the mandated
interface). Verified by 56 pytest cases at 100% statement coverage and a live HTTP smoke run
(Cisco IOS-XE 17.9.2 → 80 unified findings → evidence → PDF).
Traceability: `docs/RTM_PS.md` (official PS), `docs/TRM_ARCH.md` (arch §1-§64).
