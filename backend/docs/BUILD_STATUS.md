# Build status — what is built, missing, and extra w.r.t. the PS

Reference: official SIH26155 problem statement (NTRO) — see `docs/RTM_PS.md` for the
line-by-line RTM. Status date 2026-09-26. Verdicts from `uv run pytest -q --cov` (41/41 green,
100% statement coverage over `app/`, enforced by `fail_under`) plus live HTTP checks of both `.env` APIs
(Featherless LLM online; NVD sync with keyless fallback), a 49-route OpenAPI surface,
and a real Chromium E2E journey (12/12 green: login → upload → 80-finding audit → evidence →
remediation dry-run → training suggest → PQC → PDF download). Legend: ✅ done · 🟡 roadmap · ⬜ non-code deliverable.

## 1. Already built (every PS-mandated feature)

| # | PS requirement | Where it lives | Proof |
|---|---|---|---|
| 1 | Single + bulk config upload dashboard | `POST /configurations/upload`, `/bulk-upload`; Upload & Audit tab | pytest + live smoke (`CISCO/IOS-XE/17.9.2` detected) |
| 2 | AI training GUI (map raw lines → security categories, no redeploy) | Training tab; `/training/queue→/suggest→/approve→/reject`; approvals persist to `okf/knowledge/mappings/learned/` | approve→re-audit test |
| 3 | Multi-framework engine (CIS, NIST, STIG, ISO/IEC 27001, user-selected) | `POST /audits {frameworks}`; 70 controls, cross-framework mapping | per-framework scores tested |
| 4 | Per-device PDF: hardware/serial ID + Pass/Fail & severity + CLI fix steps | `POST /reports` (ReportLab; asset serial/model/IP block, 80-row findings, vendor steps) | PDF download asserted |
| 5 | Vendor-neutral normalization (Security Baseline Model, JSON/schema) | Canonical IR, 102 properties, M5 gate, `/canonical-ir` contract | `ir_validation.valid=true` live |
| 6 | Deviation analysis with evidence | rule DSL + `/audits/{id}/evidence` (observed→expected→source line) | evidence items asserted |
| 7 | Pattern-recognition/NLP adaptation | M1 + M2 + M3 + M4 LLM gateway (offline fallback) | oov_score + model_suggestions live |
| 8 | Versioned, reproducible audits | `versions{}` + `config_sha256` on every audit; `okf_manifest.yaml` | `versions.okf=1.1.0` live |
| 9 | Required submission docs (source, readme+setup, 2-page arch) | this repo, `README.md`+`SETUP.md`, `ARCHITECTURE.md` | files present |

## 2. Still missing / roadmap (with reason + path)

| # | Item | Why not now | Path |
|---|---|---|---|
| 1 | **Live device pull** (SSH/Netmiko/NAPALM, vendor APIs) | PS mandates file/API ingestion, which ships; live pull is suggested-workflow only | add connector service → reuse `POST /configurations/upload` internally |
| 2 | **PostgreSQL + Redis + Celery** (replacing in-memory stores) | prototype scope per arch §51; schema already mirrored + DDL exists in `okf/migrations/` | swap `app/core/store.py` for SQLAlchemy repos; job-id pattern already on sync/fleet/reports |
| 3 | **Config encryption at rest + full 5-role RBAC** | prototype: JWT + ADMIN seed; approvals/audits already actor-stamped | secrets manager + role checks on approve/apply |
| 4 | **Full FP/FN + PQC-accuracy harnesses** (§59/§61) | CVE 208-case golden + secure-vs-insecure assertions ship; exhaustive harnesses need analyst labels | extend `tests/` with labelled corpora |
| 5 | **Demo video (2 min) + 5-slide deck** ⬜ | non-code | script: `USER_GUIDE.md` §2 + arch §63 steps 1–9 |

## 3. Extra — built beyond the PS (for best marks)

| # | Extra | Why it helps |
|---|---|---|
| 1 | **CVE engine as 4th core engine** (CPE + version-range matching, 3-state verdicts, CVSS, NVD sync, **blast-radius**: new CVE → affected assets) | turns the auditor into a vulnerability platform; `POST /vulnerabilities/blast-radius` demo moment |
| 2 | **PQC readiness + CBOM** with 0–100 score, kept separate from compliance | post-quantum story no other team will show as cleanly |
| 3 | **Security analytics + combination patterns** (“Exposed Administrative Access”) | proves intelligence beyond rule-checking |
| 4 | **Fleet anomaly (M7, fit-per-fleet)** + **semantic dedup (M8)** + **M2 OOV scores visible in UI** | makes every production model visible in the product, not just the report |
| 5 | **Closed-loop remediation verify** (`verified_fixed` via re-audit diff, simulation-safe) | “before 12 findings → after 5, 7 resolved” narrative from arch §33 |
| 6 | **Reproducibility stamps** (knowledge versions + config hash on each audit) | answers “which rules produced this report?” — auditor-grade trust |
| 7 | **CERT-In as 5th framework** + 49-route versioned REST API + OpenAPI docs | India-specific depth + integration-ready platform story |
| 8 | **Real ML backbone in production path** (MiniLM-384 + native HDBSCAN, CPU torch) — no silent TF-IDF degradation | M2/M3/M7 run exactly as evaluated in `models/` (oov 0.0 vs 0.95 verified live) |
| 9 | **Import bridge** merging both `src` trees persistently (one import, hot artifacts) + separate FLEET_JOBS store + strict error codes (404/400) and input validation (asset names, pagination bounds) | fast warm requests, clean multi-tenant job tracking, clients can rely on HTTP status |

**Bottom line: nothing the PS demands is missing from the prototype; the roadmap is
production hardening + live collection + video/slides, while the extras (CVE platform,
PQC/CBOM, closed-loop verify, reproducibility) are the differentiators.**
