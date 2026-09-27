# Multi-Vendor Security - AI-Driven Network Security Compliance Auditor
### SIH 2026 · Problem Statement 26155 · NTRO
### Team: KT@UnseenGeeks

Vendor-neutral network security auditing: heterogeneous device configs in,
**Canonical Security Baseline Model** in the middle, Compliance + PQC +
Security Analytics + CVE engines, evidence-backed findings and PDF reports out.

Repo: https://github.com/Satish-vaishyar/Multi-Vendor-Security

Remediation **Apply is always a dry run** (`device_touched: false`) by design -
no flow in this repo contacts real network devices.

---

## 1. Problem statement (SIH 26155, NTRO)

NTRO operates routers, switches, firewalls, SASE, white-box/SONiC and cloud
security groups from many vendors. Each vendor uses different CLI syntax for
the same security setting, OS versions drift, and new/proprietary hardware
appears continuously. Manual checklists and vendor-locked audit suites do not
scale.

The problem statement asks for an **AI-Driven Multi-Vendor Network Security
Compliance Auditor** that provides:

1. **Unified ingestion** - single + bulk config upload from any device.
2. **AI training module** - GUI that maps unrecognized lines to security
   categories and learns **without redeployment**.
3. **Multi-framework compliance** - user-selected CIS, NIST SP 800-53, DISA
   STIG, ISO/IEC 27001 (we add CERT-In as a 5th framework).
4. **Per-device PDF** - device ID incl. serial/hardware, Pass/Fail + severity,
   device-specific CLI fix steps.
5. **Vendor-agnostic scalability** - new vendors/standards/OS versions without
   code changes.
6. **Normalization** - vendor-neutral Security Baseline Model (JSON + schema).
7. **Deviation analysis** - observed vs expected with line-level evidence.
8. **AI (pattern recognition / NLP)** for unseen syntax.
9. **Any device coverage** - firewall/SASE, router/switch, SONiC, cloud SGs;
   unknown input must route to the learning loop, never hard-fail.

Full requirement-to-code traceability: `backend/docs/RTM_PS.md` (10/10
functional requirements), `backend/docs/TRM_ARCH.md` (arch §1-§64),
`backend/docs/BUILD_STATUS.md` (gap analysis).

---

## 2. How our solution solves it

Every config - Cisco, Juniper, Fortinet, Palo Alto, Arista, or completely
unknown - follows one pipeline:

```
Config text → Ingest → M1 vendor detect → Deterministic parse (+ AI gap-fill)
→ Canonical IR (M5-validated, 103 properties) → 4 engines → Unified findings
→ Risk → Remediation (approve → SIMULATED apply → re-audit diff)
→ Evidence chain + PDF report
```

- **Syntactic diversity** is absorbed once, at parse time. All vendors become
  the same 103-property Canonical IR before any engine runs.
- **New hardware** takes a learning detour: M2 flags unknown lines, M3/LLM
  proposes a mapping, an admin approves in the Training GUI, the mapping is
  persisted to `okf/knowledge/mappings/learned/` and hot-reloaded. Next audit
  recognizes the line automatically ("learn once, audit automatically
  thereafter").
- **Trust** comes from determinism: compliance, CVE, PQC and risk verdicts are
  computed by versioned YAML rules + range math, never by LLM sampling. The
  LLM only translates unknown syntax into schema-validated IR (Pydantic/M5
  gate), and loses on conflict.
- **Operations** get one risk picture per asset: compliance + CVE + PQC +
  analytics findings share `asset_id`, evidence lines, and reproducibility
  stamps (`versions{}` + `config_sha256` on every audit).

---

## 3. Comparison with existing approaches

| Approach | Vendor coverage | Unknown syntax | Verdict trust | Evidence | Learning without redeploy | Offline |
|---|---|---|---|---|---|---|
| Vendor-locked audit suites (e.g. vendor NCCM/checklist tools) | One vendor only | Hard failure / skip | Rules, but siloed per vendor | Varies | No - code change per vendor | Usually yes |
| Generic network scanners (config + live-poll posture tools) | Broad, shallow | Best-effort fingerprint | Heuristic / probe-based | Host-level, rarely config-line | No | Needs network access |
| Manual CIS/STIG checklists + spreadsheets | Any, by hand | Human effort | Human, non-reproducible | Manual | N/A (all manual) | Yes, but slow |
| LLM-chat wrappers ("paste config, ask for audit") | Any text | Guesses | Non-deterministic, hallucinates policy | No provenance | No versioned knowledge | No (API-only) |
| **This repo (Canonical IR + OKF + M1-M8)** | 5 deterministic + any-unknown via AI loop | M2 detect → M3/LLM suggest → human approve → registry | Versioned YAML rules + range math; LLM never decides compliance | Line-level observed→expected→source | Yes - YAML mapping + control packs, hot-reloaded | Yes - heuristic fallback, seed CVE KB, TF-IDF fallback |

The differentiator is not "more AI" but **AI in the right place**: AI handles
input understanding (detection, OOV, mapping suggestions); deterministic,
auditable engines handle security decisions.

---

## 4. Key features

- Single + bulk upload with SHA-256, metadata, vendor auto-detection.
- Canonical IR browser, Unknown-Tokens queue, parsing confidence per config.
- User-selected frameworks (CIS / NIST / STIG / ISO27001 / CERT-In) + per-framework
  scores; platform-inapplicable controls excluded from scoring (N/A).
- Four engines per audit: **Compliance, CVE, PQC-readiness (+ CBOM), Security
  analytics (+ combination patterns)**.
- Unified findings (`F-*` / `F-CVE-*` / `F-SEC-*` / `F-PQC-*`) with severity,
  confidence, evidence, risk and remediation.
- Training loop: queue → suggest (M3 + LLM) → approve/reject → learned YAML →
  re-audit verification.
- Remediation plans with vendor CLI steps, approval gate, simulated apply,
  re-audit diff (`verified_fixed`), `device_touched: false` always.
- Fleet anomaly review (`POST /analytics/fleet`), semantic dedup (M8), CVE
  blast-radius ("new CVE → which assets are affected").
- Per-device PDF (device ID, scores, findings, CVE/PQC/remediation/evidence)
  + dashboard executive summary.
- Reproducibility: knowledge versions + config hash + timestamps on every
  audit; 208-case CVE golden set; 200 golden configs; 56 pytest cases at 100%
  statement coverage (`fail_under=100`).

---

## 5. Why this approach is different

1. **Canonical IR first.** Analysis is vendor-neutral by construction; adding a
   vendor means adding YAML mappings, not forking engine logic.
2. **Deterministic wins, AI fills gaps.** Registry regexes run before the LLM;
   conflicts resolve in favor of the registry; M5/Pydantic rejects malformed AI
   output.
3. **Closed learning loop with a human gate.** No silent auto-learning; every
   registry write is approved, timestamped and actor-stamped.
4. **Real ML backbone in the audit path, honestly evaluated.** MiniLM-L6-v2
   384-dim embeddings + native HDBSCAN + CPU torch where measured; TF-IDF is an
   explicit offline fallback, not a silent downgrade.
5. **CVE as a 4th core engine**, not a bolt-on: CPE resolution + version-range
   math + NVD sync + blast-radius + CBOM shared with PQC.
6. **Simulation-safe remediation.** Approve → dry-run → re-audit diff gives the
   "before 12 findings → after 5, 7 resolved" narrative without touching devices.
7. **Monolith that stays honest.** One FastAPI service (60 routes, 56 under
   `/api/v1`) reuses `okf/` + `models/` instead of duplicating rules, CVE data
   or trained weights.

---

## 6. Models (M1-M13) - why each exists, where it runs, what it buys

Backbone: **MiniLM-L6-v2 (384-dim)**. Scale: 2,850 configs · 100k lines ·
5,400 mappings · 375 controls · 40 PQC rules · 5,000 risk rows · 10k fleet
devices (500 fleets) · 200 golden · 300 unseen · 400 quantum.
Source: `models/MODELS_PERFORMANCE.md` (2026-09-26, from
`evaluation/metrics.json`). Stress: 13/13 PASS (empty/garbage/2k-line/unicode).

| Model | Why it is required | Where it is used | Performance / effect |
|---|---|---|---|
| M1 Vendor Detector (rules + TF-IDF LogReg) | Route every config to the right parser; unknown must not crash the audit | `app/parsers/vendor_detector.py`, `POST /detection/vendor` | 1.000 known-profile acc; 0.973 serving (77 unknown-profile → `unknown` = spec-correct routing); ~4.3 ms/config |
| M2 OOV Detector (MiniLM + LogReg + token-novelty hybrid) | Catch lines no registry covers so they enter the training loop instead of being silently dropped | Unknown-Tokens tab, Training queue, `oov_score` per line | P/R/F1 1.000, FPR 0.000; unseen-family recall 0.025 → **1.000** via novelty channel; ~11 ms/line |
| M3 Mapping (MiniLM + kNN-3) | Propose canonical property for unknown lines - the core of "learn without redeploy" | `POST /training/{id}/suggest`, approve → `mappings/learned/` | Top-1 0.967, Top-3 0.998, MRR 0.982; approve→registry→refresh verified |
| M4 LLM Parser (Featherless `gpt-oss-120b` wrapper) | Translate genuinely novel syntax to schema-valid IR when kNN is uncertain | OKF `llm_gateway.py` gap-fill path only | JSON-valid, sample conf 0.98; offline heuristic fallback (~60 regexes) keeps the app fully usable without a key |
| M5 IR Validator (Pydantic/schema gate) | Stop malformed AI output from ever reaching the engines | Every Canonical IR write, `ir_validation.valid` | Rejects bad enums/keys; coerces e.g. SSH version; gate asserted in tests |
| M6 Risk (deterministic rules → XGBoost-200) | Turn severity×exposure×criticality×confidence into a comparable score | Per-finding `rule_score`, risk view | Train acc 0.877, Spearman 0.522; rule sweep 0.216 (low/internal) → 6.4 (critical/internet) |
| M7 Fleet Anomaly (HDBSCAN-majority-centroid) | Find the misconfigured box among 500 fleets, not just per-device failures | `POST /analytics/fleet` (fit-per-fleet) | P 1.000, R 0.132 → **0.884**, FAR 0.000, silhouette 1.000 (n=10k) |
| M8 Similarity / dedup (MiniLM cosine) | Collapse repeated findings so analysts see 2 problems, not 100 copies | Audit dedup stage | Identical-pair 1.000, dissimilar-pair 0.178; 100 → 2 demo; ~10.8 ms/pair |
| M9 Small Transformer (torch tiny encoder) | Benchmark: can a neural net beat kNN for mapping at this scale? | Research benchmark only | Test 0.970 vs kNN 0.967 (Δ +0.003) → **kNN stays prod** (simpler, incremental) |
| M10 QKS / M11 VQC / M12 QAOA / M13 VQE | Quantum-classical research baselines (kernel, classifier, prioritizer, weight optimizer) | Research only - **never imported by the audit path** | Honest negatives/parity at demo scale (e.g. QKS 0.583 vs RBF 0.590; VQC 0.458 vs MLP 0.562; QAOA 14/17 gap 3; VQE 0.7523 vs expert 0.7053) |

Net effect: M1+M2+M3+M4 keep unknown input from becoming missed coverage;
M5 keeps AI honest; M6+M7+M8 turn raw findings into prioritized, deduplicated,
fleet-aware risk.

---

## 7. OKF (Operational Knowledge Framework) - why it exists, why not RAG

**Why OKF instead of RAG / LLM-as-auditor:** compliance verdicts must be
reproducible, versioned and appealable. A retrieval + generation loop can
retrieve the wrong chunk, paraphrase a threshold, or change its answer between
runs. OKF inverts the responsibility: **knowledge is code-reviewed YAML/JSON,
the LLM is only a translator**.

- LLM may propose `SSH.VERSION = 2` from an unknown line; it may never declare
  "this device is compliant". `eval_op` / `ComplianceEngine` decides.
- Every control carries `{control_id, property, operator, expected, evidence,
  remediation, references, version, source, author}`; `okf_manifest.yaml`
  (v1.1.0, Canonical IR v1.0) pins what produced each audit.
- Source hierarchy is enforced: official framework > vendor docs > NVD >
  expert rule > AI suggestion; AI never overrides policy.
- Fully offline-capable: heuristic gateway fallback, seed CVE KB, TF-IDF
  fallback - the app runs with zero keys.

**What OKF covers** (`okf/`, `okf_manifest.yaml`):

- **103 canonical properties** in `knowledge/properties/` (5 packs:
  base 22, aaa_access 19, crypto_system 21, network 20, software_mgmt 21).
- **82 controls** in `knowledge/controls/` (core 14, extended 21, CERT-In 5,
  NIST-OSCAL subset 30, hardening 12; raw OSCAL 1196 retained).
- **5 frameworks**: CIS, NIST SP 800-53 Rev5, DISA STIG, ISO 27001, CERT-In +
  `crosswalks/unified.yaml` (CIS↔NIST↔STIG↔ISO).
- Vendor mappings (cisco, cisco_extra, juniper, fortinet, generic +
  `learned/`) with versioning, approval status, provenance.
- Per-vendor remediation packs (`remediation/{cisco,juniper,fortinet}/`) with
  validation, rollback and approval-required flags.
- Deterministic **RiskEngine** (severity×exposure×criticality×confidence).
- **LearningEngine**: unknown-token detector (KNOWN/UNKNOWN/UNCERTAIN),
  semantic top-3, LLM parser → schema-validated IR.
- **Single LLM gateway** (`llm_gateway.py`, Featherless `openai/gpt-oss-120b`,
  `offline_fallback: heuristic`, `value_coercion: true`).
- Scrapers (`nist_oscal`, `cis`, `stig`, `iso` + `run_all.py`), corpus/golden/
  fleet generators, `migrations/001_okf.sql`, 208-case golden CVE set.

---

## 8. CVE engine

Pipeline (`okf/src/cve/` - 9 modules: inventory, cpe_resolver,
version_normalizer, version_range, kb, nvd_client, correlator, cbom, update):

```
Software components (from Canonical IR)
  → vendor/product/version extract
  → CPE resolver (alias table + canonical form)
  → local KB / NVD records
  → version-range evaluator (inclusive/exclusive bounds)
  → correlator
  → {VULNERABLE | NOT_AFFECTED | UNKNOWN} + CVSS/CWE/refs/fixed version
  → unified finding (F-CVE-*) + remediation (upgrade path, KB-grounded only)
```

- No ML in the verdict path (policy); ML/LLM only pre-lookup (extract
  vendor/product/version → CPE candidates → verify).
- NVD API 2.0 sync (paged, optional key; automatic keyless retry), ~398k-record
  scale verified live; local `knowledge/vulnerability/cves.json` seeds offline use.
- **Blast-radius**: `POST /vulnerabilities/blast-radius` answers "new CVE →
  which assets are affected" per asset with version evaluation.
- **CBOM** (`cbom.build_cbom`) is shared with the PQC engine
  (classical / pqc-ready / hybrid / deprecated).

Endpoints: `GET /vulnerabilities/{audit}`, `GET .../{finding}`,
`GET /vulnerabilities/cves`, `POST /vulnerabilities/sync`,
`GET /vulnerabilities/kb/status`, `GET /vulnerabilities/sync/{job}`,
`POST /vulnerabilities/blast-radius`.

---

## 9. Architecture (full)

```
+---------------------------------------------------------------------+
| FRONTEND: React 19 + Vite + Tailwind + React Query + Zustand +      |
| Recharts (20 pages). Talks ONLY to /api/v1 (HTTPS/JSON + JWT).      |
| Never touches devices, DB, LLM, NVD or models directly.             |
+---------------------------------------------------------------------+
                                  |
                                  v
+---------------------------------------------------------------------+
| BACKEND: FastAPI modular monolith, 60 routes (56 under /api/v1).    |
| OpenAPI at /docs. HTML console at /ui (API-only).                   |
|                                                                     |
| Ingest (validation, 5 MB, SHA-256, single + bulk upload)            |
|   |                                                                 |
|   v                                                                 |
| M1 vendor detect (rules + LogReg, models/artifacts/*.pkl)           |
|   |                                                                 |
|   v                                                                 |
| Parse: registry regexes FIRST --> Canonical IR --> M5/Pydantic gate |
|   | miss: M2 OOV --> M3 kNN + M4 LLM suggest --> Training approve   |
|   | registry (learned/, hot-reload) --> rejoin same downstream      |
|   v                                                                 |
| Four engines (same Canonical IR in, findings out):                  |
|   - Compliance: OKF 82 controls, 5 frameworks, DSL + Crosswalk      |
|   - CVE: CPE + version-range + NVD sync + correlator + CBOM         |
|   - PQC: CBOM rows, readiness 0-100, migration recs                 |
|   - Security analytics: 10 detectors + combination patterns         |
|   |                                                                 |
|   v                                                                 |
| Unified findings + Risk (OKF RiskEngine + M6 rule_score)            |
| + M8 dedup + M7 fleet aggregation                                   |
|   |                                                                 |
|   v                                                                 |
| Remediation: plan --> approve gate --> SIMULATED apply              |
| (device_touched: false) --> re-audit diff (verified_fixed)          |
|   |                                                                 |
|   v                                                                 |
| Evidence chain (line-level) --> PDF report (ReportLab)              |
|                                                                     |
| Stores: in-memory dev | Supabase Postgres + pgvector (prod)         |
+---------------------------------------------------------------------+
                 | OKF_DIR=../okf      | MODELS_DIR=../models
                 v                     v
+---------------------------------+ +---------------------------------+
| OKF (okf/, v1.1.0)              | | MODELS (models/)                |
| 103 props - 82 controls - 5 fw  | | M1 detect - M2 OOV - M3 mapping |
| crosswalk - remediation - risk  | | M5 validate - M6 risk - M7 fleet|
| mapping registry + learn loop   | | M8 dedup (in audit path)        |
| CVE engine: 9 modules + CBOM    | | M4 LLM wrapper (gap-fill only)  |
| llm_gateway + offline fallback  | | M9-M13 research-only, not wired |
| scrapers + corpus/fleet scripts | | artifacts/*.pkl + minilm/ (hot) |
+---------------------------------+ +---------------------------------+
```

Request flow (what `/ui` and the React app call):

```
POST /configurations/upload → CFG-... → POST /audits → AUD-...
→ GET /audits/{id} → GET /audits/{id}/results → GET /findings?audit_id=...
→ GET /audits/{id}/evidence → POST /reports → GET /reports/{id}/download
```

---

## 10. Repository structure (high level)

```
Multi-Vendor-Security/
  README.md / APPLICATION_SETUP.md / FRONTEND_GUIDE.md / DEPLOY.md
├── docker-compose.yml                # prod: backend :8000 + frontend :8080, Supabase DB
├── backend/                          # runnable FastAPI API + /ui console (START HERE)
│   ├── README.md  docs/              # SETUP, USER_GUIDE, API_REFERENCE,
│   │                                 # IMPLEMENTATION, RTM_PS, TRM_ARCH,
│   │                                 # BUILD_STATUS, ARCHITECTURE
│   ├── app/
│   │   ├── main.py                   # /, /health, /readyz, /ui, router wiring
│   │   ├── api/v1/                   # auth, assets, configurations, audits,
│   │   │                             # engines (compliance/vuln/pqc/analytics),
│   │   │                             # findings, training, remediation, reports,
│   │   │                             # misc (dashboard/okf/detection)
│   │   ├── core/                     # config, security (JWT), store, persist, db
│   │   ├── parsers/                  # ingestion, vendor_detector, canonical
│   │   ├── engines/                  # security, pqc (compliance+CVE from okf)
│   │   ├── services/                 # audit_service, integration (OKF/ML bridge)
│   │   └── db/                       # schema.sql + migrations
│   ├── tests/                        # 56 pytest cases (flows, errors, engines, models)
│   └── frontend/index.html           # API-only test console served at /ui
├── frontend/                         # runnable React UI (20 pages)
│   ├── src/
│   │   ├── api/                      # axios client + endpoint wrappers
│   │   ├── pages/                    # Login, Dashboard, Upload, ConfigDetails,
│   │   │                             # Audits, AuditResults, Compliance,
│   │   │                             # Vulnerabilities, PQC, Analytics, Findings,
│   │   │                             # Remediation, Training, Assets, Reports,
│   │   │                             # Settings (+ detail pages)
│   │   └── components/ stores/ hooks/ types/ utils/
│   └── .env.development / .env.production
│                                     # VITE_API_BASE_URL only (no secrets)
├── okf/                              # knowledge layer (library used by backend)
│   ├── llm_gateway.py  main.py  okf_manifest.yaml  RTM_OKF_CVE.md
│   └── src/  knowledge/  scrapers/  scripts/  tests/  data/  docs/  frontend/
├── models/                           # ML M1-M13 + datasets + artifacts (library)
│   ├── README.md  MODELS_PERFORMANCE.md  RTM_MODELS.md  requirements.txt
│   ├── src/m1_vendor.py ... m13_vqe.py (+ common, embed, evaluate_all)
│   └── scripts/ datasets/ artifacts/ evaluation/
├── docs/                             # problem specification (read-only)
│   └── arch.md  api.md  models.md  okf.md  cve_okf.md  tech_stack.md  frontend.md
└── test-files/                       # 7 sample configs (Cisco x2, Juniper,
                                      # Fortinet, Palo Alto, Arista + edge-case)
```

`backend/` finds `okf/` + `models/` via `OKF_DIR=../okf`, `MODELS_DIR=../models`
- keep the three folders as siblings.

---

## 11. Tech stack

| Layer | Used here | Role |
|---|---|---|
| Backend | Python 3.12+, FastAPI, Pydantic, `uv`, pytest + pytest-cov (`fail_under=100`), httpx | REST orchestration, Canonical-IR validation, 56-test suite |
| Frontend | React 19, Vite, Tailwind, React Query, Zustand, Recharts, axios, react-router | 20-page UI; talks only to `/api/v1` |
| AI/ML | scikit-learn, XGBoost, HDBSCAN, PyTorch (CPU), sentence-transformers (MiniLM-L6-v2 384-d), joblib | M1-M9 training/serving; TF-IDF fallback offline |
| LLM | Featherless `openai/gpt-oss-120b` via single `okf/llm_gateway.py` + offline heuristic | Unknown-syntax translation only; never verdicts |
| Knowledge | YAML + JSON Schema + Python rule engine + OSCAL-normalized NIST subset | 103 props, 82 controls, crosswalk, remediation/risk/mapping registries |
| CVE | NVD API 2.0, CPE dictionary/match, custom version-range engine, local KB | Deterministic correlation, sync, blast-radius, CBOM |
| Crypto/PQC | `cryptography` + policy engine (CBOM classification) | Readiness 0-100, migration recs, kept separate from compliance |
| Reports | ReportLab | Per-device PDF |
| Data | In-memory stores (dev); Supabase Postgres + pgvector + pgcrypto (prod); Redis/Celery (prod jobs) | Assets, audits, findings, OKF, mappings, CVE, jobs |
| Deploy | Docker + Compose, Nginx (frontend image), GitHub repo | `docker compose up --build` (:8080 → :8000) |
| Auth | JWT (PyJWT), `ADMIN_EMAIL`/`ADMIN_PASSWORD` seed, `REQUIRE_AUTH` gate | Login + token auth; RBAC/encryption are prod scope |

Deliberately **not** added: Kubernetes, Kafka, Elasticsearch, Neo4j (NetworkX
suffices for the prototype graph), separate vector DB (pgvector covers it),
multiple LLMs, custom CVE-prediction model, quantum hardware dependency.

---

## 12. Prerequisites

- **Backend**: Python 3.12+, [`uv`](https://docs.astral.sh/uv/) package manager
- **Frontend**: Node.js 18+ and npm
- **Docker** (optional, for `docker-compose.yml` production stack)
- **Database**: none for local dev (in-memory stores); Supabase Postgres for production (see `DEPLOY.md`)

---

## 13. Run it (5 minutes, local dev)

```powershell
git clone https://github.com/Satish-vaishyar/Multi-Vendor-Security.git
cd Multi-Vendor-Security

# Terminal 1 - backend
cd backend
copy .env.example .env   # defaults work offline; add LLM/NVD keys later
uv sync
uv run pytest -q
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
# console: http://127.0.0.1:8000/ui   API docs: http://127.0.0.1:8000/docs

# Terminal 2 - frontend
cd frontend
npm install
npm run dev              # open the URL Vite prints (default http://localhost:5173)
```

Demo login: `admin@example.com` / `admin123` (change via `ADMIN_EMAIL` / `ADMIN_PASSWORD` in `backend/.env`).

> **New here?** Follow [`APPLICATION_SETUP.md`](APPLICATION_SETUP.md) - complete
> setup for every module (`backend/`, `frontend/`, `okf/`, `models/`, Docker),
> env reference, verification checklist, and troubleshooting.

> The frontend points at the backend via `frontend/.env.development`
> (`VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1`).
> If your backend runs elsewhere, edit that file and restart `npm run dev`.

---

## 14. Run it (production, Docker)

```powershell
copy backend\.env.example backend\.env   # fill JWT_SECRET, DATABASE_URL, CORS_ORIGINS
docker compose up --build
# Frontend http://localhost:8080 | Backend http://localhost:8000
```

Checklist (env, Supabase schema, verification, security notes): `DEPLOY.md`.

---

## 15. Documentation index

| Doc | Contents |
|---|---|
| `APPLICATION_SETUP.md` | **Complete setup for all modules** - prerequisites, backend, frontend, okf, models, Docker, env reference, verification, troubleshooting |
| `backend/docs/SETUP.md` | Prerequisites, install with `uv`, `.env` keys, running, verification, troubleshooting |
| `backend/docs/USER_GUIDE.md` | Starting the server, using the console tab-by-tab, training-loop demo, curl flows |
| `backend/docs/API_REFERENCE.md` | All 60 live endpoints (56 under `/api/v1`) with methods, payloads, examples |
| `backend/docs/IMPLEMENTATION.md` | Spec traceability: `arch.md` layers L1-L10 and `api.md` groups → code files |
| `backend/docs/RTM_PS.md` | SIH-26155 problem statement → implementation (10/10 features) |
| `backend/docs/TRM_ARCH.md` | `arch.md` → implementation traceability |
| `backend/docs/BUILD_STATUS.md` | Built vs missing vs extra w.r.t. the problem statement (gap analysis) |
| `backend/docs/ARCHITECTURE.md` | 2-page architecture (SIH evaluation deliverable) |
| `FRONTEND_GUIDE.md` | Frontend user guide: login → upload → audit → results → remediation |
| `DEPLOY.md` | Production hosting checklist (env, Supabase, Docker, verification) |
| `test-files/README.md` | What each sample config proves |
| `models/MODELS_PERFORMANCE.md` | M1-M13 scoreboard, matrices, stress results |
| `okf/RTM_OKF_CVE.md` | OKF + CVE requirement traceability |

---

## 16. Verification & test evidence

- `cd backend; uv run pytest -q` - 56 tests (upload→parse→canonical→audit→
  results→evidence→engines→findings→training→remediation dry-run→PDF,
  secure-vs-insecure ordering, OKF browser, M1 detection).
- `uv run pytest -q --cov` - 100% statement coverage over `app/`
  (`fail_under=100` enforced).
- `/health` → `{"success":true,"status":"healthy"}`; `/readyz` → readiness + DB.
- Sample proof: `test-files/01-cisco-insecure-router.txt` (low score) vs
  `02-cisco-secure-router.txt` (high score); `03-06` vendor auto-detection;
  `07-edge-unknown-tokens.txt` training queue (`blorp`/`hyperflux`).
- Models stress 13/13 PASS; M2 FPR 0.0, M7 FAR 0.0 (zero-breach safety metrics).

---

## 17. Security notes & limitations

- **Secrets live only in `backend/.env`** (git-ignored, never committed, excluded from
  Docker images via `backend/.dockerignore`). Copy from `backend/.env.example` and fill in.
- Never commit API keys (`FEATHERLESS_API_KEY`, `NVD_API_KEY`) or the Supabase
  `DATABASE_URL` - if a secret ever leaks into git history, **rotate it immediately**.
- Production requires a strong `JWT_SECRET` (the dev default is rejected), explicit
  `CORS_ORIGINS` (no `*`), and `REQUIRE_AUTH=true`. See `DEPLOY.md`.
- Honest roadmap (out of prototype scope): live SSH/Netmiko pull, full Postgres +
  Redis/Celery swap, config encryption at rest + 5-role RBAC, exhaustive FP/FN +
  PQC-accuracy harnesses, demo video + 5-slide deck.

---

## 18. References

- SIH 26155 problem statement (NTRO): https://sih2026.vuce.in/ps/SIH26155
- NIST OSCAL (machine-readable controls): https://csrc.nist.gov/projects/open-security-controls-assessment-language
- NVD APIs (CVE/CPE): https://nvd.nist.gov/developers
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- DISA STIGs: https://public.cyber.mil/stigs/
- ISO/IEC 27001: https://www.iso.org/standard/27001
- CERT-In guidelines: https://www.cert-in.org.in
- Sentence-Transformers (MiniLM-L6-v2): https://www.sbert.net
- HDBSCAN: https://hdbscan.readthedocs.io
- XGBoost: https://xgboost.readthedocs.io
- This repo: https://github.com/Satish-vaishyar/Multi-Vendor-Security
- In-repo spec: `docs/arch.md`, `docs/api.md`, `docs/models.md`, `docs/okf.md`, `docs/cve_okf.md`, `docs/tech_stack.md`, `docs/frontend.md`

---

*Built by **KT@UnseenGeeks** for SIH 2026 - vendor-neutral auditing with
deterministic verdicts, AI-assisted learning, and evidence you can appeal.*
