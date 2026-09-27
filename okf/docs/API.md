# OKF API Reference - every route: request, response, why, analysis, client handling

Base URL: `http://127.0.0.1:8001` (port 8000 in this sandbox is held by a stale process; use 8001).
Interactive docs: `GET /docs` (Swagger UI) · machine schema: `GET /openapi.json` · test console: `/ui/`.
Auth: none in v1 (single-tenant lab build). Version: `1.1.0` (`okf_manifest.yaml`).

## Conventions (all routes)

**Success envelope** - every 200 response looks like:
```json
{ "success": true, "data": { "...": "..." }, "message": "ok" }
```
Always read payload from `data`, never from the top level.

**Error envelope** - failures look like:
```json
{ "success": false, "error": { "code": "NOT_FOUND | APPROVAL_REQUIRED | ...", "message": "..." } }
```
`code` values: `NOT_FOUND` (bad control/audit/CVE id), `APPROVAL_REQUIRED` (apply before approve).
HTTP status is 200 even for these application errors; only malformed JSON/bodies yield 422.

**`llm_offline` / `offline` flag** (audit + training responses): `false` = Featherless `openai/gpt-oss-120b`
answered live; `true` = deterministic heuristic fallback was used (no `FEATHERLESS_API_KEY` or the call
failed). Results are valid either way - deterministic registry values always win over LLM output.

## Behavior map - dynamic vs rule-based vs pre-set

| # | Route | Behavior | What that means |
|---|---|---|---|
| 1 | `GET /` | **Pre-set** | Static service info; same response always. |
| 2 | `POST /audit` | **Rule-based + dynamic gap-fill** | Verdicts come 100% from deterministic YAML rules over your config; the LLM only fills properties the registry missed (and loses on conflict). Score/findings change with input, rules don't. |
| 3 | `GET …/evidence` | **Rule-based lookup** | Deterministic join of stored findings + parse provenance. No AI, no new computation. |
| 4 | `GET /properties` | **Pre-set** | Static curated vocabulary (103 entries from YAML). |
| 5 | `GET /controls` | **Pre-set + filter** | Static 82-control pack; only the query filter varies the listing. |
| 6 | `GET /controls/{id}` | **Pre-set** | Static control + remediation join. |
| 7 | `GET /crosswalk/{id}` | **Pre-set** | Static framework map stored on the control. |
| 8 | `GET /frameworks` | **Pre-set** | Static registry (5 frameworks). |
| 9 | `GET /remediation/{id}` | **Pre-set** | Static vendor fix pack. |
| 10 | `POST …/approve` | **Stateful (human-driven)** | No AI/rules - records your approval decision with timestamp for the audit trail. |
| 11 | `POST …/apply` | **Rule-based simulation** | Dry-run planner + real re-audit of the config you supply; recomputed per call, never touches devices. |
| 12 | `POST …/suggest` | **Dynamic (AI)** | Live Featherless `gpt-oss-120b` call per request (heuristic fallback offline). Output varies run to run - always human-reviewed, never auto-applied. |
| 13 | `POST …/training/approve` | **Dynamic learning** | Writes to `mappings/learned/` and hot-reloads the registry - permanently changes future audit behavior. |
| 14 | `POST /cve/audit` | **Rule-based** | Deterministic CPE → KB → version-range math over your input. Zero LLM in the verdict path. |
| 15 | `POST /cve/sync` | **Dynamic (live fetch)** | Pulls fresh data from NVD over the network; results depend on NVD state, rate limits, and your `pages` param. |
| 16 | `GET /cve/kb` | **Pre-set snapshot** | Read-only view of whatever the KB currently holds (seeds + syncs). |
| 17 | `POST /cve/blast-radius` | **Rule-based** | Pure version-range computation over the CVE + asset list you post. |

Design intent: policy and verdicts are pre-set/rule-based (auditable, reproducible); AI and network are
used only for *input understanding* (route 2 gap-fill, route 12) and *fresh intelligence* (route 15) -
never for the security decision itself.

---

## 1. `GET /` - service discovery

**Why:** health check + endpoint index so clients (and the test console's "Check API" button) can verify
reachability and version without knowing the route table.
**Request:** none.
```powershell
curl http://127.0.0.1:8001/
```
**Response:** `{ success, service: "OKF", version, docs: "/docs", endpoints: [...], ui: "/ui (test console)" }`.
**Analysis:** static; no I/O.
**Client handling:** if this fails, the server isn't up - don't retry the other routes; start it with
`python -m uvicorn main:app --port 8001` from `F:\Multi-vendor\okf\`.

---

## 2. `POST /api/v1/okf/audit` - full compliance audit (the core route)

**Why:** the single call that turns a raw device config into scored, evidence-backed findings across
multiple frameworks. Everything else (evidence, remediation, reports) hangs off the `audit_id` it returns.
**Request body:**
```json
{
  "asset_id": "RTR-001",
  "vendor": "cisco",
  "platform": "ios-xe",
  "config_text": "hostname R1\nip ssh version 1\n...",
  "frameworks": ["CIS", "NIST", "STIG", "ISO27001", "CERT-In"],
  "asset_criticality": "HIGH"
}
```
| Field | Required | Notes |
|---|---|---|
| `config_text` | yes | raw CLI/config dump; `!`/`#` lines ignored |
| `vendor` | no (default `cisco`) | `cisco`/`juniper`/`fortinet`/`paloalto`/`arista`/`unknown`; selects deterministic mapping pack |
| `frameworks` | no | subset to evaluate; unknown names simply match nothing |
| `asset_criticality` | no | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`; scales risk scores |
| `asset_id`/`platform` | no | echoed into findings/provenance |

```powershell
$body = @{ asset_id="RTR-001"; vendor="cisco"; config_text=(Get-Content .\sample.txt -Raw); frameworks=@("CIS","NIST") } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8001/api/v1/okf/audit -Method Post -Body $body -ContentType "application/json"
```
**Response (`data`):**
```json
{
  "audit_id": "AUD-244150CE",
  "summary": { "compliance_score": 42.9, "total": 70, "passed": 30, "failed": 7,
               "unknown": 33, "CRITICAL": 2, "HIGH": 4, "MEDIUM": 1, "LOW": 0 },
  "by_framework": { "CIS": { "compliance_score": 50.0, "total": 20, "...": "..." } },
  "findings": [ {
      "finding_id": "F-OKF-SSH-001", "engine": "compliance", "control_id": "OKF-SSH-001",
      "title": "SSH version 2 must be enabled", "severity": "HIGH", "status": "FAIL",
      "asset_id": "RTR-001",
      "evidence": { "control_id": "OKF-SSH-001", "property": "SSH.VERSION",
                    "observed_value": 1, "expected_value": 2, "operator": "EQUALS", "status": "FAIL" },
      "remediation": { "vendors": { "cisco": { "commands": ["ip ssh version 2"], "...": "..." } },
                       "risk": { "risk_score": 7.5, "priority": "HIGH", "factors": { "...": "..." } } },
      "frameworks": { "CIS": "CIS-SSH-001", "NIST": "AC-17", "STIG": "V-220622", "ISO27001": "A.8.20" },
      "confidence": 1.0 } ],
  "canonical_ir": { "SSH": { "VERSION": 1 }, "TELNET": { "ENABLED": true } },
  "provenance": { "SSH.VERSION": { "line": "ip ssh version 1", "line_no": 2, "source": "curated", "confidence": 1.0 } },
  "unknown_lines": ["blorp enable hyperflux-mode"],
  "llm_offline": false
}
```
Field notes: `compliance_score` = 100·passed/total (one decimal). `status` per finding is
`PASS`/`FAIL`/`UNKNOWN` (`UNKNOWN` = property absent from IR - never silently treated as pass).
`audit_id` = `AUD-` + first 8 hex of SHA-256(config) - identical configs give identical ids (dedup-friendly).
**How backend analyses** (`src/api_okf.py:audit` → `learning_engine.audit_config` → `engines.ComplianceEngine`):
1. `MappingRegistry.to_canonical_ir` applies curated regexes line-by-line (provenance recorded).
2. Uncovered lines go to `llm_gateway.parse_config_to_ir` (Featherless gpt-oss-120b, or heuristic offline);
   LLM values are type-coerced (`"2"`→`2`) and only fill properties determinism missed.
3. Flat IR is nested (`SSH.VERSION`→`SSH:{VERSION}`); each control's YAML condition (`EQUALS`/`GTE`/`IN`/`all`/`any`…)
   is evaluated; `RiskEngine` scores every finding.
4. Result is stored in the in-memory `AUDITS` dict with config hash + knowledge versions (reproducibility).
**Client handling:** render `summary` as headline; group `findings` by `status` then `severity`;
link each FAIL to `GET …/evidence` (same `audit_id`) and to remediation via `control_id`;
surface `unknown_lines` as the entry point to the training tab; show an "AI assisted" badge when
`llm_offline` is false. Empty `config_text` yields mostly `UNKNOWN` - treat as "nothing parsed", not "secure".

---

## 3. `GET /api/v1/okf/audit/{audit_id}/evidence` - why-did-this-fail chain

**Why:** explainability (api.md §31). Turns each finding into control → property → observed/expected →
exact source line, so an auditor/judge can trust the verdict.
**Request:** `GET /api/v1/okf/audit/AUD-244150CE/evidence` (id from route 2).
**Response (`data`):** `{ "audit_id": "...", "items": [ { "control_id": "OKF-SSH-001", "property": "SSH.VERSION", "observed_value": 1, "expected_value": 2, "status": "FAIL", "source": { "line": "ip ssh version 1", "line_no": 2, "confidence": 1.0 } } ] }` - one item per finding, including PASS rows (proof of compliance, not just failure).
**Analysis:** pure lookup in the stored audit; joins each finding's evidence with the parse `provenance` map.
`source.line_no` may be null when the value came from the LLM rather than a registry line.
**Client handling:** render as a table under the findings list; `NOT_FOUND` means the id is wrong or the
server restarted (store is in-memory - re-run the audit to recreate it). In production this would be a DB row.

---

## 4. `GET /api/v1/okf/properties[?category=]` - canonical vocabulary

**Why:** exposes the 103-property registry so UIs, training screens and API clients use the same closed
vocabulary the LLM is constrained to (prevents hallucinated property names).
**Request:** optional `category` ∈ remote_access|authentication|monitoring|logging|system|access_control|crypto|network|management|software.
**Response (`data`):** list of `{ property_id, category, datatype, allowed_values, security_level, description, default_expected }`, e.g. `{ "property_id": "SSH.VERSION", "datatype": "enum", "allowed_values": [1,2], "default_expected": 2, ... }`.
**Analysis:** loads `knowledge/properties/*.yaml` via `PropertyRegistry` at startup.
**Client handling:** populate dropdowns (training-approve property picker); `allowed_values` drives input
validation; `default_expected` explains what "compliant" looks like.

---

## 5. `GET /api/v1/okf/controls[?framework=&category=&severity=]` - control catalog

**Why:** lets clients browse/filter the 82-control knowledge pack before auditing (e.g. "show me all
CRITICAL CIS controls").
**Request:** combinable filters, e.g. `/controls?framework=NIST&severity=HIGH`. Framework match is
case-insensitive against each control's `frameworks` map.
**Response (`data`):** list of controls `{ control_id, title, description, category, severity, version, frameworks:{CIS:…,NIST:…}, condition:{…}, evidence_type, remediation_id, references }`.
**Analysis:** in-memory filter over `ControlKB` (YAML loaded at startup).
**Client handling:** render catalog table; `condition` is shown read-only (it *is* the executable rule);
use `control_id` to drill into route 6 or remediation route 8.

---

## 6. `GET /api/v1/okf/controls/{control_id}` - control detail + remediation

**Why:** single pane for one rule: the executable condition, framework mappings, version, plus its fix.
**Response (`data`):** control object plus `"remediation": { "control_id", "title", "vendors": { "cisco": { "commands", "validation", "rollback", "approval_required" }, ... } }` (empty object if no vendor pack yet).
**Errors:** `NOT_FOUND` for unknown ids - validate against route 5 first.
**Client handling:** "detail drawer" behind a findings row; the remediation block feeds route 8's display.

---

## 7. `GET /api/v1/okf/crosswalk/{control_id}` - framework equivalence

**Why:** proves one fix satisfies many frameworks (the OKF crosswalk story): e.g. fixing SSH covers
CIS + NIST AC-17 + STIG + ISO A.8.20 at once.
**Response (`data`):** `{ "control_id": "OKF-SSH-001", "mapped_controls": [ {"framework":"CIS","control_id":"CIS-SSH-001"}, {"framework":"NIST","control_id":"AC-17"}, ... ] }`.
**Analysis:** reads the control's own `frameworks` map (single source of truth, shared with crosswalk YAML).
**Client handling:** render as chips/badges on control detail; unknown id returns empty `mapped_controls`.

---

## 8. `GET /api/v1/okf/frameworks` - framework registry

**Why:** declares which compliance frameworks the deployment knows (CIS, NIST, STIG, ISO27001, CERT-In)
with versions/publishers - needed for report headers and audit scoping.
**Response (`data`):** list of `{ framework_id, name, version, publisher, source, control_ids[] }`.
**Client handling:** populate the audit scope checkboxes; display `control_ids` counts per framework.

---

## 9. `GET /api/v1/okf/remediation/{control_id}[?vendor=]` - fix plan (read-only)

**Why:** converts a failed finding into vendor-specific fix commands + validation + rollback info
without executing anything.
**Response (`data`):** `{ control_id, vendor, title, commands[], validation[], rollback[], approval_required, rollback_available }`, e.g. Telnet/cisco → `["line vty 0 4", "transport input ssh"]`.
**Errors:** `NOT_FOUND` if the control has no remediation entry.
**Client handling:** show commands as a reviewable diff; if `approval_required` is true, force the
route-10 approve step in the UI before enabling Apply.

---

## 10. `POST /api/v1/okf/remediation/{control_id}/approve` - human gate

**Why:** safety workflow (Generate→Review→**Approve**→Apply): no fix may run without a recorded human
decision (`approved_by`, comment, timestamp kept in `REM_APPROVALS`).
**Request:** `{ "approved_by": "admin", "comment": "..." }` (both optional).
**Response (`data`):** `{ "approval_id": "REM-OKF-TELNET-001-42311", "control_id": "...", "approved_by": "...", "comment": "...", "status": "APPROVED" }`.
**Client handling:** store `approval_id`; it is single-use-scoped to this control and required by route 11.

---

## 11. `POST /api/v1/okf/remediation/{control_id}/apply` - dry-run apply + verify

**Why:** closes the loop safely: simulates the fix and, given the *fixed* config, re-audits to prove
the finding is gone - without ever touching a live device (`device_touched: false` always).
**Request:** `{ "approval_id": "REM-…", "updated_config_text": "<paste fixed config>" }`.
**Response (`data`):** `{ control_id, mode: "SIMULATION", commands_that_would_run[], validation[], device_touched: false, re_audit_status: "PASS"|"FAIL"|"UNKNOWN", verified_fixed: true|false }` (`re_audit_*` only when `updated_config_text` supplied).
**Errors:** `APPROVAL_REQUIRED` when the id is missing/foreign - call route 10 first.
**Client handling:** three-step wizard (Get plan → Approve → Apply); green-check only when
`verified_fixed === true`; otherwise loop back to editing the config.

---

## 12. `POST /api/v1/okf/training/suggest` - AI mapping proposals

**Why:** the adaptive loop's entry point: for an unknown-vendor line, propose top candidate canonical
mappings with confidence so a human can approve instead of guessing.
**Request:** `{ "raw_command": "set mgmt-secure ssh protocol v2", "vendor": "unknown", "context": ["…"] }`.
**Response (`data`):** `{ "training_suggestions": [ {"canonical_property": "SSH.VERSION", "value": 2, "confidence": 0.94} ], "model": "openai/gpt-oss-120b", "offline": false }`.
**Analysis:** online → Featherless chat constrained to the closed property vocabulary (values type-coerced);
offline/failure → heuristic + low-confidence generic fallback. Only vocabulary-listed properties are returned.
**Client handling:** render suggestions as radio options with confidence bars; on select, pre-fill route 13's
form (property + value); low confidence (<0.5) should prompt manual review, not auto-approve.

---

## 13. `POST /api/v1/okf/training/approve` - learn a mapping

**Why:** makes the system learn: the approved vendor-syntax→canonical mapping is appended to
`knowledge/mappings/learned/` and the registry reloads, so the next audit recognizes the line automatically.
**Request:** `{ "vendor": "unknown", "platform": "any", "pattern": "mgmt-secure\\s+ssh\\s+protocol\\s+v2", "canonical_property": "SSH.VERSION", "canonical_value": 2 }` - `pattern` is a Python regex matched case-insensitively; keep it tight (anchor distinctive tokens) to avoid over-matching.
**Response (`data`):** the stored `VendorMapping` (`vendor, platform, raw_command_pattern, canonical_property, canonical_value, confidence, source: "human_verified", status: "approved"`), message "Mapping approved and registry updated".
**Client handling:** after success, re-run the audit and confirm the line disappeared from `unknown_lines`;
a "reject" path is UI-side only (simply don't call this route).

---

## 14. `POST /api/v1/okf/cve/audit` - vulnerability correlation

**Why:** answers "is this device's software version publicly vulnerable?" deterministically from the
local CVE KB (seeded) or NVD-synced data - the LLM never invents CVEs.
**Request:** `{ "asset_id": "RTR-001", "vendor": "cisco", "product": "ios_xe", "version": "17.9.2", "config_text": "Cisco IOS-XE version 17.9.2\n..." }` - version/product may come from fields or be regex-extracted from `config_text` (OS + service hints).
**Response (`data`):**
```json
{
  "asset_id": "RTR-001",
  "components": [ { "vendor": "cisco", "product": "ios_xe", "version": "17.9.2", "component_type": "operating_system", "cpe": "cpe:2.3:o:cisco:ios_xe:17.9.2:*:*:*:*:*:*:*", "source": "config_regex" } ],
  "summary": { "total": 3, "vulnerable": 1, "not_affected": 0, "unknown": 2 },
  "matches": [ { "asset_id": "RTR-001", "cve_id": "CVE-2024-99902", "product": "ios_xe",
      "installed_version": "17.9.2", "status": "VULNERABLE",
      "matched_rule": { "start": "17.6", "start_inclusive": true, "end": "17.9.3", "end_inclusive": true, "fixed": "17.9.4" },
      "fixed_version": "17.9.4", "cvss": { "score": 8.8, "severity": "HIGH", "vector": "…" },
      "cpe": "cpe:2.3:o:cisco:ios_xe:*:…", "references": [],
      "evidence": { "source": "configuration", "version": "17.9.2" },
      "confidence": { "cpe_confidence": 0.99, "version_confidence": 0.98, "correlation_confidence": 0.97 } } ],
  "findings": [ { "finding_id": "F-CVE-0001", "engine": "cve", "type": "VULNERABILITY", "source": "CVE",
      "severity": "HIGH", "status": "FAIL", "remediation": { "recommendation": "Upgrade to 17.9.4", "fixed_version": "17.9.4" }, "risk": {} } ],
  "cbom": [ { "asset_id": "RTR-001", "protocol": "operating_system", "algorithm": "cisco/ios_xe 17.9.2", "usage": "software", "klass": "classical", "pqc_status": "unknown" } ]
}
```
Three states matter: `VULNERABLE` (version inside an affected range), `NOT_AFFECTED` (product known, version outside), `UNKNOWN` (product/version unresolvable - displayed as "cannot rule out", never as clean).
**Analysis** (`src/cve/`): inventory extract → alias-aware CPE resolve (`IOS-XE`→`ios_xe`) → KB candidate lookup → `version_range.match_record` with inclusive/exclusive bounds on normalized versions (`17.9.4a`, `R81.10`, `22.4R3` handled) → CVSS/CWE enrichment → unified findings + CBOM rows.
**Client handling:** badge counts from `summary`; expandable match rows showing range vs installed + fixed version; `UNKNOWN` rows need a product/version correction flow (re-submit with explicit fields); `findings` merge into the same findings table as compliance with `engine: cve` filter.

---

## 15. `POST /api/v1/okf/cve/sync` - refresh CVE KB from NVD

**Why:** keeps vulnerability intelligence current without redeploying (new CVEs → re-correlate fleet).
**Request:** `{ "keyword": "cisco", "pages": 1, "results_per_page": 20 }` - all optional; omit `keyword` for latest CVEs. Uses `NVD_API_KEY` env if set (higher rate limit).
**Response (`data`):** `{ "ok": true, "added": 18, "updated": 2, "total": 25 }`, or `{ "ok": false, "error": "…" }` offline (KB keeps serving stale data; never blocks audits).
**Client handling:** admin button with progress state; after sync, re-run route 14 audits; NVD is heavily rate-limited without a key - keep `pages` small in demos.

---

## 16. `GET /api/v1/okf/cve/kb` - KB inventory

**Why:** transparency into what the CVE engine knows (record count + ids) - lets testers confirm seeds or syncs landed.
**Response (`data`):** `{ "records": 5, "ids": ["CVE-2024-99901", …] }` (ids capped at 100).
**Client handling:** admin/health panel; empty `records` explains all-`UNKNOWN` CVE results.

---

## 17. `POST /api/v1/okf/cve/blast-radius` - new CVE vs my fleet

**Why:** incident response ("Log4j-style"): given one CVE and an asset inventory, split the fleet into
VULNERABLE / NOT_AFFECTED / UNKNOWN without auditing each device.
**Request:** `{ "cve_id": "CVE-2024-99904", "assets": [ {"asset_id":"FW-001","vendor":"fortinet","product":"fortios","version":"7.2.2"}, {"asset_id":"FW-003","vendor":"fortinet","product":"fortios","version":"7.4.0"} ] }`.
**Response (`data`):** `{ "cve_id": "…", "assets": [ {…,"status":"VULNERABLE"}, {…,"status":"NOT_AFFECTED"} ], "vulnerable": [ … ] }`.
**Errors:** `NOT_FOUND` for unknown CVE ids (check route 16 first).
**Client handling:** render `vulnerable[]` as the action list (upgrade tickets), greys for clean, amber for
`UNKNOWN` (missing version data - request clarification, don't assume safe).

---

## Quick test script (entire API in 6 calls)

```powershell
$B = "http://127.0.0.1:8001"
Invoke-RestMethod "$B/"                                                              # 1. health
$body = @{ asset_id="RTR-001"; vendor="cisco"; config_text="hostname R1`nip ssh version 1`nip http server`ntransport input telnet`nsnmp-server community public RO"; frameworks=@("CIS","NIST") } | ConvertTo-Json
$a = Invoke-RestMethod "$B/api/v1/okf/audit" -Method Post -Body $body -ContentType "application/json"   # 2. audit
Invoke-RestMethod "$B/api/v1/okf/audit/$($a.data.audit_id)/evidence"                 # 3. evidence
Invoke-RestMethod "$B/api/v1/okf/remediation/OKF-TELNET-001?vendor=cisco"             # 4. fix plan
$cve = @{ asset_id="RTR-001"; vendor="cisco"; product="ios_xe"; version="17.9.2"; config_text="Cisco IOS-XE version 17.9.2" } | ConvertTo-Json
Invoke-RestMethod "$B/api/v1/okf/cve/audit" -Method Post -Body $cve -ContentType "application/json"     # 5. CVE
$s = @{ raw_command="set mgmt-secure ssh protocol v2"; vendor="unknown" } | ConvertTo-Json
Invoke-RestMethod "$B/api/v1/okf/training/suggest" -Method Post -Body $s -ContentType "application/json" # 6. training
```
