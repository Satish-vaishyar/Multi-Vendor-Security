# API reference — endpoints exposed once the server is up

Base URL `http://127.0.0.1:8000`, API root **`/api/v1`**.
Live list verified from the running server's `/openapi.json`: **49 routes**
(42 under `/api/v1`, plus `/`, `/health`, `/ui`, `/docs`, `/redoc`, `/openapi.json`).

Common envelope (`api.md` §3): success → `{success:true, data:{…}, message:"…"}`;
error → `{success:false, error:{code, message, details}}`.
Auth: `Authorization: Bearer <token>` from `POST /auth/login`
(demo `admin@example.com` / `admin123`). Status codes per `api.md` §36
(200/201/202/400/401/403/404/409/422/500).

## Meta / UI

| Method | Path | Notes |
|---|---|---|
| GET | `/` | service info + API group list |
| GET | `/health` | `{"success":true,"status":"healthy"}` |
| GET | `/ui` | HTML test console (API-only) |
| GET | `/docs`, `/redoc`, `/openapi.json` | Swagger / ReDoc / raw spec |

## Auth (§4)

| Method | Path | Body → response |
|---|---|---|
| POST | `/api/v1/auth/login` | `{"email","password"}` → `{access_token, token_type, expires_in, user{id,name,role}}` |
| GET | `/api/v1/auth/me` | (token) → `{id,name,email,role}` |

## Assets (§5)

| Method | Path |
|---|---|
| POST | `/api/v1/assets` — `{"name","vendor","product","model","version","serial_number","ip_address","environment","criticality"}` → `{asset_id,…,status:"ACTIVE"}` |
| GET | `/api/v1/assets?page=1&page_size=20&vendor=Cisco&status=ACTIVE` → `{items,page,page_size,total}` |
| GET | `/api/v1/assets/{asset_id}` |
| PATCH | `/api/v1/assets/{asset_id}` — partial metadata update |
| DELETE | `/api/v1/assets/{asset_id}` — soft-delete (`status:"DELETED"`) |

## Configurations (§6–9, §33)

| Method | Path |
|---|---|
| POST | `/api/v1/configurations/upload` — `multipart/form-data`: `file`, `asset_id`, optional `vendor`, `platform` → `{configuration_id,filename,size,status,detected_vendor,detected_platform,detected_version}` |
| POST | `/api/v1/configurations/bulk-upload` — `files[]` + `asset_id` → `{batch_id,total_files,accepted,rejected,configurations[]}` |
| POST | `/api/v1/configurations/{configuration_id}/parse` — normalize now → `{job_id,status:"COMPLETED"}` |
| GET | `/api/v1/configurations/{configuration_id}` — metadata + `{parser:{type,confidence}}` |
| GET | `/api/v1/configurations/{configuration_id}/canonical-ir` — the Canonical IR contract (§40) consumed by all engines |
| GET | `/api/v1/configurations/{configuration_id}/unknowns` — `{unknown_count,items[{id,line,context,status}]}` → feeds Training UI |

Example upload + canonical IR:

```bash
curl -s localhost:8000/api/v1/configurations/upload -F "file=@router.txt" -F "asset_id=AST-001"
curl -s localhost:8000/api/v1/configurations/CFG-…/canonical-ir | python -m json.tool
```

## Audits (§10–12, §31) — central orchestration

| Method | Path |
|---|---|
| POST | `/api/v1/audits` — `{"asset_id","configuration_id","frameworks":["CIS","NIST","STIG","ISO27001"],"run_cve":true,"run_pqc":true,"run_security_analysis":true,"generate_report":false}` → `{audit_id,status}` |
| GET | `/api/v1/audits/{audit_id}` — `{status,progress,stages{ingestion,normalization,compliance,cve,pqc,security,risk,report}}` |
| GET | `/api/v1/audits/{audit_id}/results` — `{summary{compliance_score,critical,high,medium,low},frameworks,cve,pqc,findings[],canonical_ir}` |
| GET | `/api/v1/audits/{audit_id}/evidence` — `{items[{control_id,property,observed_value,expected_value,source{configuration_id,line,line_no}}]}` |

## Compliance (§13)

| Method | Path |
|---|---|
| GET | `/api/v1/compliance/frameworks` — `[{id,name,version}]` (CIS, NIST, STIG, ISO27001, CERT-In) |
| GET | `/api/v1/compliance/{audit_id}` — overall score + per-framework breakdown |
| GET | `/api/v1/compliance/{audit_id}/framework/{framework}` — e.g. `/framework/NIST` |
| GET | `/api/v1/compliance/{audit_id}/controls` — control table for the UI |

## Vulnerabilities / CVE (§14–15)

| Method | Path |
|---|---|
| GET | `/api/v1/vulnerabilities/{audit_id}` — `{summary{total,critical,high,medium,low,unknown},items[]}` |
| GET | `/api/v1/vulnerabilities/{audit_id}/{finding_id}` — CVE detail (affected range, fixed version, CVSS, CPE, references) |
| GET | `/api/v1/vulnerabilities/cves?cve_id=&vendor=&product=&severity=` — local KB browser (max 200 rows) |
| POST | `/api/v1/vulnerabilities/sync` — `{"keyword","pages":1,"results_per_page":200,"products":["cisco ios xe"],"drop_seeds":false}` → `{job_id,status}` (NVD fetch; big pages + paced requests stay under rate limits) |
| GET | `/api/v1/vulnerabilities/kb/status` — `{records,nvd_records,seed_records,real_world}` (production matching uses NVD records only; seeds are offline fixtures) |
| GET | `/api/v1/vulnerabilities/sync/{job_id}` — sync job status |
| POST | `/api/v1/vulnerabilities/blast-radius` — `{"cve_id","assets":[{asset_id,vendor,product,version}]}` → per-asset VULNERABLE/NOT_AFFECTED/UNKNOWN |

## PQC (§16) · Security analytics (§17–18)

| Method | Path |
|---|---|
| GET | `/api/v1/pqc/{audit_id}` — `{readiness_score,algorithms[],weak_algorithms[],migration_recommendations[]}` |
| GET | `/api/v1/analytics/{audit_id}` — `{risk_score,anomalies[],patterns[]}` |
| POST | `/api/v1/analytics/fleet` — `{"asset_ids":[…]}` → `{job_id,status}` |
| GET | `/api/v1/analytics/fleet/{job_id}` — fleet job status |

## Findings (§19–20, unified schema)

| Method | Path |
|---|---|
| GET | `/api/v1/findings?severity=&type=&asset_id=&status=&audit_id=&engine=` — `type ∈ {COMPLIANCE,VULNERABILITY,SECURITY,PQC}` |
| GET | `/api/v1/findings/{finding_id}` — full record (evidence, risk, remediation, asset, source) |

## Training — adaptive vendor loop (§21–25)

| Method | Path |
|---|---|
| GET | `/api/v1/training/queue?status=PENDING` — `{items[{training_id,vendor,platform,raw_command,context,status}]}` |
| POST | `/api/v1/training/{training_id}/suggest` — `{suggestions[{canonical_property,value,confidence}]}` |
| POST | `/api/v1/training/{training_id}/approve` — `{"canonical_property","canonical_value","comment"}` → `{status:"APPROVED",mapping_id,registry_updated:true}` (persists to `okf/knowledge/mappings/learned/`) |
| POST | `/api/v1/training/{training_id}/reject` — `{"reason"}` |
| GET | `/api/v1/training/jobs/{job_id}` — background-job status |

## Remediation (§26–27, simulation only)

| Method | Path |
|---|---|
| GET | `/api/v1/remediation/{finding_id}` — `{vendor,platform,steps[{order,command}],validation[],rollback_available,approval_required}` |
| POST | `/api/v1/remediation/{finding_id}/approve` — `{"approved_by","comment"}` → approval `{id,…}` |
| POST | `/api/v1/remediation/{finding_id}/apply` — `{"id":"<approval-id>","updated_config_text":"…"}` → `{mode:"SIMULATION",device_touched:false,…}` + optional re-audit diff (`re_audit_status`,`verified_fixed`) |

## Reports (§28)

| Method | Path |
|---|---|
| POST | `/api/v1/reports` — `{"audit_id","format":"PDF","sections":[…]}` → `{report_id,status,download_url}` |
| GET | `/api/v1/reports/{report_id}` — `{status,download_url}` |
| GET | `/api/v1/reports/{report_id}/download` — `application/pdf` |

## Dashboard (§29) · OKF browser (§30) · Detection (§32)

| Method | Path |
|---|---|
| GET | `/api/v1/dashboard/summary` — `{assets,compliance{overall},findings{critical,high,medium,low},cve,pqc,training{pending}}` (single call for the home page) |
| GET | `/api/v1/okf/properties?category=` — 102 canonical properties |
| GET | `/api/v1/okf/controls?framework=&category=&severity=` — 70 controls |
| GET | `/api/v1/okf/controls/{control_id}` — control + rule + evidence + remediation + version |
| GET | `/api/v1/okf/crosswalk/{control_id}` — cross-framework mappings (CIS↔NIST↔STIG↔ISO) |
| POST | `/api/v1/detection/vendor` — `{"configuration_id"}` or `{"config_text"}` → `{vendor,platform,version,confidence,method}` |

## Frontend flow (what `/ui` calls, `api.md` §34)

```
POST /configurations/upload → CFG-… → POST /audits → AUD-… →
GET /audits/{id} → GET /audits/{id}/results → GET /findings?audit_id=… →
GET /audits/{id}/evidence → POST /reports → GET /reports/{id}/download
```

The frontend never calls NVD, the LLM, PostgreSQL, ML models or OKF directly.
To regenerate this list: start the server and open `/openapi.json`
(`paths` count = 49) or `/docs`.
