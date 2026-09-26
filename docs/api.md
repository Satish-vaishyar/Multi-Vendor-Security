Yes. Since your team follows a **backend-first, API-contract-first architecture**, I would design the backend as a proper platform rather than exposing APIs only for the screens.

The SIH problem explicitly requires unified ingestion, AI-powered training for unseen vendor formats, multi-framework compliance, actionable reporting, and vendor-agnostic scalability. ([SIH 2026 Problem Statements][1])

Below is the **API specification I would freeze for the first backend version**.

# SIH 26155 Backend API Specification

## 1. Overall API architecture

```text
Frontend
   │
   │ HTTPS / REST JSON
   ▼
┌───────────────────────────────────────────────┐
│                 FastAPI Backend                │
│                                               │
│  Auth / Users                                 │
│  Assets                                       │
│  Configurations                               │
│  Audits                                       │
│  Compliance                                   │
│  CVE                                          │
│  PQC                                          │
│  Security Analytics                           │
│  AI Training                                  │
│  Findings                                     │
│  Remediation                                  │
│  Reports                                      │
│  OKF                                          │
└───────────────────────┬───────────────────────┘
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
   PostgreSQL         Redis           Workers
        │                                │
        └───────────────┬────────────────┘
                        ▼
               ML / OKF / CVE
```

Base URL:

```text
/api/v1
```

For example:

```text
POST /api/v1/audits
GET  /api/v1/audits/{audit_id}
```

I strongly recommend versioning from day one.

---

# 2. API modules

I would expose **12 API groups**.

```text
/api/v1
│
├── auth
├── assets
├── configurations
├── audits
├── compliance
├── vulnerabilities
├── pqc
├── analytics
├── findings
├── training
├── remediation
├── reports
└── okf
```

---

# 3. Common API response format

Don't let every endpoint return a different structure.

Use a common wrapper.

### Success

```json
{
  "success": true,
  "data": {},
  "message": "Audit created successfully",
  "request_id": "req_123456"
}
```

### Error

```json
{
  "success": false,
  "error": {
    "code": "INVALID_CONFIGURATION",
    "message": "Configuration format could not be parsed",
    "details": {}
  },
  "request_id": "req_123456"
}
```

This makes frontend integration much easier.

---

# 4. Authentication APIs

## POST `/auth/login`

### Request

```json
{
  "email": "admin@example.com",
  "password": "********"
}
```

### Response

```json
{
  "success": true,
  "data": {
    "access_token": "eyJ...",
    "token_type": "bearer",
    "expires_in": 3600,
    "user": {
      "id": "USR-001",
      "name": "Admin",
      "role": "ADMIN"
    }
  }
}
```

Frontend stores the token and sends:

```text
Authorization: Bearer <token>
```

---

## GET `/auth/me`

Returns:

```json
{
  "id": "USR-001",
  "name": "Admin",
  "email": "admin@example.com",
  "role": "ADMIN"
}
```

---

# 5. Asset APIs

An asset is the actual device being audited.

Examples:

```text
Router
Switch
Firewall
SASE device
Cloud firewall
```

## POST `/assets`

### Request

```json
{
  "name": "Core-Router-01",
  "vendor": "Cisco",
  "product": "IOS-XE",
  "model": "Catalyst",
  "version": "17.9.4",
  "serial_number": "ABC123",
  "ip_address": "10.0.0.1",
  "environment": "PRODUCTION",
  "criticality": "HIGH"
}
```

### Response

```json
{
  "success": true,
  "data": {
    "asset_id": "AST-001",
    "name": "Core-Router-01",
    "vendor": "Cisco",
    "product": "IOS-XE",
    "version": "17.9.4",
    "status": "ACTIVE"
  }
}
```

---

## GET `/assets`

Supports:

```text
?page=1
&page_size=20
&vendor=Cisco
&status=ACTIVE
```

### Response

```json
{
  "success": true,
  "data": {
    "items": [],
    "page": 1,
    "page_size": 20,
    "total": 125
  }
}
```

---

## GET `/assets/{asset_id}`

Returns complete asset information.

---

## PATCH `/assets/{asset_id}`

Update asset metadata.

---

## DELETE `/assets/{asset_id}`

Soft-delete the asset.

---

# 6. Configuration APIs

This is one of your most important API groups.

The SIH requirement specifically calls for uploading single or bulk configuration files from network devices. ([SIH 2026 Problem Statements][1])

## POST `/configurations/upload`

Use `multipart/form-data`.

### Request

```text
file: router.txt
asset_id: AST-001
```

Optional:

```text
vendor: Cisco
platform: IOS-XE
```

If vendor is omitted:

```text
AI/vendor detection
```

### Response

```json
{
  "success": true,
  "data": {
    "configuration_id": "CFG-001",
    "filename": "router.txt",
    "size": 48291,
    "status": "UPLOADED",
    "detected_vendor": "Cisco",
    "detected_platform": "IOS-XE",
    "detected_version": "17.9.4"
  }
}
```

---

# 7. Bulk configuration upload

## POST `/configurations/bulk-upload`

### Request

```text
files[]: router1.txt
files[]: router2.txt
files[]: firewall1.conf
```

### Response

```json
{
  "batch_id": "BATCH-001",
  "total_files": 3,
  "accepted": 3,
  "rejected": 0,
  "configurations": [
    {
      "configuration_id": "CFG-001",
      "status": "QUEUED"
    },
    {
      "configuration_id": "CFG-002",
      "status": "QUEUED"
    }
  ]
}
```

---

# 8. Configuration parsing API

## POST `/configurations/{configuration_id}/parse`

Starts normalization.

### Response

```json
{
  "job_id": "JOB-001",
  "status": "QUEUED"
}
```

Don't make the frontend wait for a 30-second/2-minute parsing operation.

Use asynchronous jobs.

---

## GET `/configurations/{configuration_id}`

Returns:

```json
{
  "configuration_id": "CFG-001",
  "asset_id": "AST-001",
  "vendor": "Cisco",
  "platform": "IOS-XE",
  "version": "17.9.4",
  "status": "PARSED",
  "created_at": "...",
  "parser": {
    "type": "KNOWN_VENDOR",
    "confidence": 0.99
  }
}
```

---

# 9. Canonical IR API

This API is useful for debugging and the training interface.

## GET `/configurations/{configuration_id}/canonical-ir`

Example response:

```json
{
  "device": {
    "vendor": "Cisco",
    "platform": "IOS-XE",
    "version": "17.9.4"
  },

  "services": {
    "ssh": true,
    "telnet": false,
    "http": false,
    "https": true,
    "snmp": true
  },

  "aaa": {
    "authentication": true,
    "authorization": true
  },

  "logging": {
    "enabled": true,
    "remote_server": true
  },

  "crypto": {
    "ssh_version": 2
  },

  "software_components": []
}
```

This is the main contract between your **parser layer and OKF/analysis engines**.

---

# 10. Audit APIs

This should be the central orchestration API.

## POST `/audits`

### Request

```json
{
  "asset_id": "AST-001",

  "configuration_id": "CFG-001",

  "frameworks": [
    "CIS",
    "NIST",
    "STIG",
    "ISO27001"
  ],

  "run_cve": true,

  "run_pqc": true,

  "run_security_analysis": true,

  "generate_report": true
}
```

### Response

```json
{
  "success": true,
  "data": {
    "audit_id": "AUD-001",
    "status": "QUEUED"
  }
}
```

---

# 11. Audit status

## GET `/audits/{audit_id}`

Response:

```json
{
  "audit_id": "AUD-001",

  "status": "RUNNING",

  "progress": 68,

  "stages": {
    "ingestion": "COMPLETED",
    "normalization": "COMPLETED",
    "compliance": "RUNNING",
    "cve": "COMPLETED",
    "pqc": "PENDING",
    "security": "PENDING",
    "risk": "PENDING",
    "report": "PENDING"
  }
}
```

This lets the frontend show:

```text
Audit in progress
████████████░░░░ 68%
```

---

# 12. Audit result

## GET `/audits/{audit_id}/results`

Response:

```json
{
  "audit_id": "AUD-001",

  "summary": {
    "compliance_score": 78.4,
    "critical": 2,
    "high": 7,
    "medium": 11,
    "low": 4
  },

  "frameworks": {
    "CIS": {
      "score": 81
    },
    "NIST": {
      "score": 76
    },
    "STIG": {
      "score": 79
    },
    "ISO27001": {
      "score": 82
    }
  },

  "cve": {
    "vulnerable": 3,
    "not_affected": 41,
    "unknown": 2
  },

  "pqc": {
    "readiness": 64
  }
}
```

---

# 13. Compliance APIs

## GET `/compliance/frameworks`

Response:

```json
{
  "frameworks": [
    {
      "id": "CIS",
      "name": "CIS Benchmarks",
      "version": "..."
    },
    {
      "id": "NIST",
      "name": "NIST SP 800-53",
      "version": "Rev. 5"
    },
    {
      "id": "STIG",
      "name": "DISA STIG",
      "version": "..."
    },
    {
      "id": "ISO27001",
      "name": "ISO/IEC 27001",
      "version": "..."
    }
  ]
}
```

---

## GET `/compliance/{audit_id}`

Returns overall compliance.

---

## GET `/compliance/{audit_id}/framework/{framework}`

Example:

```text
GET /compliance/AUD-001/framework/NIST
```

Response:

```json
{
  "framework": "NIST",

  "score": 76,

  "controls": {
    "total": 100,
    "passed": 76,
    "failed": 20,
    "not_applicable": 4
  },

  "findings": []
}
```

---

## GET `/compliance/{audit_id}/controls`

Frontend can display the control table.

```json
{
  "items": [
    {
      "control_id": "AC-17",
      "title": "Remote Access",
      "status": "FAIL",
      "severity": "HIGH",
      "evidence": {}
    }
  ]
}
```

---

# 14. CVE APIs

This is where your enhanced CVE architecture becomes visible to the frontend.

## GET `/vulnerabilities/{audit_id}`

Response:

```json
{
  "summary": {
    "total": 8,
    "critical": 2,
    "high": 3,
    "medium": 2,
    "low": 1
  },

  "items": []
}
```

---

## GET `/vulnerabilities/{audit_id}/{finding_id}`

Detailed CVE:

```json
{
  "finding_id": "VULN-001",

  "cve_id": "CVE-XXXX-XXXX",

  "asset": "Core-Router-01",

  "product": "ExampleProduct",

  "installed_version": "7.2.3",

  "status": "VULNERABLE",

  "affected_range": {
    "start": "7.0",
    "end": "7.2.4"
  },

  "fixed_version": "7.2.5",

  "cvss": {
    "score": 9.1,
    "severity": "CRITICAL"
  },

  "cpe": "cpe:2.3:...",

  "references": []
}
```

---

# 15. CVE database APIs

For administrators:

## GET `/vulnerabilities/cves`

Filters:

```text
?cve_id=CVE-...
?vendor=Cisco
?product=IOS-XE
?severity=CRITICAL
```

---

## POST `/vulnerabilities/sync`

Starts NVD synchronization.

Response:

```json
{
  "job_id": "CVE-SYNC-001",
  "status": "QUEUED"
}
```

---

## GET `/vulnerabilities/sync/{job_id}`

```json
{
  "status": "RUNNING",
  "records_processed": 125000,
  "records_added": 320,
  "records_updated": 41
}
```

---

# 16. PQC APIs

## GET `/pqc/{audit_id}`

Response:

```json
{
  "readiness_score": 64,

  "algorithms": [
    {
      "algorithm": "RSA",
      "key_size": 2048,
      "status": "TRANSITION"
    },
    {
      "algorithm": "AES",
      "key_size": 256,
      "status": "READY"
    }
  ],

  "weak_algorithms": [],
  "migration_recommendations": []
}
```

---

# 17. Security Analytics APIs

## GET `/analytics/{audit_id}`

Response:

```json
{
  "risk_score": 72,

  "anomalies": [
    {
      "type": "CONFIGURATION_DEVIATION",
      "property": "LOGGING.REMOTE_SERVER",
      "severity": "HIGH"
    }
  ]
}
```

---

# 18. Fleet analytics

For multiple devices:

## POST `/analytics/fleet`

```json
{
  "asset_ids": [
    "AST-001",
    "AST-002",
    "AST-003"
  ]
}
```

Response:

```json
{
  "job_id": "FLEET-001",
  "status": "QUEUED"
}
```

Then:

```text
GET /analytics/fleet/FLEET-001
```

---

# 19. Findings API

This should be one unified API regardless of source.

## GET `/findings`

Filters:

```text
?severity=CRITICAL
&type=CVE
&asset_id=AST-001
&status=OPEN
```

Response:

```json
{
  "items": [
    {
      "finding_id": "F-001",
      "type": "CVE",
      "title": "...",
      "severity": "CRITICAL",
      "asset_id": "AST-001",
      "status": "OPEN"
    },
    {
      "finding_id": "F-002",
      "type": "COMPLIANCE",
      "title": "...",
      "severity": "HIGH",
      "asset_id": "AST-001",
      "status": "OPEN"
    }
  ]
}
```

---

# 20. Finding details

## GET `/findings/{finding_id}`

Return:

```text
Finding
Evidence
Source
Control
CVE
Risk
Remediation
Asset
Timeline
```

Example:

```json
{
  "finding_id": "F-001",

  "type": "CVE",

  "severity": "CRITICAL",

  "source": {
    "cve": "CVE-XXXX-XXXX"
  },

  "asset": {
    "id": "AST-001",
    "name": "Core-Router-01"
  },

  "evidence": {
    "property": "SOFTWARE.VERSION",
    "observed": "7.2.3"
  },

  "risk": {
    "score": 9.4
  },

  "remediation": {
    "available": true
  }
}
```

---

# 21. AI Training APIs

This is **one of the most important API groups** because it directly addresses the SIH adaptive-training requirement. The PS specifically asks for an interactive training interface where administrators map unrecognized command lines to security categories and the system learns without backend redeployment. ([SIH 2026 Problem Statements][1])

## GET `/training/queue`

Response:

```json
{
  "items": [
    {
      "training_id": "TR-001",

      "vendor": "Unknown",

      "platform": "Unknown",

      "raw_command": "set secure-mgmt ssh v2",

      "context": [
        "management",
        "security"
      ],

      "status": "PENDING"
    }
  ]
}
```

---

# 22. AI mapping suggestion

## POST `/training/{training_id}/suggest`

Backend runs:

```text
Embedding
+
Semantic search
+
LLM
```

Response:

```json
{
  "training_id": "TR-001",

  "suggestions": [
    {
      "canonical_property": "SSH.VERSION",
      "value": 2,
      "confidence": 0.94
    },
    {
      "canonical_property": "SSH.ENABLED",
      "value": true,
      "confidence": 0.78
    }
  ]
}
```

---

# 23. Human approval API

## POST `/training/{training_id}/approve`

Request:

```json
{
  "canonical_property": "SSH.VERSION",
  "canonical_value": 2,
  "comment": "Verified against vendor documentation"
}
```

Response:

```json
{
  "status": "APPROVED",

  "mapping_id": "MAP-001",

  "registry_updated": true,

  "retraining_required": true
}
```

---

# 24. Reject mapping

## POST `/training/{training_id}/reject`

```json
{
  "reason": "Incorrect semantic mapping"
}
```

---

# 25. Training status

## GET `/training/jobs/{job_id}`

```json
{
  "status": "COMPLETED",
  "samples_added": 126,
  "model_updated": true,
  "index_updated": true
}
```

---

# 26. Remediation APIs

## GET `/remediation/{finding_id}`

Response:

```json
{
  "finding_id": "F-001",

  "vendor": "Cisco",

  "platform": "IOS-XE",

  "steps": [
    {
      "order": 1,
      "command": "configure terminal"
    },
    {
      "order": 2,
      "command": "..."
    }
  ],

  "validation": [
    "show running-config"
  ],

  "rollback_available": true,

  "approval_required": true
}
```

---

# 27. Important: Don't expose "execute remediation" directly initially

For SIH:

```text
GET remediation
      ↓
Review
      ↓
Approve
      ↓
Apply
      ↓
Validate
```

So:

## POST `/remediation/{id}/approve`

and then:

## POST `/remediation/{id}/apply`

The backend should have authorization checks before anything is executed.

For your first demo, you can make `/apply` a **simulation/dry-run** rather than actually changing a network device.

---

# 28. Reports APIs

The PS explicitly calls for a comprehensive PDF report covering device identification, compliance findings, severity and device-specific remediation. ([SIH 2026 Problem Statements][1])

## POST `/reports`

```json
{
  "audit_id": "AUD-001",

  "format": "PDF",

  "sections": [
    "EXECUTIVE_SUMMARY",
    "DEVICE",
    "COMPLIANCE",
    "CVE",
    "PQC",
    "SECURITY",
    "REMEDIATION",
    "EVIDENCE"
  ]
}
```

Response:

```json
{
  "report_id": "REP-001",
  "status": "GENERATING"
}
```

---

## GET `/reports/{report_id}`

```json
{
  "report_id": "REP-001",
  "status": "COMPLETED",

  "download_url": "/api/v1/reports/REP-001/download"
}
```

---

## GET `/reports/{report_id}/download`

Returns:

```text
application/pdf
```

---

# 29. Dashboard API

Rather than making the frontend call 15 APIs just to load the home page, create an aggregated endpoint.

## GET `/dashboard/summary`

Response:

```json
{
  "assets": {
    "total": 125,
    "healthy": 84,
    "at_risk": 41
  },

  "compliance": {
    "overall": 78.4
  },

  "findings": {
    "critical": 8,
    "high": 23,
    "medium": 51,
    "low": 19
  },

  "cve": {
    "critical": 4,
    "high": 11
  },

  "pqc": {
    "ready": 61,
    "transition": 42,
    "at_risk": 22
  },

  "training": {
    "pending": 13
  }
}
```

This makes the frontend very simple.

---

# 30. OKF APIs

The frontend may need to display the knowledge system.

## GET `/okf/properties`

Returns canonical properties.

## GET `/okf/controls`

Filters:

```text
?framework=NIST
?category=SSH
?severity=HIGH
```

## GET `/okf/controls/{control_id}`

Returns:

```text
Control
Rule
Evidence
Framework mappings
Remediation
Version
```

## GET `/okf/crosswalk/{control_id}`

Returns:

```json
{
  "control_id": "NIST-AC-17",

  "mapped_controls": [
    {
      "framework": "CIS",
      "control_id": "..."
    },
    {
      "framework": "STIG",
      "control_id": "..."
    }
  ]
}
```

---

# 31. API for audit evidence

This is important for explainability.

## GET `/audits/{audit_id}/evidence`

Response:

```json
{
  "items": [
    {
      "control_id": "OKF-SSH-001",

      "property": "SSH.VERSION",

      "observed_value": 1,

      "expected_value": 2,

      "source": {
        "configuration_id": "CFG-001",
        "line_start": 43,
        "line_end": 43
      }
    }
  ]
}
```

This lets the frontend show:

> **Why did this fail?**

And then:

```text
SSH VERSION
Expected: 2
Found: 1

Evidence:
Line 43:
ip ssh version 1
```

This is extremely valuable during judging.

---

# 32. API for vendor detection

You can expose it separately for debugging/training.

## POST `/detection/vendor`

Request:

```json
{
  "configuration_id": "CFG-001"
}
```

Response:

```json
{
  "vendor": "Cisco",
  "platform": "IOS-XE",
  "version": "17.9.4",
  "confidence": 0.98
}
```

---

# 33. API for unknown vendor

## GET `/configurations/{id}/unknowns`

Response:

```json
{
  "unknown_count": 4,

  "items": [
    {
      "id": "UNK-001",

      "line": "set secure-management ssh v2",

      "context": [],

      "status": "PENDING_TRAINING"
    }
  ]
}
```

This feeds your Training UI.

---

# 34. API flow from frontend perspective

The frontend should not know how your backend works internally.

For example, when user uploads a configuration:

```text id="cbyl0m"
Frontend
   │
   │ POST /configurations/upload
   ▼
Backend
   │
   └── returns CFG-001
          │
          ▼
Frontend
   │
   │ POST /audits
   ▼
Backend
   │
   └── returns AUD-001
          │
          ▼
Frontend
   │
   │ GET /audits/AUD-001
   │
   │ GET /audits/AUD-001/results
   │
   │ GET /findings?audit_id=AUD-001
   ▼
Dashboard
```

The frontend does **not** call:

```text
NVD
LLM
PostgreSQL
ML model
OKF
```

directly.

Everything goes through your backend.

---

# 35. Long-running jobs

Don't make endpoints synchronous for expensive operations.

Use:

```text id="hlv4r9"
POST /audits
       ↓
202 Accepted
       ↓
audit_id
       ↓
GET /audits/{id}
```

Same for:

```text
CVE sync
Training
Fleet analytics
PDF generation
Bulk uploads
```

---

# 36. HTTP status codes

Standardise these.

| Status | Usage                   |
| ------ | ----------------------- |
| `200`  | Successful GET          |
| `201`  | Resource created        |
| `202`  | Background job accepted |
| `400`  | Invalid request         |
| `401`  | Authentication required |
| `403`  | Permission denied       |
| `404`  | Resource not found      |
| `409`  | Conflict                |
| `422`  | Validation error        |
| `500`  | Internal error          |

---

# 37. Backend project structure

I would now structure your FastAPI backend like:

```text
backend/
│
├── app/
│   ├── main.py
│   │
│   ├── api/
│   │   └── v1/
│   │       ├── auth.py
│   │       ├── assets.py
│   │       ├── configurations.py
│   │       ├── audits.py
│   │       ├── compliance.py
│   │       ├── vulnerabilities.py
│   │       ├── pqc.py
│   │       ├── analytics.py
│   │       ├── findings.py
│   │       ├── training.py
│   │       ├── remediation.py
│   │       ├── reports.py
│   │       ├── dashboard.py
│   │       └── okf.py
│   │
│   ├── schemas/
│   │   ├── asset.py
│   │   ├── configuration.py
│   │   ├── canonical_ir.py
│   │   ├── audit.py
│   │   ├── finding.py
│   │   ├── cve.py
│   │   ├── training.py
│   │   └── remediation.py
│   │
│   ├── services/
│   │   ├── audit_service.py
│   │   ├── compliance_service.py
│   │   ├── cve_service.py
│   │   ├── pqc_service.py
│   │   ├── training_service.py
│   │   └── report_service.py
│   │
│   ├── engines/
│   │   ├── parser/
│   │   ├── normalization/
│   │   ├── okf/
│   │   ├── compliance/
│   │   ├── cve/
│   │   ├── pqc/
│   │   ├── security/
│   │   └── risk/
│   │
│   ├── models/
│   │
│   ├── repositories/
│   │
│   ├── workers/
│   │
│   └── core/
│
├── okf/
├── models/
├── datasets/
├── migrations/
├── tests/
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

# 38. API dependency hierarchy

The most important thing is not to let APIs become tightly coupled.

```text
                    Dashboard
                       │
                       ▼
                  Audit API
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
    Compliance       CVE          PQC
          │            │            │
          └────────────┼────────────┘
                       ▼
                 Findings API
                       │
                       ▼
                 Risk Engine
                       │
                       ▼
                Remediation API
```

And underneath:

```text
Configuration
      ↓
Canonical IR
      ↓
OKF
```

---

# 39. APIs I would consider the MVP

Don't build all APIs on day one.

### Phase 1

```text
POST /auth/login

POST /assets
GET  /assets
GET  /assets/{id}

POST /configurations/upload
GET  /configurations/{id}

POST /audits
GET  /audits/{id}
GET  /audits/{id}/results

GET  /findings
GET  /findings/{id}
```

### Phase 2

```text
GET /compliance/{audit_id}
GET /compliance/{audit_id}/controls

GET /vulnerabilities/{audit_id}
GET /vulnerabilities/{audit_id}/{finding_id}

GET /pqc/{audit_id}
GET /analytics/{audit_id}
```

### Phase 3

```text
GET  /training/queue
POST /training/{id}/suggest
POST /training/{id}/approve
POST /training/{id}/reject

GET /remediation/{finding_id}
```

### Phase 4

```text
POST /reports
GET  /reports/{id}
GET  /reports/{id}/download

POST /vulnerabilities/sync
GET  /vulnerabilities/sync/{job_id}
```

---

# 40. One API contract that ties the whole system together

The **most important contract in your entire backend** is actually:

```text
Configuration → Canonical IR
```

Everything downstream should consume this.

```json
{
  "schema_version": "1.0",

  "device": {
    "vendor": "Cisco",
    "platform": "IOS-XE",
    "model": "Catalyst",
    "version": "17.9.4",
    "serial_number": "..."
  },

  "services": {},

  "aaa": {},

  "access_control": {},

  "logging": {},

  "crypto": {},

  "interfaces": [],

  "routing": [],

  "policies": [],

  "software_components": [],

  "unknown_tokens": []
}
```

Then:

```text
                    Canonical IR
                        │
        ┌───────────────┼─────────────────┐
        ▼               ▼                 ▼
       OKF             CVE               PQC
        │               │                 │
        ▼               ▼                 ▼
   Compliance       Vulnerabilities     Crypto
        │               │                 │
        └───────────────┼─────────────────┘
                        ▼
                 Unified Findings
```

That gives you a **clean backend/frontend separation**, while also making your backend internally modular. The frontend only needs to understand the API contracts and never needs to know whether a result came from Python rules, an ML model, NVD, the OKF, or an LLM.

For SIH 26155 specifically, this API-first architecture maps cleanly to the requested ingestion, adaptive training, multi-framework compliance and reporting requirements. ([SIH 2026 Problem Statements][1])

[1]: https://sih2026.vuce.in/ps/SIH26155?utm_source=chatgpt.com "SIH26155 · AI-Driven Multi-Vendor Network Security Compliance Auditor | SIH 2026 Problem Statements"
