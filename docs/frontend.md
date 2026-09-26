# SIH 26155

## AI-Driven Multi-Vendor Network Security Compliance Auditor

### Frontend Development & Backend Integration Specification

**Document Version:** 1.0
**Frontend:** React + Vite + TypeScript
**UI:** Tailwind CSS
**Charts:** Recharts
**Backend:** FastAPI REST API
**API Base:** `/api/v1`

---

# 1. Purpose of This Document

This document defines everything required to build the frontend for the SIH 26155 Network Security Compliance Auditor.

The frontend must:

1. Provide a professional security-audit dashboard.
2. Allow users to upload network configurations.
3. Start and monitor audits.
4. Display vendor detection and configuration normalization.
5. Display multi-framework compliance results.
6. Display CVE/vulnerability findings.
7. Display PQC/cryptographic readiness.
8. Display security analytics.
9. Display AI-generated unknown-command mappings.
10. Allow administrators to approve/reject AI mappings.
11. Display remediation recommendations.
12. Generate and download audit reports.
13. Communicate with the backend **only through REST APIs**.

The frontend must not directly communicate with:

* PostgreSQL
* Redis
* NVD
* LLM providers
* ML models
* OKF files
* Python services
* CVE databases

All such communication happens through the backend.

---

# 2. Frontend Architecture

Use the following architecture:

```text
                    FRONTEND
                       │
                       │ REST / JSON
                       ▼
              ┌──────────────────┐
              │   FastAPI API    │
              └────────┬─────────┘
                       │
       ┌───────────────┼────────────────┐
       ▼               ▼                ▼
   Compliance         CVE              PQC
   Engine             Engine           Engine
       │               │                │
       └───────────────┼────────────────┘
                       ▼
                Unified Findings
                       │
                       ▼
                  Remediation
```

The frontend should only care about the API contracts.

---

# 3. Technology Stack

## Required

```text
React
Vite
TypeScript
Tailwind CSS
React Router
Axios
Recharts
Lucide React
```

Recommended supporting libraries:

```text
TanStack Query
React Hook Form
Zod
Sonner
date-fns
```

### Why TypeScript?

All backend responses have structured schemas. TypeScript should mirror those schemas so that frontend/backend integration errors are caught during development.

---

# 4. Frontend Project Structure

Use:

```text
frontend/
│
├── src/
│   │
│   ├── api/
│   │   ├── client.ts
│   │   ├── auth.api.ts
│   │   ├── dashboard.api.ts
│   │   ├── assets.api.ts
│   │   ├── configurations.api.ts
│   │   ├── audits.api.ts
│   │   ├── compliance.api.ts
│   │   ├── vulnerabilities.api.ts
│   │   ├── pqc.api.ts
│   │   ├── analytics.api.ts
│   │   ├── findings.api.ts
│   │   ├── training.api.ts
│   │   ├── remediation.api.ts
│   │   ├── reports.api.ts
│   │   └── okf.api.ts
│   │
│   ├── components/
│   │   ├── common/
│   │   ├── layout/
│   │   ├── dashboard/
│   │   ├── assets/
│   │   ├── audit/
│   │   ├── compliance/
│   │   ├── vulnerabilities/
│   │   ├── pqc/
│   │   ├── analytics/
│   │   ├── findings/
│   │   ├── training/
│   │   ├── remediation/
│   │   └── reports/
│   │
│   ├── pages/
│   │   ├── Login.tsx
│   │   ├── Dashboard.tsx
│   │   ├── Assets.tsx
│   │   ├── AssetDetails.tsx
│   │   ├── UploadConfiguration.tsx
│   │   ├── AuditDetails.tsx
│   │   ├── Compliance.tsx
│   │   ├── Vulnerabilities.tsx
│   │   ├── VulnerabilityDetails.tsx
│   │   ├── PQC.tsx
│   │   ├── SecurityAnalytics.tsx
│   │   ├── Findings.tsx
│   │   ├── FindingDetails.tsx
│   │   ├── Training.tsx
│   │   ├── Remediation.tsx
│   │   ├── Reports.tsx
│   │   └── Settings.tsx
│   │
│   ├── hooks/
│   ├── stores/
│   ├── types/
│   ├── utils/
│   ├── constants/
│   ├── routes/
│   └── App.tsx
│
├── public/
├── .env
├── package.json
└── vite.config.ts
```

---

# 5. Environment Configuration

Create:

```text
.env.development
.env.production
```

Example:

```env
VITE_API_BASE_URL=http://localhost:8000/api/v1
```

Production:

```env
VITE_API_BASE_URL=https://api.yourdomain.com/api/v1
```

Never hardcode:

```text
http://localhost:8000
```

inside individual components.

---

# 6. API Client

Create one Axios instance.

```text
src/api/client.ts
```

It should handle:

* Base URL
* Authorization token
* JSON headers
* Request errors
* 401 handling
* Common API response format

Expected backend response:

```json
{
  "success": true,
  "data": {},
  "message": "Success",
  "request_id": "req_123"
}
```

Error:

```json
{
  "success": false,
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid request",
    "details": {}
  },
  "request_id": "req_123"
}
```

---

# 7. Global Application Layout

After login, the application should have:

```text
┌───────────────────────────────────────────────────────────────┐
│ Logo / Product Name                  Notifications  User      │
├───────────────┬───────────────────────────────────────────────┤
│               │                                               │
│ Dashboard     │                                               │
│ Assets        │                                               │
│ Configurations│                 MAIN CONTENT                  │
│ Audits        │                                               │
│ Compliance    │                                               │
│ Vulnerabilities                                               │
│ PQC           │                                               │
│ Analytics     │                                               │
│ Findings      │                                               │
│ AI Training   │                                               │
│ Remediation   │                                               │
│ Reports       │                                               │
│               │                                               │
│ Settings      │                                               │
└───────────────┴───────────────────────────────────────────────┘
```

Desktop-first design is acceptable because this is an enterprise security platform.

However, the application should remain usable on tablet/mobile widths.

---

# 8. Navigation

Main sidebar:

```text
Dashboard
Assets
Configurations
Audits
Compliance
Vulnerabilities
PQC Security
Security Analytics
Findings
AI Training
Remediation
Reports
Settings
```

Use icons consistently.

Suggested icons:

```text
Dashboard        LayoutDashboard
Assets           Server
Configurations   FileCode
Audits           ClipboardCheck
Compliance       ShieldCheck
Vulnerabilities  Bug
PQC              KeyRound
Analytics        Activity
Findings         AlertTriangle
Training         BrainCircuit
Remediation      Wrench
Reports          FileText
Settings         Settings
```

---

# 9. Login Page

Route:

```text
/login
```

Fields:

```text
Email
Password
```

Button:

```text
Sign In
```

API:

```http
POST /api/v1/auth/login
```

On successful login:

```text
Store access token
       ↓
Load /auth/me
       ↓
Redirect /dashboard
```

Do not display raw API errors.

Convert them into user-friendly messages.

---

# 10. Dashboard

Route:

```text
/dashboard
```

The dashboard is the main screen.

API:

```http
GET /api/v1/dashboard/summary
```

---

## Dashboard layout

### Header

```text
Security Overview
Last updated: 10:42 AM

[Run New Audit]
```

---

## KPI cards

Display:

```text
Total Assets
Assets At Risk
Compliance Score
Critical Findings
High Findings
Open CVEs
PQC Readiness
Pending AI Mappings
```

Example:

```text
┌─────────────┐
│ 125         │
│ Total Assets│
└─────────────┘

┌─────────────┐
│ 78.4%       │
│ Compliance  │
└─────────────┘

┌─────────────┐
│ 8           │
│ Critical    │
└─────────────┘
```

---

# 11. Dashboard Charts

### Compliance by Framework

Bar chart:

```text
CIS       █████████ 81%
NIST      ████████  76%
STIG      ████████  79%
ISO       █████████ 82%
```

API data comes from:

```http
GET /api/v1/dashboard/summary
```

---

### Findings by Severity

Donut chart:

```text
Critical
High
Medium
Low
```

---

### Vulnerability Overview

Show:

```text
Critical CVEs
High CVEs
Medium CVEs
Low CVEs
```

---

### PQC Readiness

Show:

```text
PQC Ready
Transition Required
At Risk
```

---

### AI Training Queue

Show:

```text
13 Unknown Mappings Pending
```

Clicking it navigates to:

```text
/training
```

---

# 12. Assets Page

Route:

```text
/assets
```

API:

```http
GET /api/v1/assets
```

Table:

| Asset          | Vendor   | Platform | Version | Criticality | Status | Risk     |
| -------------- | -------- | -------- | ------- | ----------- | ------ | -------- |
| Core-Router-01 | Cisco    | IOS-XE   | 17.9.4  | High        | Active | High     |
| FW-01          | Fortinet | FortiOS  | 7.x     | Critical    | Active | Critical |

Features:

```text
Search
Vendor filter
Status filter
Criticality filter
Pagination
Sort
```

---

# 13. Asset Details Page

Route:

```text
/assets/:assetId
```

API:

```http
GET /api/v1/assets/{asset_id}
```

Show:

```text
Asset Information
Vendor
Product
Platform
Version
IP
Environment
Criticality
Last Audit
Risk
```

Tabs:

```text
Overview
Configurations
Audits
Findings
CVEs
Compliance
PQC
```

---

# 14. Configuration Upload Page

Route:

```text
/configurations/upload
```

This should be one of the most polished screens.

---

## Upload interface

```text
┌─────────────────────────────────────────────┐
│                                             │
│        Drag & Drop Configuration            │
│                                             │
│          or [Browse Files]                  │
│                                             │
│ Supported: .txt .cfg .conf .yaml .json     │
│                                             │
└─────────────────────────────────────────────┘
```

Allow:

```text
Single file
Multiple files
```

Optional fields:

```text
Asset
Vendor
Platform
```

Vendor/platform should be optional because the system must support automatic detection.

---

# 15. Upload API

```http
POST /api/v1/configurations/upload
Content-Type: multipart/form-data
```

Request:

```text
file
asset_id
vendor?
platform?
```

Response:

```json
{
  "configuration_id": "CFG-001",
  "status": "UPLOADED",
  "detected_vendor": "Cisco",
  "detected_platform": "IOS-XE"
}
```

After upload:

```text
Upload
 ↓
Configuration details
 ↓
[Start Audit]
```

---

# 16. Configuration Details

Route:

```text
/configurations/:configurationId
```

Display:

```text
Filename
Vendor
Platform
Version
Upload Date
Parser Type
Parser Confidence
Status
```

Tabs:

```text
Raw Configuration
Canonical IR
Unknown Tokens
Parsing Information
```

---

# 17. Raw Configuration Viewer

Use a code editor/viewer style.

Example:

```text
1  hostname CORE-R1
2  ip domain-name example.local
3  ip ssh version 2
4  no ip http server
5  logging 10.0.0.20
```

Important:

**Do not allow editing unless explicitly implemented as a separate feature.**

Initially make it read-only.

---

# 18. Canonical IR Viewer

Display the normalized configuration in human-readable sections:

```text
Device
Services
AAA
Logging
Crypto
Access Control
Interfaces
Routing
Software Components
```

Example:

```text
SSH
────────────────
Enabled       Yes
Version       2
Weak Ciphers  No
```

---

# 19. Audit Creation

Button:

```text
Start Audit
```

Opens configuration:

```text
Select Frameworks

☑ CIS
☑ NIST
☑ DISA STIG
☑ ISO 27001

Analysis

☑ CVE
☑ PQC
☑ Security Analytics

☑ Generate PDF Report

[Start Audit]
```

API:

```http
POST /api/v1/audits
```

---

# 20. Audit Progress Screen

Route:

```text
/audits/:auditId
```

After starting an audit, display a progress timeline.

```text
✓ Configuration Ingestion
✓ Vendor Detection
✓ Configuration Normalization
● Compliance Analysis
○ CVE Correlation
○ PQC Analysis
○ Security Analytics
○ Risk Calculation
○ Report Generation
```

API:

```http
GET /api/v1/audits/{audit_id}
```

Poll while:

```text
status = QUEUED
status = RUNNING
```

Suggested polling:

```text
every 2–3 seconds
```

Stop polling when:

```text
COMPLETED
FAILED
CANCELLED
```

Do not poll indefinitely.

---

# 21. Audit Results Page

Route:

```text
/audits/:auditId/results
```

This should become the central report screen.

Top section:

```text
Audit Completed

Overall Risk
72 / 100

Compliance
78.4%

Critical
2

High
7

Medium
11

Low
4
```

Then tabs:

```text
Overview
Compliance
CVE
PQC
Security
Findings
Evidence
Remediation
```

---

# 22. Compliance Page

Route:

```text
/audits/:auditId/compliance
```

API:

```http
GET /api/v1/compliance/{audit_id}
```

Show framework cards:

```text
CIS
81%

NIST
76%

STIG
79%

ISO 27001
82%
```

Then framework selector:

```text
[CIS] [NIST] [STIG] [ISO 27001]
```

---

# 23. Compliance Control Table

API:

```http
GET /api/v1/compliance/{audit_id}/controls
```

Table:

| Control | Description   | Status | Severity | Evidence |
| ------- | ------------- | ------ | -------- | -------- |
| AC-17   | Remote Access | Fail   | High     | View     |
| AU-2    | Logging       | Pass   | Medium   | View     |

Statuses:

```text
PASS
FAIL
PARTIAL
NOT_APPLICABLE
UNKNOWN
```

Use clear status badges.

---

# 24. Compliance Control Details

Clicking a control opens a drawer/modal/page.

Display:

```text
Control ID
Control Title
Framework
Description
Status
Severity
Expected Value
Observed Value
Evidence
Related Controls
Remediation
```

Example:

```text
NIST AC-17

Status: FAIL

Expected:
SSH Version = 2

Observed:
SSH Version = 1

Evidence:
Configuration line 43
```

---

# 25. Vulnerabilities Page

Route:

```text
/vulnerabilities
```

API:

```http
GET /api/v1/vulnerabilities/{audit_id}
```

Top cards:

```text
Total CVEs
Critical
High
Medium
Low
Unknown
```

Table:

| CVE      | Product      | Version | Severity | Status     | Fixed Version |
| -------- | ------------ | ------- | -------- | ---------- | ------------- |
| CVE-XXXX | Cisco IOS-XE | 17.9.2  | Critical | Vulnerable | 17.9.5        |

Filters:

```text
Severity
Vendor
Product
Status
CVE ID
```

---

# 26. Vulnerability Status

Use exactly:

```text
VULNERABLE
NOT_AFFECTED
UNKNOWN
```

Do not show:

```text
Safe
100% Secure
No Vulnerabilities
```

because the backend may only have enough information to determine `UNKNOWN`.

---

# 27. Vulnerability Details

Route:

```text
/vulnerabilities/:findingId
```

API:

```http
GET /api/v1/vulnerabilities/{audit_id}/{finding_id}
```

Display:

```text
CVE ID
Description
Affected Product
Installed Version
CPE
Affected Version Range
Fixed Version
CVSS
Severity
CWE
References
Evidence
Remediation
```

Important visual section:

```text
Installed Version
17.9.2

Affected Range
>= 17.0
< 17.9.5

        ↓

VULNERABLE

Fixed Version
17.9.5
```

---

# 28. PQC Page

Route:

```text
/pqc
```

API:

```http
GET /api/v1/pqc/{audit_id}
```

Top:

```text
PQC Readiness
64%
```

Categories:

```text
READY
TRANSITION
AT_RISK
UNKNOWN
```

Show:

```text
RSA
ECDSA
AES
SHA
TLS
SSH
IPsec
```

Example:

```text
RSA-2048
Transition Required

AES-256
Ready

SHA-1
At Risk
```

---

# 29. PQC migration section

Show:

```text
Current Algorithm
Current Key Size
Risk
Recommended Direction
Priority
```

Do not make the frontend invent recommendations. Display exactly what the backend returns.

---

# 30. Security Analytics Page

Route:

```text
/analytics
```

API:

```http
GET /api/v1/analytics/{audit_id}
```

Show:

```text
Overall Security Risk
Configuration Anomalies
Policy Deviations
Repeated Weaknesses
Fleet Outliers
```

Example:

```text
Configuration Deviation

Logging configuration differs from
the organization's baseline.

Severity: HIGH
```

---

# 31. Findings Page

Route:

```text
/findings
```

API:

```http
GET /api/v1/findings
```

This is the unified view.

Filters:

```text
Type
Severity
Asset
Status
Framework
CVE
```

Finding types:

```text
COMPLIANCE
CVE
PQC
SECURITY
CONFIGURATION
```

Table:

| Finding        | Type       | Asset     | Severity | Status |
| -------------- | ---------- | --------- | -------- | ------ |
| Telnet Enabled | Compliance | Router-01 | Critical | Open   |
| CVE-XXXX       | CVE        | FW-01     | Critical | Open   |
| Weak RSA       | PQC        | FW-02     | High     | Open   |

---

# 32. Finding Details

Route:

```text
/findings/:findingId
```

Display:

```text
Finding title
Description
Severity
Risk score
Asset
Source
Evidence
Affected property
Related control
Related CVE
Remediation
History
```

The most important section:

### Why was this finding generated?

```text
Observed:
TELNET.ENABLED = true

Expected:
TELNET.ENABLED = false

Rule:
OKF-TELNET-001

Result:
FAIL
```

This gives explainability.

---

# 33. AI Training Page

Route:

```text
/training
```

This page is specifically for the adaptive learning loop.

API:

```http
GET /api/v1/training/queue
```

Show:

```text
Pending
Approved
Rejected
```

---

# 34. Unknown command interface

Example:

```text
Unknown Configuration Command

Vendor:
UnknownVendor

Platform:
Unknown

Command:

set secure-management ssh v2
```

Context:

```text
management
security
remote-access
```

Button:

```text
[Generate AI Suggestions]
```

API:

```http
POST /api/v1/training/{training_id}/suggest
```

---

# 35. AI suggestions

Display:

```text
AI Suggestions

1. SSH.VERSION = 2
   Confidence: 94%

2. SSH.ENABLED = true
   Confidence: 78%

3. SSH.CONFIGURATION
   Confidence: 42%
```

Each suggestion:

```text
[Approve]
```

There should also be:

```text
[Reject]
```

and preferably:

```text
[Choose Different Property]
```

---

# 36. Human approval

When the user approves:

```http
POST /api/v1/training/{training_id}/approve
```

Request:

```json
{
  "canonical_property": "SSH.VERSION",
  "canonical_value": 2,
  "comment": "Verified"
}
```

After success:

```text
Mapping Approved ✓

Registry updated.

Configuration can now be re-audited.
```

The frontend should then refresh the training queue.

---

# 37. Remediation Page

Route:

```text
/remediation
```

API:

```http
GET /api/v1/remediation/{finding_id}
```

Display:

```text
Finding
Current Configuration
Recommended Action
Vendor
Platform
Commands
Validation
Rollback
Approval
```

Example:

```text
Finding:
Telnet Enabled

Recommended:
Disable Telnet and use SSH.

Commands:
1. configure terminal
2. line vty 0 4
3. transport input ssh
```

---

# 38. Remediation safety

The frontend should visually distinguish:

```text
RECOMMENDATION
DRY RUN
APPROVED
APPLIED
VALIDATED
```

Never present a recommendation as if it has already been applied.

If backend returns:

```json
{
  "approval_required": true
}
```

show:

```text
Approval Required
```

---

# 39. Reports Page

Route:

```text
/reports
```

API:

```http
GET /api/v1/reports
```

Display:

```text
Report
Audit
Created
Status
Format
Action
```

Actions:

```text
View
Download
```

---

# 40. Generate Report

From Audit Results:

```text
[Generate PDF Report]
```

API:

```http
POST /api/v1/reports
```

Request:

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

Show:

```text
Generating report...
```

Then poll:

```http
GET /api/v1/reports/{report_id}
```

Once completed:

```text
[Download PDF]
```

---

# 41. Report preview

Before download, show:

```text
Audit Summary
Compliance
Risk
CVE
PQC
Findings
Remediation
```

The frontend should not generate the PDF itself.

The backend generates the authoritative PDF.

---

# 42. API State Management

Use **TanStack Query** for server state.

Example:

```text
useQuery()
useMutation()
useInfiniteQuery()
```

Use a separate lightweight store such as Zustand only for frontend state:

```text
Sidebar state
Theme
Upload UI state
Selected filters
Modal state
```

Do not duplicate backend state in Zustand unnecessarily.

---

# 43. Loading States

Every API-driven screen must have:

```text
Loading
Success
Empty
Error
```

Example:

```text
Loading:
Skeleton

Empty:
No vulnerabilities found.

Error:
Unable to load vulnerability data.
[Retry]
```

Never show a blank screen while waiting for the backend.

---

# 44. Error Handling

Backend:

```json
{
  "success": false,
  "error": {
    "code": "AUDIT_NOT_FOUND",
    "message": "Audit does not exist"
  }
}
```

Frontend maps this to:

```text
Audit not found.

The requested audit may have been deleted
or you may not have permission to access it.
```

Never show:

```text
AxiosError: Request failed with status code 404
```

to the user.

---

# 45. API Type Definitions

Create TypeScript interfaces matching backend Pydantic schemas.

Example:

```typescript
export interface Asset {
  asset_id: string;
  name: string;
  vendor: string;
  product: string;
  version: string;
  environment: string;
  criticality: string;
  status: string;
}
```

Finding:

```typescript
export interface Finding {
  finding_id: string;
  type: FindingType;
  title: string;
  severity: Severity;
  asset_id: string;
  status: FindingStatus;
}
```

Enums:

```typescript
type Severity =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "INFO";

type FindingType =
  | "COMPLIANCE"
  | "CVE"
  | "PQC"
  | "SECURITY"
  | "CONFIGURATION";
```

These should exactly match backend values.

---

# 46. Do not hardcode backend data

Bad:

```typescript
const compliance = 78.4;
```

Good:

```typescript
const { data } = useCompliance(auditId);
```

Similarly, don't hardcode:

```text
CVE names
Control names
Framework scores
Asset names
Risk values
```

The backend is the source of truth.

---

# 47. Frontend API service pattern

Example:

```typescript
export async function getAudit(auditId: string) {
  const response = await api.get(`/audits/${auditId}`);
  return response.data.data;
}
```

Then component:

```typescript
const { data, isLoading, error } = useQuery({
  queryKey: ["audit", auditId],
  queryFn: () => getAudit(auditId)
});
```

This keeps API logic outside UI components.

---

# 48. API polling

Use polling for:

```text
Audit
CVE synchronization
AI training
Report generation
Fleet analysis
```

Example:

```text
POST /audits
       ↓
AUD-001
       ↓
GET /audits/AUD-001
       ↓
RUNNING
       ↓
GET /audits/AUD-001
       ↓
RUNNING
       ↓
GET /audits/AUD-001
       ↓
COMPLETED
```

When completed, invalidate:

```text
audit
dashboard
findings
compliance
vulnerabilities
pqc
analytics
```

---

# 49. Frontend Routing

Recommended routes:

```text
/login

/dashboard

/assets
/assets/:assetId

/configurations/upload
/configurations/:configurationId

/audits
/audits/:auditId
/audits/:auditId/results

/audits/:auditId/compliance
/audits/:auditId/vulnerabilities
/audits/:auditId/pqc
/audits/:auditId/analytics
/audits/:auditId/findings

/findings
/findings/:findingId

/training

/remediation

/reports

/settings
```

---

# 50. Global search

Add a global search in the header.

Search:

```text
Asset
CVE
Finding
Audit
Control
Configuration
```

Backend endpoint can later be:

```http
GET /api/v1/search?q=...
```

This is optional for MVP but useful.

---

# 51. Notifications

Header should have a notification icon.

Examples:

```text
New critical CVE detected
Audit completed
AI mapping requires approval
Report generated
CVE database updated
```

Initially these can be fetched through:

```http
GET /api/v1/notifications
```

If this API isn't implemented initially, keep the UI component ready but don't fake notifications.

---

# 52. Design language

This is a cybersecurity enterprise product.

Recommended visual direction:

```text
Dark security dashboard
High information density
Clean cards
Subtle borders
Clear severity colours
Strong typography
Minimal decorative graphics
```

Do not make it look like a generic AI chatbot.

The UI should communicate:

```text
Enterprise
Security
Trust
Auditability
Technical depth
```

---

# 53. Severity colours

Use a consistent severity mapping.

```text
CRITICAL → red
HIGH     → orange
MEDIUM   → yellow
LOW      → blue/neutral
INFO     → gray
```

Do not use colours arbitrarily across different pages.

For example:

```text
Critical
[CRITICAL]

High
[HIGH]

Medium
[MEDIUM]

Low
[LOW]
```

---

# 54. Status colours

Compliance:

```text
PASS
FAIL
PARTIAL
NOT APPLICABLE
UNKNOWN
```

Vulnerability:

```text
VULNERABLE
NOT AFFECTED
UNKNOWN
```

Training:

```text
PENDING
APPROVED
REJECTED
```

Audit:

```text
QUEUED
RUNNING
COMPLETED
FAILED
CANCELLED
```

---

# 55. Important UX rule: explainability

Every security conclusion should have a path to evidence.

For example:

```text
Finding:
SSH Version 1 Detected
       ↓
Why?
       ↓
Observed Value: 1
Expected Value: 2
       ↓
Evidence
       ↓
Configuration line 43
       ↓
OKF-SSH-001
       ↓
NIST AC-17
```

The frontend should make this chain easy to inspect.

---

# 56. Important UX rule: AI transparency

When an AI model is involved, show that it is an AI suggestion.

Example:

```text
AI Suggested Mapping

SSH.VERSION = 2

Confidence: 94%

[Approve]
[Reject]
```

Do not display:

```text
AI says this is definitely SSH.VERSION.
```

The backend's human approval state should remain authoritative.

---

# 57. Important UX rule: CVE transparency

For CVEs show:

```text
CVE
       ↓
Product
       ↓
CPE
       ↓
Installed Version
       ↓
Affected Version Range
       ↓
Result
```

Example:

```text
Installed:
17.9.2

Affected:
>= 17.0 and < 17.9.5

Result:
VULNERABLE
```

This makes the CVE engine understandable to judges.

---

# 58. Main dashboard user journey

The intended user journey is:

```text
Login
  ↓
Dashboard
  ↓
Upload Configuration
  ↓
Vendor Detection
  ↓
Start Audit
  ↓
Audit Progress
  ↓
Audit Results
  ├── Compliance
  ├── CVE
  ├── PQC
  ├── Security
  └── Findings
       ↓
   Finding Details
       ↓
   Remediation
       ↓
   Generate Report
```

---

# 59. Unknown vendor journey

Second important journey:

```text
Upload Unknown Configuration
          ↓
AI Parser
          ↓
Canonical IR
          ↓
Unknown Commands
          ↓
AI Training Page
          ↓
AI Suggestions
          ↓
Human Approval
          ↓
Mapping Registry
          ↓
Re-audit
          ↓
Improved Recognition
```

This should be visually demonstrated in the frontend.

---

# 60. Frontend-backend responsibility boundary

### Frontend handles

```text
UI
Navigation
Forms
Validation for UX
Charts
Tables
Filtering
Sorting
Pagination
API calls
Loading states
Error states
User interactions
```

### Backend handles

```text
Authentication
Authorization
Parsing
Vendor detection
Canonical IR
AI/ML
OKF
Compliance
CVE
CPE
PQC
Risk
Remediation generation
PDF generation
Database
NVD synchronization
Training
```

### Frontend must NOT handle

```text
CVE matching
Compliance calculations
Risk calculation
LLM calls
NVD API calls
ML inference
OKF rule execution
```

---

# 61. API contract priority

Before frontend development begins, backend developer must provide:

```text
1. OpenAPI specification
2. API base URL
3. Authentication mechanism
4. Request schemas
5. Response schemas
6. Error schemas
7. Enum values
8. Pagination format
9. File upload format
10. Async job states
```

FastAPI will automatically expose OpenAPI documentation.

The frontend developer should use:

```text
/api/v1/docs
/api/v1/openapi.json
```

during integration.

---

# 62. Backend mock mode

Frontend development should **not wait for the backend to be completely finished**.

Create mock API responses based on the exact backend schemas.

Example:

```text
src/
└── mocks/
    ├── dashboard.mock.ts
    ├── assets.mock.ts
    ├── audits.mock.ts
    ├── compliance.mock.ts
    ├── vulnerabilities.mock.ts
    ├── pqc.mock.ts
    ├── findings.mock.ts
    └── training.mock.ts
```

Once backend is available:

```text
Mock API
   ↓
Real API
```

No UI rewrite should be required.

---

# 63. Definition of Done

Frontend is considered complete only when all of these work:

### Authentication

```text
☐ Login
☐ Token handling
☐ Logout
☐ Protected routes
```

### Assets

```text
☐ Asset listing
☐ Asset details
☐ Filters
☐ Search
```

### Configuration

```text
☐ Upload single configuration
☐ Upload multiple configurations
☐ Upload progress
☐ Raw configuration viewer
☐ Canonical IR viewer
☐ Unknown token viewer
```

### Audit

```text
☐ Start audit
☐ Audit progress
☐ Audit result
☐ Error handling
```

### Compliance

```text
☐ Framework overview
☐ Control list
☐ Control details
☐ Evidence
```

### CVE

```text
☐ Vulnerability summary
☐ CVE list
☐ CVE details
☐ Version range display
☐ Severity filtering
```

### PQC

```text
☐ Readiness score
☐ Algorithm list
☐ Migration recommendations
```

### Security Analytics

```text
☐ Risk overview
☐ Anomaly list
☐ Fleet analysis
```

### AI Training

```text
☐ Unknown command queue
☐ AI suggestions
☐ Approve
☐ Reject
☐ Training status
```

### Remediation

```text
☐ Remediation details
☐ Commands
☐ Validation
☐ Approval status
```

### Reports

```text
☐ Generate report
☐ Report status
☐ Download PDF
```

---

# 64. Final frontend architecture

The frontend should ultimately look like:

```text
                         React Frontend
                              │
               ┌──────────────┴──────────────┐
               │                             │
           UI Layer                    API Layer
               │                             │
       ┌───────┼────────┐                    │
       │       │        │                    │
    Dashboard Audit  Findings                │
       │       │        │                    │
       └───────┼────────┘                    │
               │                             │
               ▼                             ▼
        TanStack Query                 Axios Client
                                             │
                                             │
                                             ▼
                                  FastAPI /api/v1
                                             │
          ┌──────────────────────────────────┼────────────────────┐
          │                                  │                    │
          ▼                                  ▼                    ▼
      Compliance                           CVE                   PQC
          │                                  │                    │
          └──────────────────┬───────────────┴────────────────────┘
                             ▼
                       Unified Findings
                             │
                             ▼
                        Remediation
```

# 65. Final principle for the frontend developer

The frontend should be treated as a **pure API consumer**.

The contract is:

```text
BACKEND
    ↓
OpenAPI + JSON schemas
    ↓
FRONTEND
    ↓
Visualisation + user interaction
```

The frontend should **never duplicate backend intelligence**.

For example:

```text
❌ Frontend calculates CVSS

❌ Frontend determines whether a version is vulnerable

❌ Frontend calculates compliance percentage

❌ Frontend decides whether an AI mapping is valid

❌ Frontend calculates risk score

❌ Frontend directly calls NVD

❌ Frontend directly calls an LLM
```

Instead:

```text
Backend:
"SSH.VERSION expected 2, observed 1 → FAIL"

Frontend:
"Show this failure clearly."
```

```text
Backend:
"CVE-XXXX affects installed version 17.9.2"

Frontend:
"Show the vulnerability and its evidence."
```

```text
Backend:
"AI suggests SSH.VERSION = 2 with confidence 94%"

Frontend:
"Show suggestion and let administrator approve/reject."
```

This separation will make your SIH implementation much easier to develop, test, demonstrate and eventually deploy as a real SaaS product.
