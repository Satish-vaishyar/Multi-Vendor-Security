# SIH 2026 PS 26155

# AI-Driven Multi-Vendor Network Security Compliance Auditor

## Complete System Architecture & Technical Design

---

# 1. Executive Architecture

The proposed platform is an **AI-assisted, vendor-neutral network security auditing system** that accepts configurations from multiple network vendors, converts them into a common **Canonical Security Baseline Model**, and then independently analyses that normalized representation through four security engines:

1. **Compliance Engine**
2. **PQC Readiness Engine**
3. **Security Analytics Engine**
4. **CVE Vulnerability Engine**

The outputs of all four engines are then combined by a **Unified Finding and Risk Engine**, which generates evidence-backed findings, prioritizes risks, recommends remediation, and produces auditable reports.

The most important architectural principle is:

> **The configuration syntax is vendor-specific, but security analysis is vendor-neutral.**

Therefore, Cisco, Juniper, Fortinet, or a previously unseen vendor eventually become the **same Canonical Security Baseline Model** before entering the analysis layer.

---

# 2. Complete End-to-End Architecture

```text
┌─────────────────────────────────────────────────────────────────────┐
│                        CONFIGURATION SOURCES                        │
│                                                                     │
│ Cisco IOS/IOS-XE │ Juniper Junos │ FortiOS │ Unknown Vendor        │
│ CLI Files        │ Config Files  │ Config  │ Proprietary Syntax    │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     1. UNIFIED INGESTION LAYER                     │
│                                                                     │
│ File Upload │ Text Input │ API │ Batch Upload │ Future Connectors │
│                                                                     │
│ Validation │ Sanitization │ Metadata Extraction │ Hashing          │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       2. VENDOR DETECTION                          │
│                                                                     │
│ Vendor Identification                                               │
│ Platform / OS Detection                                             │
│ Version Extraction                                                  │
│ Confidence Score                                                    │
│ Syntax Fingerprinting                                               │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                 ┌──────────────┴──────────────┐
                 │                             │
                 ▼                             ▼
┌──────────────────────────────┐   ┌─────────────────────────────────┐
│       KNOWN VENDOR           │   │       UNKNOWN / UNSEEN          │
│                              │   │           VENDOR                │
│ Deterministic Parser        │   │ AI Parsing Pipeline             │
│ Vendor Rules                │   │ Unknown Token Detector          │
│ Templates                   │   │ Mapping Classifier              │
│ Grammar                     │   │ LLM-assisted Interpretation      │
└──────────────┬───────────────┘   └────────────────┬────────────────┘
               │                                    │
               │                                    ▼
               │                       ┌────────────────────────────┐
               │                       │ HUMAN VALIDATION / TRAINING│
               │                       │                            │
               │                       │ Suggested Mapping         │
               │                       │ Approve / Reject / Edit    │
               │                       └────────────┬───────────────┘
               │                                    │
               │                                    ▼
               │                       ┌────────────────────────────┐
               │                       │     MAPPING REGISTRY       │
               │                       │                            │
               │                       │ Vendor Syntax → Canonical │
               │                       │ Property Mapping           │
               │                       └────────────┬───────────────┘
               │                                    │
               └────────────────┬───────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 3. CANONICAL SECURITY BASELINE MODEL               │
│                                                                     │
│ Vendor-Neutral Security Representation / Canonical IR               │
│                                                                     │
│ Device Identity                                                     │
│ AAA │ Access Control │ Services │ Interfaces                       │
│ Routing │ Logging │ Policies │ Cryptography │ Encryption            │
│ Management Plane │ Security Controls │ Software Metadata            │
│ Unknown Tokens / Confidence / Provenance                            │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
              │                 │                 │
              ▼                 ▼                 ▼
      ┌──────────────┐  ┌──────────────┐  ┌────────────────┐
      │  COMPLIANCE  │  │     PQC      │  │    SECURITY    │
      │    ENGINE    │  │    ENGINE    │  │    ANALYTICS   │
      └──────┬───────┘  └──────┬───────┘  └───────┬────────┘
             │                 │                  │
             │                 │                  │
             └─────────────────┼──────────────────┘
                               │
                               │       ┌──────────────────────┐
                               └──────►│      CVE ENGINE      │
                                       │                      │
                                       │ Vendor/Product       │
                                       │ Version              │
                                       │ Components           │
                                       │ Services             │
                                       │ CVE Correlation      │
                                       │ CVSS / Severity      │
                                       └───────────┬──────────┘
                                                   │
                    ┌──────────────────────────────┴───────────────┐
                    │                                              │
                    ▼                                              ▼
          ┌──────────────────────┐                      ┌─────────────────────┐
          │  UNIFIED FINDING     │                      │   EVIDENCE GRAPH    │
          │       ENGINE         │◄────────────────────►│                     │
          │                      │                      │ Raw Config          │
          │ Compliance Findings  │                      │ Canonical Property  │
          │ PQC Findings         │                      │ Control / CVE       │
          │ Security Findings    │                      │ Finding             │
          │ CVE Findings         │                      │ Remediation         │
          └──────────┬───────────┘                      └─────────────────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │     RISK ENGINE      │
          │                      │
          │ Severity             │
          │ Confidence           │
          │ Exposure             │
          │ Asset Criticality    │
          │ Exploitability       │
          │ Priority             │
          └──────────┬───────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │  REMEDIATION ENGINE  │
          │                      │
          │ Recommended Fix      │
          │ Vendor Commands       │
          │ Before/After         │
          │ Validation            │
          │ Human Approval       │
          └──────────┬───────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │ EVIDENCE & REPORTING │
          │                      │
          │ Audit Report         │
          │ Compliance Report    │
          │ CVE Report           │
          │ PQC / CBOM Report    │
          │ Security Report      │
          │ Executive Summary    │
          │ Signed PDF           │
          └──────────────────────┘
```

---

# 3. Architectural Layers

The entire system is divided into **10 major layers**.

| Layer | Component                         | Purpose                                          |
| ----- | --------------------------------- | ------------------------------------------------ |
| L1    | Configuration Ingestion           | Accept heterogeneous network configurations      |
| L2    | Vendor Detection                  | Identify vendor, platform and version            |
| L3    | Parsing & AI Adaptation           | Convert vendor syntax into security concepts     |
| L4    | Mapping Registry                  | Store learned vendor-to-canonical mappings       |
| L5    | Canonical Security Baseline Model | Create vendor-neutral security representation    |
| L6    | Four Analysis Engines             | Compliance, PQC, Security Analytics, CVE         |
| L7    | Unified Finding & Risk            | Correlate and prioritize findings                |
| L8    | Remediation                       | Generate validated remediation recommendations   |
| L9    | Evidence & Knowledge Graph        | Maintain complete audit traceability             |
| L10   | Reporting & Dashboard             | Present results to technical and executive users |

---

# 4. Layer 1: Unified Ingestion Engine

The ingestion engine is the entry point for all configurations.

## Supported inputs

Initially:

```text
.txt
.cfg
.conf
.json
.xml
CLI output
```

Future:

```text
REST API
SSH
Netmiko
NAPALM
Vendor APIs
Network controllers
```

## Responsibilities

### 4.1 File validation

Check:

* File type
* File size
* Encoding
* Content validity
* Malformed configuration
* Duplicate upload

### 4.2 Metadata extraction

Extract:

```text
Filename
Timestamp
Source
Device name
Potential vendor
Potential version
Configuration hash
Upload user
```

### 4.3 Configuration fingerprint

Generate a cryptographic hash:

```text
SHA-256(configuration)
```

This provides:

* Integrity
* Deduplication
* Audit tracking
* Evidence identification

---

# 5. Layer 2: Vendor Detection Engine

Before parsing, the platform determines what type of configuration it is dealing with.

## Detection

```text
Configuration
      ↓
Syntax fingerprint
      ↓
Vendor classifier
      ↓
Platform classifier
      ↓
Version extractor
      ↓
Confidence
```

Example:

```json
{
  "vendor": "Cisco",
  "platform": "IOS-XE",
  "version": "17.9",
  "confidence": 0.98
}
```

For an unknown configuration:

```json
{
  "vendor": "UNKNOWN",
  "platform": "UNKNOWN",
  "version": null,
  "confidence": 0.42
}
```

That automatically triggers the adaptive AI pipeline.

---

# 6. Layer 3: Parsing Architecture

There are deliberately **two parsing paths**.

## Path A: Known Vendor

```text
Configuration
      ↓
Vendor Parser
      ↓
Rule / Grammar Parser
      ↓
Structured Tokens
      ↓
Canonical Mapping
```

The deterministic parser has priority.

---

## Path B: Unknown Vendor

```text
Configuration
      ↓
Unknown Token Detector
      ↓
AI Parser
      ↓
Mapping Classifier
      ↓
Suggested Canonical Property
      ↓
Human Validation
      ↓
Mapping Registry
      ↓
Canonical Mapping
```

This satisfies the adaptive vendor requirement without forcing the backend to be redeployed for every new syntax.

---

# 7. AI Parsing Policy

The system must follow:

> **Deterministic values win. AI fills gaps.**

This is critical.

If the deterministic parser knows:

```text
ip http server
```

means:

```text
HTTP = ENABLED
```

the AI must not override that result.

AI should primarily handle:

* Unknown syntax
* Unknown tokens
* New vendor commands
* Semantic mapping
* Ambiguous commands

---

# 8. Human-in-the-Loop Training

The training interface is one of the key differentiators.

Example:

```text
Unknown command:

security-zone trust

AI interpretation:

Security Zone = TRUST

Confidence:
87%

Canonical Property:

network.security_zone

[Approve] [Edit] [Reject]
```

If approved:

```text
Unknown command
      ↓
Approved mapping
      ↓
Mapping Registry
      ↓
Future configurations
      ↓
Automatically recognized
```

This creates a continuous learning loop.

---

# 9. Mapping Registry

The registry stores every approved mapping.

Example:

```json
{
  "vendor": "Vendor-X",
  "platform": "OS-X",
  "version": "4.2",
  "source_token": "security-zone trust",
  "canonical_property": "network.security_zone",
  "canonical_value": "trust",
  "confidence": 0.97,
  "status": "approved",
  "approved_by": "admin",
  "mapping_version": "1.2"
}
```

The registry should support:

* Versioning
* Rollback
* Approval status
* Confidence
* Vendor
* Platform
* Version
* Provenance

---

# 10. Layer 4: Canonical Security Baseline Model

This is the **heart of the architecture**.

The Canonical Security Baseline Model provides a common language between:

```text
Vendor Configuration
```

and

```text
Security Intelligence
```

---

## 10.1 Core model

```text
Device
├── Identity
├── Vendor
├── Platform
├── Version
│
├── AAA
│   ├── Authentication
│   ├── Authorization
│   └── Accounting
│
├── Services
│   ├── SSH
│   ├── Telnet
│   ├── HTTP
│   ├── HTTPS
│   └── SNMP
│
├── Interfaces
│
├── Routing
│
├── ACL
│
├── Logging
│
├── Policies
│
├── Cryptography
│
├── Certificates
│
├── Encryption
│
├── Management Plane
│
├── Software Components
│
└── Unknown Tokens
```

---

# 11. Why the Canonical IR Is Critical

Without it:

```text
Cisco → Compliance
Cisco → CVE
Cisco → PQC
Cisco → Security

Juniper → Compliance
Juniper → CVE
Juniper → PQC
Juniper → Security

Fortinet → Compliance
Fortinet → CVE
...
```

This becomes extremely difficult to scale.

With Canonical IR:

```text
Cisco ──────┐
Juniper ────┤
Fortinet ───┤
Unknown ────┤
             ▼
       Canonical IR
             │
      ┌──────┼──────┬──────┐
      ▼      ▼      ▼      ▼
   Compliance PQC Security CVE
```

Therefore, adding a new vendor primarily requires **mapping into the common representation**, not rewriting every security engine.

---

# 12. Four-Engine Analysis Architecture

After normalization, **100% of successfully mapped security-relevant data is sent to all four engines**.

```text
                 CANONICAL IR
                      │
       ┌──────────────┼──────────────┐
       │              │              │
       ▼              ▼              ▼
 Compliance          PQC         Security
   Engine            Engine      Analytics
       │              │              │
       └──────────────┼──────────────┘
                      │
                      ▼
                    CVE
                   Engine
```

Architecturally, however, all four are independent consumers:

```text
Canonical IR
    │
    ├── Compliance
    ├── PQC
    ├── Security Analytics
    └── CVE
```

They can therefore execute:

* Sequentially for a small demo
* In parallel using asynchronous workers in production

---

# 13. Engine 1: Compliance Engine

## Purpose

Determine whether configuration satisfies security frameworks.

## Input

```text
Canonical IR
+
Versioned Control Packs
+
Crosswalk Registry
```

## Supported framework architecture

```text
CIS
NIST
ISO 27001
CERT-In
Custom Organisation Controls
```

Each control should have:

```text
Control ID
Framework
Version
Title
Description
Severity
Condition
Expected State
Evidence Rule
Remediation
References
```

---

# 14. Compliance Evaluation

Example:

```text
Control:

CIS-NET-001

Requirement:
Telnet must be disabled
```

Canonical IR:

```text
services.telnet = true
```

Evaluation:

```text
Expected = false
Actual = true

Result = FAIL
```

Output:

```json
{
  "engine": "compliance",
  "control_id": "CIS-NET-001",
  "status": "FAIL",
  "severity": "HIGH"
}
```

---

# 15. Cross-Framework Mapping

One security property can map to multiple controls.

```text
Canonical Property
       │
       ├── CIS Control
       ├── NIST Control
       ├── ISO Control
       └── CERT-In Control
```

This prevents duplicate analysis.

One underlying issue can generate multiple framework references while remaining one underlying security finding.

---

# 16. Engine 2: PQC Readiness Engine

## Purpose

Assess cryptographic readiness for the post-quantum transition.

Pipeline:

```text
Canonical IR
      ↓
Cryptographic Inventory
      ↓
Algorithm Identification
      ↓
Key / Certificate Analysis
      ↓
Classical / PQC / Hybrid Classification
      ↓
CBOM
      ↓
PQC Readiness
      ↓
Q-Day Exposure
```

---

# 17. Cryptographic Bill of Materials

The CBOM should capture:

```text
Asset
Protocol
Algorithm
Key Size
Certificate
Usage
Location
Class
PQC Status
Migration Requirement
```

Example:

```text
Router-01
 └── SSH
      └── RSA-2048
           ├── Classical
           ├── Quantum Risk
           └── Migration Candidate
```

---

# 18. PQC Analysis

The engine can classify:

```text
Classical
PQC-ready
Hybrid
Unknown
Deprecated
Migration Required
```

The output should remain separate from conventional compliance scoring.

This allows the system to answer both:

> "Is this configuration compliant?"

and:

> "Is this configuration ready for post-quantum cryptography?"

---

# 19. Engine 3: Security Analytics Engine

This engine focuses on security posture rather than framework compliance.

## Categories

### Authentication

```text
Weak authentication
Missing MFA-related controls
Weak AAA configuration
```

### Network Exposure

```text
Internet-facing management
Open management services
Dangerous interfaces
```

### Access Control

```text
Overly permissive ACL
Missing management ACL
Broad source ranges
```

### Services

```text
Telnet
HTTP
Legacy protocols
Unnecessary services
```

### Logging

```text
Logging disabled
Remote logging missing
Insufficient audit configuration
```

### Configuration Drift

```text
Baseline deviation
Unexpected change
Policy drift
```

---

# 20. Security Analytics Can Detect Combinations

This is where the platform becomes more intelligent than a simple rule checker.

Example:

```text
SSH enabled
+
Password authentication enabled
+
Internet-facing management
+
No MFA-related control
```

Individually these may produce moderate findings.

Together they may create a much more significant exposure pattern.

The analytics engine can therefore generate:

```text
"Exposed Administrative Access Pattern"
```

with evidence linking all contributing properties.

---

# 21. Engine 4: CVE Vulnerability Engine

This is now a core engine.

## Purpose

Correlate the device's:

```text
Vendor
Product
Platform
Version
Components
Services
```

with vulnerability intelligence.

---

# 22. CVE Pipeline

```text
Canonical IR
      │
      ▼
Software / Platform Identification
      │
      ▼
Product Normalization
      │
      ▼
Version Normalization
      │
      ▼
CVE Knowledge Base
      │
      ▼
Candidate CVEs
      │
      ▼
Affected-Version Verification
      │
      ▼
CVSS / Severity
      │
      ▼
Exposure Correlation
      │
      ▼
CVE Finding
```

---

# 23. CVE Matching Strategy

Do not perform simplistic:

```text
Cisco → search all Cisco CVEs
```

Instead:

```text
Vendor
   +
Product
   +
Platform
   +
Software Version
   +
Component
   +
Service
```

Example:

```text
Vendor:
Cisco

Product:
IOS-XE

Version:
17.9.x

Component:
Web Management

Service:
HTTPS
```

Then correlate against the vulnerability database.

---

# 24. CVE False-Positive Reduction

The engine should distinguish:

### Potential Match

```text
Product matches
Version uncertain
```

from:

### Confirmed Match

```text
Product matches
Version falls inside affected range
```

and:

### Not Affected

```text
Product matches
Version outside affected range
```

This is important for a credible security auditor.

---

# 25. CVSS and Exploitability

For each confirmed vulnerability:

```text
CVE ID
CVSS
Severity
Affected Version
Fixed Version
Exploitability information
Evidence
```

The platform should retain the original vulnerability metadata and source reference so the finding can be audited.

---

# 26. Unified Finding Engine

All four engines produce findings.

```text
Compliance
    │
    ├── Finding C001
    │
PQC
    │
    ├── Finding P001
    │
Security Analytics
    │
    ├── Finding S001
    │
CVE
    │
    └── Finding V001
             │
             ▼
       Unified Finding Store
```

All findings should use the same basic schema.

---

# 27. Common Finding Schema

```json
{
  "finding_id": "F-00124",

  "engine": "CVE",

  "category": "Vulnerability",

  "severity": "HIGH",

  "title": "Vulnerable software version detected",

  "device_id": "RTR-001",

  "description": "...",

  "evidence": {},

  "confidence": 0.97,

  "references": [],

  "recommendation": "...",

  "status": "OPEN"
}
```

This common format allows the dashboard to treat all four engines consistently.

---

# 28. Evidence Graph

One of the strongest features should be the evidence chain.

```text
RAW CONFIGURATION
       │
       ▼
PARSED TOKEN
       │
       ▼
CANONICAL PROPERTY
       │
       ├─────────────┐
       │             │
       ▼             ▼
 Compliance        CVE
 Control           Match
       │             │
       └──────┬──────┘
              ▼
           FINDING
              │
              ▼
          RISK SCORE
              │
              ▼
         REMEDIATION
```

This means an evaluator can click a finding and understand:

> **Why did the system produce this result?**

---

# 29. Risk Engine

The risk engine should not blindly combine unrelated scores.

Use multiple dimensions:

```text
Severity
Confidence
Asset Criticality
Exposure
Exploitability
Compliance Impact
PQC Impact
```

Then calculate a documented priority.

For example:

```text
Finding A

CVSS: High
Confidence: 98%
Internet Exposure: Yes
Asset Criticality: High

→ High Priority
```

The exact mathematical formula should be configurable and transparent.

---

# 30. Correlation Across Engines

This is where the architecture can become significantly more powerful.

Suppose:

```text
CVE Engine
    ↓
Known vulnerability detected

Security Analytics
    ↓
Vulnerable service exposed externally

Compliance
    ↓
Management control failed

PQC
    ↓
Legacy cryptographic algorithm
```

Instead of showing four unrelated alerts, the system can correlate them into:

```text
HIGH-RISK NETWORK ASSET

Underlying Findings:
 ├── CVE
 ├── Security Exposure
 ├── Compliance Violation
 └── PQC Weakness
```

This gives reviewers a much better understanding of the actual security posture.

---

# 31. Remediation Engine

The remediation engine converts findings into actionable fixes.

Example:

```text
Finding
   ↓
Root Cause
   ↓
Recommended Fix
   ↓
Vendor-Specific Command
   ↓
Validation
```

For Cisco:

```text
no ip http server
```

For another vendor:

```text
Equivalent vendor-specific command
```

The remediation system should use the Canonical IR to determine the underlying issue and then use vendor mappings to generate the correct syntax.

---

# 32. Remediation Safety

The platform should initially use:

> **Generate → Review → Approve → Apply → Validate**

rather than automatically modifying live network devices.

Example:

```text
Finding
   ↓
Suggested Fix
   ↓
Preview
   ↓
Human Approval
   ↓
Apply
   ↓
Re-ingest configuration
   ↓
Run all four engines again
```

This creates a closed-loop architecture.

---

# 33. Closed-Loop Security Architecture

This is a major feature:

```text
CONFIGURATION
      ↓
NORMALIZATION
      ↓
FOUR ENGINES
      ↓
FINDINGS
      ↓
REMEDIATION
      ↓
UPDATED CONFIGURATION
      ↓
RE-INGESTION
      ↓
FOUR ENGINES AGAIN
      ↓
VERIFY FIX
```

The platform can therefore demonstrate:

```text
Before:
12 findings

After remediation:
5 findings

Verified:
7 findings resolved
```

---

# 34. Reporting Engine

Reports should have multiple levels.

## Technical Report

Contains:

* Device information
* Configuration summary
* All findings
* Evidence
* CVEs
* CVSS
* Compliance controls
* PQC status
* Security analytics
* Remediation

## Executive Report

Contains:

```text
Overall Security Posture
Critical Findings
High Findings
CVE Exposure
Compliance %
PQC Readiness
Top Risks
Recommended Actions
```

---

# 35. Dashboard

The frontend should have approximately six primary pages.

## 1. Dashboard

```text
Total Devices
Audited Devices
Compliance %
Critical Findings
High Findings
CVE Count
PQC Readiness
Security Risk
```

## 2. Upload & Audit

```text
Upload Configuration
      ↓
Detect Vendor
      ↓
Parse
      ↓
Normalize
      ↓
Run Audit
```

## 3. Findings

Filters:

```text
Engine
Severity
Device
Vendor
Framework
CVE
Status
```

## 4. Training

```text
Unknown Commands
AI Prediction
Confidence
Canonical Mapping
Approve / Edit / Reject
```

## 5. PQC / CBOM

```text
Crypto Assets
Classical Algorithms
PQC-ready Assets
Migration Candidates
Q-Day Exposure
```

## 6. Reports

```text
Compliance Report
Security Report
CVE Report
PQC Report
Complete Audit Report
```

---

# 36. Backend Architecture

Recommended structure:

```text
backend/
│
├── app/
│   │
│   ├── api/
│   │   ├── ingestion.py
│   │   ├── audit.py
│   │   ├── findings.py
│   │   ├── training.py
│   │   ├── cve.py
│   │   ├── pqc.py
│   │   └── reports.py
│   │
│   ├── ingestion/
│   │   ├── validator.py
│   │   ├── fingerprint.py
│   │   └── metadata.py
│   │
│   ├── detection/
│   │   └── vendor_detector.py
│   │
│   ├── parsers/
│   │   ├── registry.py
│   │   ├── cisco.py
│   │   ├── juniper.py
│   │   ├── fortinet.py
│   │   └── ai_parser.py
│   │
│   ├── ir/
│   │   ├── schema.py
│   │   ├── validator.py
│   │   └── normalizer.py
│   │
│   ├── training/
│   │   ├── oov_detector.py
│   │   ├── mapping_classifier.py
│   │   ├── trainer.py
│   │   └── registry.py
│   │
│   ├── engines/
│   │   ├── compliance/
│   │   ├── pqc/
│   │   ├── security/
│   │   └── cve/
│   │
│   ├── findings/
│   │   ├── schema.py
│   │   ├── correlation.py
│   │   └── risk.py
│   │
│   ├── remediation/
│   │   ├── generator.py
│   │   ├── validator.py
│   │   └── approval.py
│   │
│   ├── evidence/
│   │   ├── provenance.py
│   │   ├── graph.py
│   │   └── hashing.py
│   │
│   ├── reports/
│   │   ├── pdf.py
│   │   └── executive.py
│   │
│   └── quantum/
│       ├── qks.py
│       ├── vqc.py
│       ├── qaoa.py
│       └── vqe.py
│
├── data/
│   ├── raw/
│   ├── golden/
│   ├── processed/
│   ├── cve/
│   ├── benchmarks/
│   └── reports/
│
├── control_packs/
│   ├── cis/
│   ├── nist/
│   ├── iso/
│   └── cert_in/
│
├── registry/
│   ├── mappings/
│   ├── vendors/
│   └── crosswalk/
│
└── tests/
```

---

# 37. Database Architecture

A relational database such as PostgreSQL can contain:

```text
devices
configurations
vendors
platforms
mapping_registry
canonical_properties
control_packs
controls
framework_mappings
findings
cves
cve_matches
crypto_assets
cbom
remediations
evidence
audit_runs
users
approvals
```

---

# 38. Important Database Relationship

The central relationship should look like:

```text
Configuration
      │
      ▼
Canonical Asset
      │
      ├──────────► Compliance Findings
      │
      ├──────────► PQC Findings
      │
      ├──────────► Security Findings
      │
      └──────────► CVE Findings
                         │
                         ▼
                   Risk Findings
```

---

# 39. Knowledge Architecture

The platform should maintain separate knowledge sources.

```text
                    KNOWLEDGE LAYER
                          │
       ┌──────────────────┼──────────────────┐
       ▼                  ▼                  ▼
 Control Knowledge    Vendor Knowledge    Vulnerability
      Base                 Base              Knowledge
       │                    │                  │
 CIS/NIST/etc.        Vendor mappings       CVE database
       │                    │                  │
       └────────────────────┼──────────────────┘
                            │
                            ▼
                    Analysis Engines
```

This separation makes updates easier.

A new CVE should not require redeploying the parser.

A new vendor mapping should not require changing compliance rules.

A new compliance framework should not require changing the CVE engine.

---

# 40. OKF Architecture

Use the proposed **Open Knowledge Format** as the normalized knowledge/control representation.

```text
OKF
├── Metadata
├── Control
├── Applicability
├── Condition
├── Evidence
├── Remediation
├── References
├── Version
└── Signature
```

Control packs should be:

* Versioned
* Signed
* Traceable
* Independently updateable

---

# 41. Crosswalk Graph

A graph-based crosswalk can connect:

```text
Canonical Property
       │
       ├── CIS
       ├── NIST
       ├── ISO
       ├── CERT-In
       └── Internal Policy
```

This allows one normalized property to support multiple frameworks.

Example:

```text
"Telnet disabled"
       │
       ├── CIS-X
       ├── NIST-Y
       └── Internal-NET-04
```

---

# 42. CVE Knowledge Architecture

Keep CVE intelligence independent.

```text
CVE Knowledge Base
│
├── CVE ID
├── Vendor
├── Product
├── Version Range
├── CVSS
├── Severity
├── Description
├── References
├── Fixed Version
└── Exploitability Metadata
```

The CVE engine consumes this knowledge.

---

# 43. Data Flow for a Known Vendor

Example:

```text
Cisco Config
     ↓
Ingestion
     ↓
Cisco Detected
     ↓
Cisco Deterministic Parser
     ↓
Canonical Mapping
     ↓
Canonical IR
     ↓
┌────────┬────────┬────────┬────────┐
│Compliance│ PQC │ Security │ CVE │
└────────┴────────┴────────┴────────┘
     ↓
Unified Findings
     ↓
Risk Correlation
     ↓
Remediation
     ↓
Report
```

---

# 44. Data Flow for an Unknown Vendor

```text
Unknown Config
       ↓
Ingestion
       ↓
Vendor Unknown
       ↓
Unknown Token Detector
       ↓
AI Parser
       ↓
Mapping Prediction
       ↓
Human Approval
       ↓
Mapping Registry
       ↓
Canonical IR
       ↓
┌────────┬────────┬────────┬────────┐
│Compliance│ PQC │ Security │ CVE │
└────────┴────────┴────────┴────────┘
       ↓
Unified Findings
       ↓
Risk
       ↓
Remediation
       ↓
Report
```

**The downstream process is identical.**

That is the core scalability advantage.

---

# 45. Quantum ML Layer

The QML component should remain a **research/advanced analytics layer**, not a dependency for the main auditor.

Architecture:

```text
Canonical IR
      ↓
Feature Encoder
      ↓
Classical Baseline
      │
      ├── XGBoost
      └── Transformer / classical model
      │
      ▼
Quantum Models
      ├── QKS
      ├── VQC
      ├── QAOA
      └── VQE
      │
      ▼
Measured Comparison
```

The system should report actual measured performance rather than claiming that quantum models are inherently superior.

---

# 46. Where QML Fits

Do not make this:

```text
Canonical IR
      ↓
Quantum ML
      ↓
Compliance
```

Instead:

```text
Canonical IR
      │
      ├── Core Security Engines
      │
      └── Optional Quantum Research Layer
```

The primary auditor must remain functional if the quantum layer is disabled.

---

# 47. Security Architecture

The auditor itself should also be secure.

## Authentication

```text
User
 ↓
Authentication
 ↓
Role
 ↓
Authorization
```

Roles:

```text
Admin
Auditor
Security Analyst
Reviewer
Viewer
```

---

# 48. Sensitive Configuration Protection

Network configurations can contain sensitive information.

Therefore:

```text
Upload
 ↓
Secure storage
 ↓
Encryption
 ↓
Controlled processing
 ↓
Access-controlled results
```

Sensitive fields should be masked in UI/reporting where appropriate.

---

# 49. Audit Logging

Every important operation should create an audit record.

```text
Who
What
When
Which Configuration
Which Version
Which Mapping
Which Finding
Which Approval
Which Remediation
```

This is especially important for:

* Mapping approvals
* Control-pack updates
* Remediation approvals
* Configuration changes
* Report generation

---

# 50. Technology Stack

Recommended stack based on the existing architecture:

### Frontend

```text
React
Vite
Tailwind CSS
Recharts
```

### Backend

```text
Python
FastAPI
Pydantic
```

### Database

```text
PostgreSQL
```

### AI / ML

```text
PyTorch
Transformers
XGBoost
Scikit-learn
```

### Graph

```text
NetworkX
```

### Network Parsing

```text
Custom parsers
Regex
Grammar/rule engines
Netmiko
NAPALM
```

### PQC

```text
liboqs / appropriate PQC implementation
Cryptography libraries
```

### Quantum

```text
Qiskit
IBM Quantum / Aer
```

### Reporting

```text
ReportLab
```

### Deployment

```text
Docker
Docker Compose
Nginx
```

---

# 51. Service Architecture

For the SIH prototype, do **not** overcomplicate the deployment into dozens of microservices.

Use a modular monolith:

```text
Frontend
    │
    ▼
FastAPI
    │
    ├── Ingestion
    ├── Parser
    ├── AI Training
    ├── Canonical IR
    ├── Compliance
    ├── PQC
    ├── Security
    ├── CVE
    ├── Finding
    ├── Risk
    ├── Remediation
    └── Reporting
          │
          ▼
      PostgreSQL
```

Background workers can later be introduced for expensive operations.

---

# 52. Asynchronous Processing

For larger configurations:

```text
Upload
 ↓
Create Audit Job
 ↓
Queue
 ↓
Worker
 ↓
Parse
 ↓
Normalize
 ↓
Run 4 Engines
 ↓
Store Findings
 ↓
Notify Frontend
```

This prevents the UI from blocking during analysis.

---

# 53. Performance Architecture

The system should process the four engines independently.

```text
                    Canonical IR
                         │
       ┌─────────────────┼─────────────────┐
       ▼                 ▼                 ▼
 Compliance             PQC              Security
 Worker                  Worker            Worker
       │                 │                 │
       └─────────────────┼─────────────────┘
                         │
                         ▼
                    CVE Worker
```

For a production implementation, CVE matching can also run concurrently.

---

# 54. Caching

Cache:

```text
Vendor Detection
Mapping Results
CVE Queries
Control Evaluations
Canonical IR
```

Especially:

```text
Vendor + Product + Version
```

because the same version may appear across many devices.

---

# 55. Versioning

Version all important knowledge:

```text
Parser Version
Mapping Registry Version
Canonical IR Version
Control Pack Version
CVE Database Version
PQC Rules Version
Risk Model Version
```

This allows the report to answer:

> "Which rules and knowledge were used when this audit was performed?"

---

# 56. Reproducibility

Every audit should store:

```text
Audit ID
Configuration Hash
Parser Version
Mapping Version
Control Pack Version
CVE Database Version
PQC Rule Version
Timestamp
```

Therefore, the same audit can be reproduced later.

---

# 57. Testing Architecture

Create a **golden configuration corpus**.

For every vendor:

```text
Known-good configuration
Known-bad configuration
Edge cases
Malformed configuration
Unknown commands
```

Example:

```text
data/golden/
├── cisco/
├── juniper/
├── fortinet/
└── unknown/
```

Expected outputs should be stored alongside them.

---

# 58. AI Model Evaluation

For the AI mapping system measure:

```text
Accuracy
Precision
Recall
F1
Top-1 Accuracy
Top-3 Accuracy
Unknown detection rate
False mapping rate
Human approval rate
```

The existing model specification already targets coverage and false-parse performance and uses a mapping-registry feedback loop. 

---

# 59. Compliance Evaluation

Measure:

```text
Control evaluation accuracy
False positives
False negatives
Framework coverage
Evidence completeness
```

---

# 60. CVE Engine Evaluation

Measure:

```text
CVE matching precision
CVE matching recall
False positive rate
Affected-version accuracy
Version normalization accuracy
Unknown-version rate
```

This is particularly important because incorrect CVE matches can destroy trust in the auditor.

---

# 61. PQC Evaluation

Measure:

```text
Algorithm identification accuracy
Crypto asset extraction accuracy
CBOM completeness
PQC classification accuracy
Migration candidate accuracy
```

---

# 62. End-to-End Success Criteria

Your system should be considered successful when it can demonstrate:

### Test 1

```text
Cisco Config
→ Detect
→ Parse
→ Normalize
→ 4 Engines
→ Findings
→ Report
```

### Test 2

```text
Juniper Config
→ Detect
→ Parse
→ Normalize
→ 4 Engines
→ Findings
→ Report
```

### Test 3

```text
Fortinet Config
→ Detect
→ Parse
→ Normalize
→ 4 Engines
→ Findings
→ Report
```

### Test 4

```text
Unknown Vendor
→ AI Mapping
→ Human Approval
→ Canonical IR
→ 4 Engines
→ Findings
→ Report
```

### Test 5

```text
Unknown Command
→ Train
→ Mapping Registry
→ Re-upload
→ Automatically Recognized
```

### Test 6

```text
Finding
→ Remediation
→ Updated Configuration
→ Re-audit
→ Finding Resolved
```

---

# 63. The Complete Demo Story

For SIH, I would structure the live demo around one configuration.

### Step 1

Upload:

```text
Cisco configuration
```

### Step 2

System displays:

```text
Vendor: Cisco
Platform: IOS-XE
Confidence: 98%
```

### Step 3

Normalization:

```text
142 configuration statements
↓
118 canonical security properties
```

### Step 4

Run all four engines:

```text
Compliance
   7 failures

PQC
   3 migration candidates

Security
   5 security weaknesses

CVE
   2 confirmed vulnerabilities
```

### Step 5

Show unified risk:

```text
Critical: 2
High: 6
Medium: 7
Low: 2
```

### Step 6

Click one finding.

Show:

```text
Raw configuration
      ↓
Canonical property
      ↓
Security rule / CVE
      ↓
Evidence
      ↓
Risk
      ↓
Recommended remediation
```

### Step 7

Upload unknown vendor configuration.

System says:

```text
Vendor: Unknown
```

AI identifies:

```text
Unknown command
↓
Suggested meaning
↓
Confidence: 89%
```

Human clicks:

```text
APPROVE
```

### Step 8

Re-run.

The previously unknown command is now understood.

### Step 9

All four engines run again.

This demonstrates:

> **Learn once, audit automatically thereafter.**

That is a much stronger demonstration of the PS than simply showing a dashboard.

---

# 64. Final System Principle

Your complete architecture can be reduced to this:

```text
                 ANY NETWORK CONFIGURATION
                           │
                           ▼
                  UNIFIED INGESTION
                           │
                           ▼
                    VENDOR DETECTION
                           │
              ┌────────────┴────────────┐
              │                         │
           KNOWN                     UNKNOWN
              │                         │
       DETERMINISTIC                 AI + HITL
           PARSER                   TRAINING LOOP
              │                         │
              └────────────┬────────────┘
                           │
                           ▼
                 CANONICAL SECURITY
                   BASELINE MODEL
                           │
             ┌─────────────┼─────────────┐
             │             │             │
             ▼             ▼             ▼
        COMPLIANCE        PQC       SECURITY ANALYTICS
             │             │             │
             └─────────────┼─────────────┘
                           │
                           ▼
                          CVE
                         ENGINE
                           │
                           ▼
                  UNIFIED FINDINGS
                           │
                           ▼
                     RISK ENGINE
                           │
                           ▼
                  REMEDIATION ENGINE
                           │
                           ▼
                  RE-AUDIT / VERIFY
                           │
                           ▼
               EVIDENCE + REPORTING
```

## The one-line architecture for your team

> **Ingest → Detect → Parse/AI-Learn → Map → Canonical Security Baseline Model → Compliance + PQC + Security Analytics + CVE → Correlate → Risk → Remediate → Re-audit → Evidence-backed Report**
