# SIH 26155: AI/ML Model & Dataset Development Document

**Problem Statement:** SIH26155, AI-Driven Multi-Vendor Network Security Compliance Auditor
**Organization:** National Technical Research Organisation (NTRO)
**Version:** 1.0
**Purpose:** Complete model, dataset, training, evaluation and API plan for the implementation team

The official problem statement requires vendor-neutral normalization, AI-assisted interpretation of unseen vendor syntax, an administrator training loop, multi-framework compliance evaluation and actionable remediation/reporting. It explicitly describes the challenge as both syntactic diversity and adaptation to new/proprietary configurations. ([SIH 2026 Problem Statements][1])

---

# 1. Executive Model Strategy

The system should **not** try to train one giant AI model to perform the entire audit.

Instead, use a layered architecture:

```text
                    RAW NETWORK CONFIG
                           │
                           ▼
                    Vendor Detection
                           │
                           ▼
                 Deterministic Parser
                           │
                           ▼
                Unknown Token Detector
                           │
                    ┌──────┴──────┐
                    │             │
                  Known         Unknown
                    │             │
                    │       Embedding + Mapping
                    │             │
                    │             ▼
                    │          LLM Parser
                    │             │
                    │       Human Validation
                    │             │
                    └──────┬──────┘
                           ▼
                CANONICAL SECURITY
                   BASELINE MODEL
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
     Compliance           PQC          Security Analytics
       Engine            Engine              Engine
          │                │                  │
          └────────────────┼──────────────────┘
                           │
                           ▼
                      CVE Engine
                           │
                           ▼
                  Unified Finding Engine
                           │
                           ▼
                     Risk Engine
                           │
                           ▼
                    Remediation
                           │
                           ▼
                     Reporting
```

The **AI/ML portion is primarily responsible for understanding configuration syntax**. The actual compliance, CVE and PQC decisions should remain deterministic and evidence-based.

That is particularly important because the official PS expects an auditable configuration assessment, not an LLM that simply generates security opinions. ([SIH 2026 Problem Statements][1])

---

# 2. Final List of Models

## Core models

| ID  | Model                               | Type                        | Train from scratch?    | Priority     |
| --- | ----------------------------------- | --------------------------- | ---------------------- | ------------ |
| M1  | Vendor Detector                     | Classification / rules + ML | No initially           | 🔴 Critical  |
| M2  | Unknown Token Detector              | Embedding + OOV classifier  | Fit/train              | 🔴 Critical  |
| M3  | Configuration Mapping Model         | Embedding + kNN/centroid    | Fit/train continuously | 🔴 Critical  |
| M4  | LLM Configuration Parser            | Pre-trained LLM             | No                     | 🔴 Critical  |
| M5  | Canonical IR Validator              | Schema/rule model           | No                     | 🔴 Critical  |
| M6  | Risk Scoring Model                  | Rules → XGBoost later       | Later                  | 🟠 High      |
| M7  | Fleet Anomaly Detector              | HDBSCAN/K-Means             | Fit per fleet          | 🟠 High      |
| M8  | Semantic Duplicate/Similarity Model | Embeddings                  | No                     | 🟡 Medium    |
| M9  | Small Transformer Baseline          | Transformer classifier      | Yes                    | 🟡 Benchmark |
| M10 | QKS                                 | Quantum kernel classifier   | Fit                    | 🟡 Research  |
| M11 | VQC                                 | Quantum classifier          | Fit                    | 🟡 Research  |
| M12 | QAOA                                | Quantum optimizer           | Optimize               | 🟡 Research  |
| M13 | VQE                                 | Quantum optimizer           | Optimize               | 🟡 Research  |

**Important:** M10-M13 should never be allowed to become dependencies of the main auditor.

---

# 3. M1: Vendor Detection Model

## Purpose

Determine:

* Vendor
* Product family
* OS/platform
* Configuration version
* Confidence

Example:

```text
Input:

interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0

Output:

Vendor: Cisco
Platform: IOS/IOS-XE
Confidence: 0.98
```

For an unknown configuration:

```text
Vendor: UNKNOWN
Confidence: 0.31
```

That routes the configuration to the adaptive pipeline.

## Recommended approach

Do **not** train a deep neural network initially.

Use a hybrid:

```text
Vendor signatures
+
CLI keywords
+
Syntax patterns
+
OS fingerprints
+
Optional lightweight classifier
```

Example:

```text
"interface GigabitEthernet"
"router ospf"
"ip access-list"
```

can strongly indicate Cisco IOS-style syntax.

## Dataset required

Create:

```text
datasets/vendor_detection/
```

with:

```text
Cisco/
Juniper/
Fortinet/
PaloAlto/
Arista/
MikroTik/
Unknown/
```

### Target

Start with **5 vendors + unknown**.

I recommend:

1. Cisco IOS/IOS-XE
2. Juniper Junos
3. Fortinet FortiOS
4. Palo Alto PAN-OS
5. Arista EOS
6. Unknown/proprietary

The official PS lists a much broader vendor landscape, but trying to deeply implement every listed vendor is not necessary for the first working system. ([SIH 2026 Problem Statements][1])

### Dataset target

Create approximately:

```text
500 configurations/vendor
× 5 vendors
= 2,500 known configurations
```

plus:

```text
500 unknown/novel configurations
```

**Target total: ~3,000 configuration files.**

These do not need to be 3,000 completely different real devices. You can generate controlled variants from public examples and synthetic configurations.

---

# 4. M2: Unknown Token Detector

This is the first genuinely important ML model.

## Purpose

Determine:

> "Can my deterministic parser safely understand this command?"

Example:

```text
Known:

ip ssh version 2
       ↓
Known

Unknown:

set security-protection adaptive-mode strict
       ↓
Unknown / low confidence
       ↓
AI pipeline
```

## Architecture

```text
Command
   ↓
Tokenizer
   ↓
Embedding
   ↓
Known-command index
   ↓
Similarity/OOV score
   ↓
Threshold
```

## Recommended model

**Sentence-Transformers MiniLM-class embedding model**

Use a local pretrained embedding model.

Do not fine-tune it initially.

---

# 5. Dataset for Unknown Token Detector

You need **line-level labelled data**.

Create:

```text
datasets/unknown_token/
```

with:

```text
command
vendor
platform
context
label
```

Example:

```csv
command,vendor,platform,label
"ip ssh version 2",Cisco,IOS-XE,known
"no ip http server",Cisco,IOS-XE,known
"security-zone trusted",Unknown,Unknown,unknown
```

## Target dataset

Start with:

### Known

```text
10,000 configuration lines
```

### Unknown

```text
3,000 configuration lines
```

### Total

```text
13,000 labelled lines
```

Don't randomly split lines from the same configuration into train/test. That would cause leakage.

Split by **configuration file/device**, not merely by individual lines.

Recommended:

```text
70% train
15% validation
15% test
```

---

# 6. M3: Configuration Mapping Model

This is the **most important trainable model in your project**.

It answers:

> "What Canonical Security Baseline Model property does this vendor-specific command represent?"

Example:

```text
Vendor command:

no service telnet

       ↓

Mapping Model

       ↓

services.telnet
       =
false
```

Another:

```text
set system services ssh protocol-version v2

       ↓

services.ssh.version
       =
2
```

---

# 7. Mapping Model Architecture

Use:

```text
Command
+
Context
+
Vendor
+
Platform
+
Version
       ↓
Embedding
       ↓
Candidate IR properties
       ↓
kNN / Centroid Classifier
       ↓
Top-3 suggestions
       ↓
Human approval
       ↓
Mapping Registry
```

This is preferable to immediately fine-tuning a transformer because your initial labelled dataset will be small.

---

# 8. Mapping Dataset

You need a **Canonical Mapping Dataset**.

Create:

```text
datasets/mapping/
```

Format:

```json
{
  "vendor": "cisco",
  "platform": "ios-xe",
  "version": "17.x",
  "command": "no ip http server",
  "context": [
    "ip http secure-server",
    "no ip http server"
  ],
  "canonical_path": "services.http",
  "canonical_value": false,
  "category": "services",
  "confidence": 1.0,
  "source": "manual_verified"
}
```

---

# 9. Canonical Classes

Before training M3, **freeze your Canonical IR schema**.

Otherwise your labels will continuously change.

Start with approximately:

### Device

```text
device.vendor
device.platform
device.version
device.hostname
device.serial
```

### Authentication

```text
aaa.authentication
aaa.authorization
aaa.accounting
aaa.mfa
```

### Services

```text
services.ssh
services.ssh.version
services.telnet
services.http
services.https
services.snmp
```

### Logging

```text
logging.enabled
logging.remote_syslog
logging.timestamp
```

### Access control

```text
acl.enabled
acl.rules
acl.management
```

### Cryptography

```text
crypto.algorithm
crypto.key_size
crypto.tls_version
crypto.ssh_algorithm
crypto.certificate
```

### Interfaces

```text
interfaces.*
```

### Routing

```text
routing.*
```

### Security policies

```text
policies.*
```

Start with **~100-150 canonical properties** rather than hundreds or thousands.

---

# 10. Mapping Dataset Size

Initially target:

```text
150 canonical properties
× 20 verified commands/property
```

= approximately:

**3,000 verified mappings**

A practical target:

```text
2,000–5,000 verified mapping samples
```

Then continuously add human-approved examples.

Your learning loop becomes:

```text
Initial dataset
      ↓
Mapping model
      ↓
Unknown command
      ↓
Top-3 prediction
      ↓
Human approval
      ↓
New training sample
      ↓
Registry update
      ↓
Model refresh
```

This directly implements the adaptive-training concept required by the PS. ([SIH 2026 Problem Statements][1])

---

# 11. M4: LLM Configuration Parser

## Do NOT train this model.

Use a pre-trained LLM.

Its responsibility is:

> **Convert difficult/unseen configuration syntax into structured candidate security properties.**

It should produce structured JSON.

Example:

```json
{
  "property": "services.ssh.version",
  "value": 2,
  "confidence": 0.91,
  "evidence": "set system services ssh protocol-version v2"
}
```

---

# 12. LLM Role

The LLM should **not** make the final security decision.

Wrong architecture:

```text
Config
 ↓
LLM
 ↓
"Configuration is secure"
```

Correct:

```text
Config
 ↓
LLM
 ↓
Canonical IR
 ↓
Deterministic Engines
 ↓
Evidence-backed finding
```

---

# 13. LLM API Requirements

Select an API model that supports:

* Structured JSON output
* Schema-constrained output
* Low temperature/deterministic operation
* Long context
* Good code/configuration understanding

You can use a strong OpenAI model as the primary API and keep a local Ollama model as an offline fallback.

For sensitive configurations, local inference is particularly useful.

---

# 14. M5: Canonical IR Validator

This is not an ML model.

Use:

```text
Pydantic
+
JSON Schema
+
Business validation rules
```

Example:

```text
services.ssh.version
```

must be:

```text
1 / 2 / unknown
```

not:

```text
"maybe secure"
```

The validator prevents AI-generated garbage from entering the security engines.

---

# 15. M6: Risk Scoring Model

Do not start with ML.

Start with a deterministic formula.

For example:

```text
Risk =
Severity
× Exposure
× Asset Criticality
× Confidence
```

Later, once you have enough labelled findings:

```text
Features
 ↓
XGBoost
 ↓
Risk Priority
```

---

# 16. Risk Dataset

You will need analyst-labelled findings.

Create:

```text
datasets/risk/
```

Example:

```csv
severity,cvss,exposure,asset_criticality,pqc_impact,compliance_impact,priority
high,8.8,internet,critical,medium,high,critical
medium,5.3,internal,medium,low,medium,medium
```

### Initial target

Create at least:

**5,000 synthetic/analyst-labelled findings**

with controlled combinations.

Later replace synthetic labels with real analyst decisions.

---

# 17. M7: Fleet Outlier Detector

This detects:

> "Which device is significantly different from the normal security posture of this fleet?"

Example:

```text
99 devices:

logging = enabled

1 device:

logging = disabled

       ↓

Fleet anomaly
```

## Recommended algorithm

Use:

**HDBSCAN**

with K-Means as fallback.

No neural network required.

---

# 18. Fleet Dataset

You need normalized IRs.

Create:

```text
datasets/fleet/
```

Generate synthetic fleets.

Example:

```text
Fleet A
 ├── Router 001
 ├── Router 002
 ├── Router 003
 ...
 └── Router 100
```

Then inject controlled deviations:

```text
Missing logging
Telnet enabled
Weak SNMP
HTTP enabled
Weak SSH
Missing ACL
Weak crypto
```

Target:

**500 synthetic fleets × 50-100 devices**

This gives you enough examples to test anomaly detection.

---

# 19. M8: Semantic Similarity Model

This uses the same embedding backbone.

Purpose:

* Duplicate finding detection
* Similar commands
* Similar configurations
* Semantic-equivalence detection
* Finding deduplication

Example:

```text
"Telnet service is active"

and

"Unencrypted remote terminal access is enabled"

```

should be recognized as semantically related.

No separate training is necessary initially.

Use the same embedding model.

---

# 20. M9: Small Transformer Benchmark

This is not your primary production model.

Use it to benchmark:

```text
kNN/centroid
vs
small Transformer
```

Possible architecture:

```text
MiniLM/BERT-style encoder
+
classification head
```

Train it on your mapping dataset.

Only build this after M3 works.

---

# 21. M10: QKS

Quantum Kernel method.

Use it as an experimental model:

```text
Mapping Dataset
      ↓
Feature Extraction
      ↓
PCA
      ↓
10-12 dimensions
      ↓
Quantum Kernel
      ↓
Classification
```

Compare against:

```text
XGBoost
Transformer
QKS
```

Your existing project specification already places PCA before the QML models. 

---

# 22. M11: VQC

Variational Quantum Classifier.

Use:

```text
Qiskit
+
Aer
```

First.

Only then test actual quantum hardware if useful.

Architecture:

```text
Features
 ↓
PCA
 ↓
Quantum Encoding
 ↓
Variational Circuit
 ↓
Measurement
 ↓
Mapping Classification
```

Do not make it responsible for the production mapping pipeline.

---

# 23. M12: QAOA

Use QAOA for:

> **Audit/remediation prioritization optimization.**

Example:

```text
50 findings
+
limited remediation capacity
+
asset criticality
+
risk
+
dependencies

       ↓

QAOA

       ↓

Optimal/near-optimal remediation subset
```

This is an advanced research demonstration.

---

# 24. M13: VQE

Use VQE for experimental optimization of:

```text
Severity weight
Exposure weight
Asset criticality
Compliance impact
PQC impact
Exploitability
```

Compare:

```text
Expert-defined weights
vs
Classical optimization
vs
VQE
```

Again, research only.

---

# 25. Non-ML Engine: Compliance

Do **not train a compliance model**.

Build:

```text
Control Pack
      ↓
Evaluation Rule
      ↓
Canonical IR
      ↓
PASS / FAIL / PARTIAL / UNKNOWN
```

The official PS explicitly calls for frameworks including CIS, NIST, STIGs and ISO/IEC 27001. ([SIH 2026 Problem Statements][1])

Your initial control dataset should therefore be:

```text
CIS
NIST
STIG
ISO
CERT-In
```

---

# 26. Compliance Dataset

Create:

```text
datasets/compliance/
```

Structure:

```text
framework/
    control_id
    title
    description
    severity
    condition
    canonical_property
    expected_value
    evidence_rule
    remediation
    references
```

Start with **50-100 high-value controls per framework**, rather than attempting hundreds immediately.

That gives:

```text
5 frameworks
× 75 controls
≈ 375 controls
```

This is a realistic starting knowledge base.

---

# 27. Non-ML Engine: PQC

Do not train a PQC model initially.

Create:

```text
datasets/pqc/
```

with cryptographic rules.

Example:

```text
Algorithm
Key Size
Protocol
Security Status
PQC Status
Migration Recommendation
```

Cover:

```text
RSA
ECDSA
DSA
DH
ECDH
AES
3DES
DES
RC4
SHA-1
MD5
TLS
SSH
IPsec
SNMP
```

The output is:

```text
CBOM
+
PQC Readiness
+
Q-Day Exposure
```

---

# 28. Non-ML Engine: CVE

This is very important:

## Do not train a CVE prediction model.

Use authoritative vulnerability data.

Your pipeline should be:

```text
Canonical Device
      ↓
Vendor
      ↓
Product
      ↓
Version
      ↓
CPE
      ↓
NVD
      ↓
Affected-version matching
      ↓
CVE
      ↓
CVSS
```

NVD provides APIs for CPE and vulnerability information, including the official CPE dictionary and matching data. ([NVD][2])

The SIH architecture already identifies CVE correlation using the NVD feed as the intended direction. 

---

# 29. CVE Dataset You Should Build

Create a local cache:

```text
datasets/cve/
```

Store:

```text
cve_id
cpe
vendor
product
version_ranges
cvss
severity
description
references
published
modified
fixed_version
```

Do **not manually create thousands of CVE records**.

Build a downloader/synchronizer that retrieves the vulnerability data and stores a normalized local database.

Then your CVE engine works offline during an audit.

---

# 30. Complete Dataset Architecture

Your project should eventually have:

```text
datasets/
│
├── vendor_detection/
│
├── raw_configs/
│   ├── cisco/
│   ├── juniper/
│   ├── fortinet/
│   ├── paloalto/
│   ├── arista/
│   └── unknown/
│
├── parsed_configs/
│
├── canonical_ir/
│
├── unknown_tokens/
│
├── mappings/
│
├── compliance/
│   ├── cis/
│   ├── nist/
│   ├── stig/
│   ├── iso/
│   └── cert_in/
│
├── cve/
│
├── pqc/
│
├── risk/
│
├── fleet/
│
├── quantum/
│
├── golden/
│
└── evaluation/
```

---

# 31. Golden Dataset

This is one of the most important datasets in the entire project.

Create:

```text
datasets/golden/
```

Every golden configuration should contain:

```text
raw configuration
expected vendor
expected platform
expected canonical IR
expected findings
expected remediation
```

Example:

```text
golden/
└── cisco/
    ├── secure_router_001/
    │   ├── config.txt
    │   ├── expected_ir.json
    │   ├── expected_findings.json
    │   └── expected_remediation.json
```

This becomes your **ground truth**.

---

# 32. Synthetic Data Generation

Since you currently have **zero data**, do not wait for a perfect dataset.

Build a data-generation pipeline.

```text
Vendor Templates
       ↓
Configuration Generator
       ↓
Security Variants
       ↓
Ground Truth Generator
       ↓
Dataset
```

For each vendor generate:

### Secure configuration

```text
SSH v2
Telnet disabled
HTTP disabled
Logging enabled
Strong crypto
Restricted ACL
```

### Insecure configuration

```text
Telnet enabled
HTTP enabled
Weak SSH
Missing logging
Permissive ACL
Weak crypto
```

### Edge cases

```text
Missing command
Duplicate command
Conflicting command
Malformed syntax
Unknown command
Unsupported version
```

---

# 33. Data Generation Matrix

For each vendor:

```text
              Secure   Insecure   Edge   Unknown
Cisco            200       200      50      50
Juniper          200       200      50      50
Fortinet         200       200      50      50
Palo Alto        200       200      50      50
Arista           200       200      50      50
Unknown          100       100      50     100
```

This gives approximately:

**3,000 configurations.**

You can expand it later.

---

# 34. Data Quality Rules

Every dataset sample should have:

```text
source
vendor
platform
version
configuration_hash
label_source
created_at
validated_by
ground_truth_status
```

For synthetic samples:

```text
source = synthetic
```

For public examples:

```text
source = public
```

For manually verified mappings:

```text
source = expert_verified
```

Never mix unverified AI-generated labels into your ground-truth test set.

---

# 35. Train / Validation / Test Strategy

This is critical.

Do **not** randomly split individual commands from the same configuration.

Instead:

```text
Device/configuration-level split
```

Example:

```text
70%
Training

15%
Validation

15%
Test
```

And create a separate:

```text
UNSEEN VENDOR TEST SET
```

This is especially important because the PS's central challenge is adaptation to previously unseen syntax. ([SIH 2026 Problem Statements][1])

---

# 36. Most Important Evaluation Dataset

Create a dedicated:

```text
datasets/evaluation/unseen_vendor/
```

The model should **never see these mappings during training**.

Test:

```text
Vendor X
Command A
Command B
Command C
...
```

Then evaluate:

```text
Did the AI understand it?
Did it map correctly?
Did human approval fix it?
Can it recognize it on the second upload?
```

That is your strongest proof of the adaptive-training feature.

---

# 37. Model Evaluation Metrics

## Vendor Detector

```text
Accuracy
Precision
Recall
F1
Unknown detection rate
```

## Unknown Token Detector

```text
Precision
Recall
F1
False-parse rate
Coverage
```

## Mapping Model

```text
Top-1 accuracy
Top-3 accuracy
MRR
Human acceptance rate
Coverage improvement
```

## LLM Parser

```text
JSON validity
Schema validity
Property accuracy
Value accuracy
Evidence accuracy
Hallucination/error rate
```

## Risk Model

```text
Precision
Recall
F1
Spearman correlation
Analyst agreement
```

## Fleet Detector

```text
Precision
Recall
False alert rate
Silhouette score
```

## QML

```text
Accuracy
F1
Training time
Inference time
Classical-vs-quantum delta
```

---

# 38. Recommended Training Order

Because you are starting from **zero**, don't start with QML.

Follow this exact order.

### Phase 1

Build:

```text
Canonical IR
```

**Before training anything.**

---

### Phase 2

Collect:

```text
Cisco
Juniper
Fortinet
```

configurations.

---

### Phase 3

Build deterministic parsers.

---

### Phase 4

Create:

```text
Unknown Token Dataset
```

---

### Phase 5

Train:

```text
M2 Unknown Token Detector
```

---

### Phase 6

Create:

```text
Mapping Dataset
```

---

### Phase 7

Build:

```text
M3 Mapping Classifier
```

---

### Phase 8

Integrate:

```text
LLM Parser
```

---

### Phase 9

Build:

```text
Training GUI
```

---

### Phase 10

Implement:

```text
Compliance
PQC
CVE
Security Analytics
```

---

### Phase 11

Build:

```text
Unified Finding
+
Risk Engine
```

---

### Phase 12

Build:

```text
Fleet anomaly
+
XGBoost
```

---

### Phase 13

Only then:

```text
QKS
VQC
QAOA
VQE
```

---

# 39. Final Recommended Model Stack

If I were setting up your repository **today with absolutely no data**, I would freeze this:

```text
CORE PRODUCTION
────────────────────────────────────

M1  Vendor Detector
    Rules + lightweight classifier

M2  Unknown Token Detector
    MiniLM embedding + OOV classifier

M3  Mapping Registry Classifier
    MiniLM + kNN/Centroid

M4  LLM Configuration Parser
    API/local pretrained LLM

M5  Canonical IR Validator
    Pydantic + JSON Schema

M6  Risk Engine
    Rules initially → XGBoost later

M7  Fleet Outlier Detector
    HDBSCAN


SECURITY KNOWLEDGE ENGINES
────────────────────────────────────

E1  Compliance Engine
    Deterministic control packs

E2  PQC Engine
    Deterministic crypto rules

E3  Security Analytics
    Rules + correlation

E4  CVE Engine
    NVD/CPE + version matching


RESEARCH / DIFFERENTIATION
────────────────────────────────────

M8  Small Transformer
M9  QKS
M10 VQC
M11 QAOA
M12 VQE
```

---

# 40. What You Should Build First

Since you currently have **nothing**, your immediate first milestone should **not be model training**.

Build this:

```text
                    WEEK 1 FOUNDATION

                 Canonical Security IR
                         │
             ┌───────────┴───────────┐
             │                       │
       Dataset Schema          Vendor Config
             │                       │
             │                Cisco / Juniper /
             │                   Fortinet
             │                       │
             └───────────┬───────────┘
                         │
                         ▼
                 Golden Dataset
                         │
                         ▼
              Deterministic Parser
                         │
                         ▼
                  Expected IR
```

Only when this is working should you start M2 and M3.

This follows the central requirement of the PS: **heterogeneous configurations must first be normalized into a vendor-neutral security model**, after which compliance and other analysis can operate consistently. ([SIH 2026 Problem Statements][1])

---

# 41. The Most Important Dataset You Need

If you ask me **"What should we spend the most effort creating?"**, the answer is:

## `Configuration → Canonical IR` Dataset

Not a generic cybersecurity dataset.

Your core training record should look like:

```json
{
  "vendor": "cisco",
  "platform": "ios-xe",
  "version": "17.9",

  "raw_command": "no ip http server",

  "context": [
    "ip http secure-server",
    "no ip http server"
  ],

  "canonical_path": "services.http",

  "canonical_value": false,

  "security_category": "management_services",

  "confidence": 1.0,

  "label_source": "expert_verified"
}
```

This single dataset can eventually support:

```text
Unknown Token Detector
        ↓
Mapping Classifier
        ↓
Transformer
        ↓
QKS
        ↓
VQC
```

So **invest heavily in dataset quality rather than trying to collect random cybersecurity datasets**.

---

# 42. Final Target Dataset

Before your final SIH demonstration, I would aim for approximately:

| Dataset                        |                  Target |
| ------------------------------ | ----------------------: |
| Raw configurations             |                  3,000+ |
| Configuration lines            |                100,000+ |
| Verified command mappings      |                  5,000+ |
| Canonical properties           |                 100-150 |
| Compliance controls            |                 300-500 |
| CVE records                    | NVD-derived local cache |
| PQC rules                      |                   30-50 |
| Golden configurations          |                    200+ |
| Unknown-vendor configurations  |                    300+ |
| Synthetic fleet configurations |                 10,000+ |
| Risk-labelled findings         |                  5,000+ |

You **do not need all of these on day one**. They are the target state.

---

# 43. Final Recommendation

Your project should have **three levels of intelligence**:

### Level 1: Deterministic

```text
Parser
Canonical IR
Compliance
PQC
CVE
Evidence
Remediation
```

### Level 2: AI-assisted

```text
Unknown Detection
Mapping
LLM Parsing
Semantic Similarity
Risk
Fleet Analytics
```

### Level 3: Research

```text
QKS
VQC
QAOA
VQE
```

This is the strongest architecture because the **AI is solving the exact hard problem identified by NTRO, unseen vendor/configuration syntax**, while the security verdict itself remains reproducible and auditable. The official PS specifically calls for an interactive training loop where administrators map unfamiliar commands to security parameters and the system subsequently learns without backend redeployment. ([SIH 2026 Problem Statements][1])

**Your first concrete deliverable should therefore be the `Canonical IR + Dataset Schema + 3-vendor raw configuration corpus + Golden Dataset`.** Once those four are ready, the actual ML training becomes straightforward rather than guessing what data the models should learn from.

[1]: https://sih2026.vuce.in/ps/SIH26155?utm_source=chatgpt.com "SIH26155 · AI-Driven Multi-Vendor Network Security Compliance Auditor | SIH 2026 Problem Statements"
[2]: https://nvd.nist.gov/developers/products?utm_source=chatgpt.com "Product APIs"
