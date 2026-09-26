For **SIH 26155**, I would keep the stack focused and implementation-friendly. You do not need dozens of technologies. The important thing is that each technology has a clear role in the architecture.

# Recommended Tech Stack

## 1. Overall stack

| Layer                 | Technology                       | Purpose                                      |
| --------------------- | -------------------------------- | -------------------------------------------- |
| Frontend              | **React + Vite**                 | Web dashboard                                |
| UI                    | **Tailwind CSS**                 | Styling                                      |
| Charts                | **Recharts**                     | Compliance/risk/CVE visualisation            |
| Backend               | **Python + FastAPI**             | REST APIs and orchestration                  |
| Validation            | **Pydantic**                     | Canonical IR and API schema validation       |
| Database              | **PostgreSQL**                   | Assets, audits, findings, OKF, mappings      |
| Cache/Queue           | **Redis**                        | Caching, background jobs                     |
| Background jobs       | **Celery**                       | CVE updates, large audits, report generation |
| Configuration parsing | **Python + custom parsers**      | Vendor configuration parsing                 |
| AI/ML                 | **PyTorch + scikit-learn**       | Mapping, anomaly detection, ML models        |
| LLM                   | **API LLM / local LLM**          | Unknown-vendor semantic parsing              |
| Embeddings            | **Sentence Transformers**        | Semantic command/property mapping            |
| Vector DB             | **pgvector**                     | Store/search command embeddings              |
| Rules                 | **Python + YAML/JSON**           | OKF compliance rules                         |
| Security frameworks   | **OSCAL + custom OKF schema**    | Machine-readable controls                    |
| CVE                   | **NVD APIs + local CVE DB**      | Vulnerability correlation                    |
| CPE                   | **NVD CPE Dictionary**           | Product identification                       |
| CVE matching          | **Custom version-range engine**  | Determine affected versions                  |
| Crypto/PQC            | **Python cryptography + liboqs** | Cryptographic analysis/PQC                   |
| Network analysis      | **NetworkX**                     | Security/control dependency graph            |
| PDF                   | **ReportLab**                    | Audit reports                                |
| Testing               | **Pytest**                       | Backend/model testing                        |
| Containers            | **Docker + Docker Compose**      | Deployment                                   |
| Reverse proxy         | **Nginx**                        | Production serving                           |
| CI/CD                 | **GitHub Actions**               | Automated testing/deployment                 |
| Version control       | **Git + GitHub**                 | Source and OKF versioning                    |

---

# 2. Backend

### Python

**Primary backend language.**

Use it for:

```text
API
Parsing
AI/ML
OKF
Compliance
CVE
PQC
Risk
Remediation
Reports
```

### FastAPI

Use:

```text
FastAPI
├── /upload
├── /audit
├── /assets
├── /findings
├── /compliance
├── /cve
├── /pqc
├── /training
├── /remediation
└── /reports
```

Why FastAPI?

* Python-native
* Excellent Pydantic integration
* Async support
* Automatic OpenAPI documentation
* Easy ML integration

---

# 3. Data validation

## Pydantic

This is particularly important for your project.

Use it for:

```text
Raw parser output
        ↓
AI output
        ↓
Canonical IR
        ↓
OKF rules
        ↓
Findings
```

For example:

```python
class SoftwareComponent(BaseModel):
    vendor: str
    product: str
    version: str
    component_type: str
    cpe: str | None = None
```

This prevents an LLM from injecting arbitrary malformed data into your security engine.

---

# 4. Database

## PostgreSQL

Use PostgreSQL as your primary database.

Store:

```text
Users
Assets
Configurations
Canonical IR
Audit jobs
Findings
OKF controls
Frameworks
Mappings
Remediations
CVE records
CPE records
Risk
Training feedback
```

Recommended extensions:

### pgvector

Use it for:

```text
Vendor command embeddings
Canonical property embeddings
Semantic similarity
Unknown command search
Mapping recommendations
```

So you don't necessarily need a separate vector database.

---

# 5. Cache and background processing

## Redis

Use Redis for:

```text
Caching
Job queues
Temporary audit state
Rate limiting
LLM response caching
CVE update state
```

## Celery

Use Celery for long-running tasks:

```text
CVE database update
Large configuration audit
Embedding generation
Fleet analysis
PDF generation
Model retraining
```

Architecture:

```text
FastAPI
   │
   ▼
Redis
   │
   ▼
Celery Worker
   │
   ├── CVE Update
   ├── Audit
   ├── ML
   └── Reports
```

---

# 6. Frontend

## React + Vite

Use React for the dashboard.

Main pages:

```text
Dashboard
│
├── Overview
├── Upload Configuration
├── Audit Results
├── Compliance
├── CVE/Vulnerabilities
├── PQC
├── Security Analytics
├── Training
├── Remediation
└── Reports
```

## Tailwind CSS

Use Tailwind rather than spending too much time building a custom CSS framework.

## Recharts

For:

```text
Compliance %
Risk distribution
CVE severity
Framework comparison
Asset risk
PQC readiness
Trend charts
```

---

# 7. OKF technology

This is an important choice.

I recommend:

```text
OKF
├── YAML
├── JSON Schema
├── PostgreSQL
└── Python rule engine
```

Use YAML for human-maintained rules:

```yaml
control_id: OKF-SSH-001

property: SSH.VERSION

operator: EQUALS

expected: 2

severity: HIGH
```

Use JSON Schema/Pydantic for validation.

NIST's OSCAL is particularly useful here. OSCAL defines machine-readable security/control models and supports XML, JSON and YAML. Its models cover control catalogs, profiles, implementations and assessment information. ([NIST Computer Security Resource Center][1])

Therefore:

```text
Official framework data
        ↓
OSCAL where available
        ↓
OKF normalization
        ↓
Unified control representation
```

This is much better than manually hardcoding every framework into Python.

---

# 8. AI/ML stack

## scikit-learn

Use for:

```text
Baseline classifiers
Evaluation
Clustering
Anomaly detection
Feature processing
Metrics
```

## PyTorch

Use when you actually need neural-network training:

```text
Transformer experiments
Risk model
Custom embedding models
Quantum-classical experiments
```

## Sentence Transformers

Use for:

```text
Unknown command
        ↓
Embedding
        ↓
Semantic similarity
        ↓
Canonical property
```

Example:

```text
"enable secure ssh version 2"
             ↓
        Embedding
             ↓
SSH.VERSION
```

---

# 9. LLM layer

For the unknown-vendor parser:

```text
Unknown Config
      ↓
LLM
      ↓
Structured JSON
      ↓
Pydantic
      ↓
Canonical IR
```

The LLM should **not** be responsible for:

```text
CVE verdict
Compliance verdict
Risk score
PQC verdict
```

Those remain deterministic.

You can support:

```text
Cloud API LLM
+
Local LLM
```

For your demo, an API model is simpler and more reliable.

For offline deployment, use a local model through Ollama.

---

# 10. CVE stack

This part should be:

```text
NVD API
   ↓
Python ingestion
   ↓
PostgreSQL
   ↓
CPE Resolver
   ↓
Version Matcher
   ↓
CVE Correlator
```

NVD provides APIs for its official CPE Dictionary and CPE Match Criteria. The Match Criteria API supports retrieving vulnerability applicability information, including CPE match strings/ranges. ([NVD][2])

### Technologies

```text
httpx / requests
Pydantic
PostgreSQL
Python version parser
NVD API
```

I would **not** use an ML model for the actual CVE determination.

---

# 11. CVE architecture

```text
Canonical IR
     │
     ▼
Software Components
     │
     ▼
Product/Vendor Identification
     │
     ▼
CPE Resolver
     │
     ▼
NVD CPE/CVE Data
     │
     ▼
Version Range Matcher
     │
     ▼
CVE Correlation
     │
     ▼
Finding
```

---

# 12. PQC stack

Use:

### Python `cryptography`

For normal cryptographic inspection.

### liboqs / PQClean ecosystem

For post-quantum cryptographic experimentation.

Your production PQC engine should primarily be:

```text
Algorithm
+
Key size
+
Protocol
+
Configuration
+
Deterministic policy
```

rather than a trained neural network.

---

# 13. Security analytics

Initially:

```text
Python
+
NumPy
+
Pandas
+
scikit-learn
```

Later:

```text
HDBSCAN
XGBoost
```

Use this for:

```text
Fleet outlier detection
Configuration deviation
Risk patterns
Repeated security failures
```

---

# 14. Knowledge graph

## NetworkX

Use NetworkX initially.

Graph:

```text
Asset
 │
 ├── Software
 │     └── CPE
 │          └── CVE
 │
 ├── Control
 │     └── Framework
 │
 ├── Finding
 │
 └── Remediation
```

For example:

```text
Firewall-001
    │
    └── FortiOS 7.x
          │
          └── CPE
                │
                ├── CVE-XXXX
                └── CVE-YYYY
```

You don't need Neo4j initially. NetworkX + PostgreSQL is enough for the SIH prototype.

---

# 15. Configuration parsing

Use:

```text
Python
├── TextFSM
├── ntc-templates
├── Netmiko
├── NAPALM
└── Custom vendor parsers
```

But for **offline configuration files**, your own parser layer will be important.

Architecture:

```text
Cisco Parser
Juniper Parser
Fortinet Parser
Palo Alto Parser
Arista Parser
        │
        ▼
Canonical IR
```

Unknown:

```text
Unknown Config
       ↓
LLM
       ↓
Canonical IR
```

---

# 16. Report generation

Use:

## ReportLab

Generate:

```text
Executive Summary
Asset Information
Compliance Summary
CVE Findings
PQC Assessment
Security Findings
Risk Summary
Remediation
Evidence
```

Output:

```text
audit_report.pdf
```

---

# 17. Security

For the application itself:

```text
JWT
OAuth2
Argon2/bcrypt
HTTPS
RBAC
Audit logging
Secrets management
```

FastAPI supports OAuth2/JWT patterns well.

Use roles:

```text
Admin
Auditor
Security Analyst
Viewer
```

---

# 18. Deployment

## Docker

Containerise:

```text
frontend
backend
postgres
redis
worker
nginx
```

Architecture:

```text
                    Nginx
                      │
             ┌────────┴────────┐
             ▼                 ▼
          React             FastAPI
                               │
                    ┌──────────┼─────────┐
                    ▼          ▼         ▼
                PostgreSQL   Redis     ML/LLM
                               │
                               ▼
                             Celery
```

---

# 19. Development environment

Your local development stack:

```text
Windows 11
VS Code
Python 3.12
Node.js
Git
Docker Desktop
PostgreSQL
```

For the actual SIH deployment, Docker makes the environment reproducible.

---

# 20. Testing stack

Use:

```text
Pytest
pytest-asyncio
httpx
```

Test:

```text
Parser tests
Canonical IR tests
OKF rule tests
CVE matching tests
Version matching tests
ML tests
API tests
End-to-end audit tests
```

Especially create **golden test cases**:

```text
Input Config
      ↓
Expected IR
      ↓
Expected Controls
      ↓
Expected CVEs
      ↓
Expected Findings
```

---

# 21. Monitoring

For the SIH prototype, keep this lightweight:

```text
Python logging
Structured JSON logs
Audit trail
```

If you scale later:

```text
Prometheus
Grafana
OpenTelemetry
```

These aren't necessary for your first implementation.

---

# 22. Final recommended stack

If I had to freeze the stack **today**, I would use:

```text
╔══════════════════════════════════════════════╗
║              SIH 26155 STACK                 ║
╠══════════════════════════════════════════════╣
║ Frontend                                     ║
║ React + Vite + Tailwind + Recharts           ║
╠══════════════════════════════════════════════╣
║ Backend                                      ║
║ Python + FastAPI + Pydantic                  ║
╠══════════════════════════════════════════════╣
║ Database                                     ║
║ PostgreSQL + pgvector                        ║
╠══════════════════════════════════════════════╣
║ Async / Cache                                ║
║ Redis + Celery                               ║
╠══════════════════════════════════════════════╣
║ Configuration                                ║
║ Python + TextFSM + NTC Templates + Custom   ║
║ Parsers + Netmiko/NAPALM                     ║
╠══════════════════════════════════════════════╣
║ AI/ML                                        ║
║ PyTorch + scikit-learn                       ║
║ Sentence Transformers                        ║
║ LLM API / Ollama                             ║
╠══════════════════════════════════════════════╣
║ OKF                                          ║
║ YAML + JSON Schema + PostgreSQL + Python     ║
║ Rules + OSCAL                                ║
╠══════════════════════════════════════════════╣
║ CVE                                         ║
║ NVD API + CPE + PostgreSQL + Version Engine  ║
╠══════════════════════════════════════════════╣
║ PQC                                          ║
║ cryptography + liboqs                        ║
╠══════════════════════════════════════════════╣
║ Security Analytics                           ║
║ NumPy + Pandas + scikit-learn + HDBSCAN     ║
║ + XGBoost                                    ║
╠══════════════════════════════════════════════╣
║ Knowledge Graph                              ║
║ NetworkX                                     ║
╠══════════════════════════════════════════════╣
║ Reporting                                    ║
║ ReportLab                                    ║
╠══════════════════════════════════════════════╣
║ Deployment                                   ║
║ Docker + Docker Compose + Nginx              ║
╠══════════════════════════════════════════════╣
║ Testing                                      ║
║ Pytest + httpx                               ║
╠══════════════════════════════════════════════╣
║ CI/CD                                        ║
║ GitHub Actions                               ║
╚══════════════════════════════════════════════╝
```

### What I would **not** add right now

Avoid overengineering with:

* ❌ Kubernetes
* ❌ Kafka
* ❌ Elasticsearch
* ❌ Neo4j
* ❌ separate vector database
* ❌ multiple LLMs
* ❌ custom deep-learning parser
* ❌ custom CVE prediction model
* ❌ quantum hardware dependency

For your first SIH implementation, **PostgreSQL + pgvector + FastAPI + React + Python ML + NVD + OSCAL + Docker** is more than sufficient.

The particularly strong technical choice is **OSCAL + your OKF**: OSCAL already provides machine-readable models for security controls and assessments in JSON/YAML/XML, so your OKF can normalize framework content around a standards-based foundation rather than inventing an entirely isolated format. ([NIST Computer Security Resource Center][1])

[1]: https://csrc.nist.gov/Projects/open-security-controls-assessment-language/models?utm_source=chatgpt.com "Open Security Controls Assessment Language | CSRC"
[2]: https://nvd.nist.gov/developers/products?utm_source=chatgpt.com "Product APIs"
