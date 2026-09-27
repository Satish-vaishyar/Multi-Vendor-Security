# User guide - starting the application and using it

## 1. Start the server

```powershell
cd F:\Multi-vendor\backend
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000/ui** (test console) and log in (top bar)
with `admin@example.com` / `admin123`. Login is optional for most reads -
the console works anonymously and attaches the token automatically after login.
The base-URL box (default `http://127.0.0.1:8000`) lets the page talk to a
server on any host/port. “Check API” should report `healthy`.

> Prefer Swagger? Use **/docs** - every endpoint below is tryable there.

## 2. Guided demo (5 min, insecure Cisco router)

### Tab 1 - Upload & Audit
1. *Create demo asset* → note the `AST-…` id.
2. *Insecure Cisco* sample is pre-loaded (SSHv1, Telnet, HTTP, public SNMP,
   logging off, IOS-XE 17.9.2). Press *Upload* → header shows
   `CISCO / IOS-XE / 17.9.2`.
3. Tick CIS + NIST + STIG + ISO27001 → *Run audit*.
4. Result: low compliance score with counts of critical/high/medium findings,
   per-framework scores, and ~80 **unified findings** from all four engines.
   *Load evidence chain* shows the why-did-this-fail table
   (control → property → observed vs expected → source line);
   *Canonical IR* shows the normalized vendor-neutral device view.

### Tab 2 - Findings
*Refresh*, then filter by severity/engine. Pick any finding → *select* →
*Get plan → approve → dry-run apply*: shows vendor fix steps, an approval id,
and a simulated apply that **never touches a device** (`device_touched: false`).

### Tab 3 - Training (adaptive-vendor loop)
*Load queue* lists unknown lines from your upload → pick a training id →
*Suggest* (AI proposes canonical mappings) → set property/value → *Approve*.
The mapping is persisted to `okf/knowledge/mappings/learned/`; re-running the
audit recognizes the line automatically.

### Tab 4 - PQC / CBOM
*Load for last audit*: readiness score, algorithm table
(RSA/SSHv1/TLS rows flagged `MIGRATION_REQUIRED`), migration recommendations.

### Tab 5 - Reports
*Generate* → *Download*: a PDF with executive summary, scores and the findings
table (first 80 rows).

### Tab 0 - Dashboard
*Refresh*: asset totals, overall compliance, finding counts by severity,
CVE critical/high, pending training items.

## 3. Comparing secure vs insecure (the money demo)

Run the same flow with the *Secure Cisco* sample
(SSHv2, Telnet/HTTP off, SNMPv3-priv, remote syslog, password-encryption).
Its compliance score is **≥** the insecure one (asserted by
`tests/test_audit_flow.py::test_secure_scores_higher_than_insecure`).

## 4. Same flow from the command line (curl)

```bash
BASE=http://127.0.0.1:8000
TOKEN=$(curl -s $BASE/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"admin123"}' | python -c "import sys,json;print(json.load(sys.stdin)['data']['access_token'])")
AID=$(curl -s $BASE/api/v1/assets -H 'Content-Type: application/json' \
  -d '{"name":"Core-Router-01","vendor":"Cisco","product":"IOS-XE","version":"17.9.2","criticality":"HIGH"}' | python -c "import sys,json;print(json.load(sys.stdin)['data']['asset_id'])")
curl -s $BASE/api/v1/configurations/upload -F "file=@router.txt" -F "asset_id=$AID"
# → {"configuration_id":"CFG-…","detected_vendor":"CISCO","detected_platform":"IOS-XE",…}
curl -s $BASE/api/v1/audits -H 'Content-Type: application/json' -d "{
  \"asset_id\":\"$AID\",\"configuration_id\":\"CFG-…\",
  \"frameworks\":[\"CIS\",\"NIST\",\"STIG\",\"ISO27001\"],
  \"run_cve\":true,\"run_pqc\":true,\"run_security_analysis\":true}"
curl -s $BASE/api/v1/audits/AUD-…/results | python -m json.tool | head -40
curl -s $BASE/api/v1/reports -H 'Content-Type: application/json' \
  -d '{"audit_id":"AUD-…","format":"PDF"}'
curl -s -o audit.pdf $BASE/api/v1/reports/REP-…/download
```

(PowerShell: replace `curl` with `curl.exe` and use single-line JSON.)

## 5. Sample configurations to try

- **Insecure Cisco** (console preset): SSHv1 + Telnet + HTTP + `public` SNMP + no logging.
- **Secure Cisco** (console preset): SSHv2 + Telnet/HTTP off + SNMPv3-priv + syslog.
- **Juniper** (console preset): `set system services …` syntax - exercises cross-vendor normalization.
- **Unknown vendor**: paste proprietary-looking lines (e.g. `secure-mgmt ssh protocol v2`)
  and drive the Training tab to teach the system.

## 6. Rules of the road

- Remediation is **simulation only** - approve → dry-run → optional re-audit diff.
- Deterministic values win over AI (`arch.md` §7): the LLM only fills gaps the
  parsers cannot cover, and never decides compliance.
- Stores are in-memory: restarting the server clears assets/audits/findings.
  Export what matters via the PDF report or `/results` JSON.
