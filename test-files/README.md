# Test Files - what each file is for

Upload these from the frontend: **Upload → Configuration Files** (drag & drop or Browse).
All files are plain text (`.txt`), each under 5 KB, well below the 5 MB backend limit.

| # | File | Vendor detected | Expected result |
|---|---|---|---|
| 1 | `01-cisco-insecure-router.txt` | CISCO / IOS-XE 17.9.2 | LOW score. SSHv1, Telnet, HTTP, public SNMP, no logging/NTP/AAA, 1024-bit key. Your "bad" demo - lots of findings. |
| 2 | `02-cisco-secure-router.txt` | CISCO / IOS-XE 17.9.4 | HIGH score. Hardened reference. Upload both 01 + 02 and compare scores - secure must score ≥ insecure. |
| 3 | `03-juniper-insecure-switch.txt` | JUNIPER / Junos 20.4R3 | LOW score. SSHv1, Telnet, HTTP, weak IKE (dh-group1), no syslog/NTP. |
| 4 | `04-fortinet-insecure-firewall.txt` | FORTINET / FortiOS 7.2.2 | LOW score + CVE hits (old FortiOS is in the CVE knowledge base). |
| 5 | `05-paloalto-insecure-firewall.txt` | PALOALTO / PAN-OS 10.2.3 | LOW score. Telnet, HTTP, permissive any-any rule, weak crypto. |
| 6 | `06-arista-insecure-switch.txt` | ARISTA / EOS 4.28.0F | LOW score. HTTP-only management API, SSHv1, Telnet, public SNMP. |
| 7 | `07-edge-unknown-tokens.txt` | CISCO (known lines) + unknowns | Mixed. Check the **Unknown Tokens** tab and the **Training** page - the `blorp`/`hyperflux` lines should appear in the training queue. |

## Suggested test runs

1. **Single upload**: file 01 → Start Audit (all frameworks, all engines on) → Results.
2. **Secure vs insecure**: file 01, then file 02 → compare compliance scores on Audit Results.
3. **Bulk upload**: select files 03-06 together → Bulk upload → run one audit per configuration.
4. **Training loop**: file 07 → Configuration details → **Unknown Tokens** tab → Training page → Suggest/Approve.
5. **CVE + PQC + Analytics**: any audit with `run_cve`, `run_pqc`, `run_security_analysis` checked → open Vulnerabilities, PQC, Security Analytics pages.
6. **PDF report**: on Start Audit check **Generate PDF report**, or Reports page → generate → download.
