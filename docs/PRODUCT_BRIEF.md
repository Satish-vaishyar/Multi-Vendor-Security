# Product brief: who pays, and for what

*Pricing and market figures here are hypotheses to validate with design partners, not measured facts.*

## The problem
Network and security teams run fleets of routers, firewalls and switches from several vendors (Cisco, Juniper,
Fortinet, Palo Alto, Arista). Auditors ask them to prove the configurations meet CIS / NIST / STIG / ISO 27001 /
CERT-In controls. Today that is done by hand or with per-vendor tools, in spreadsheets, a few times a year:

* a manual review of one device takes hours, so fleets are sampled, not covered;
* findings are generic ("enable logging") with no vendor-specific fix, so remediation stalls;
* evidence for the auditor is rebuilt by hand every cycle;
* configuration drift between audits goes unnoticed;
* vulnerable OS versions and quantum-vulnerable crypto are tracked separately, if at all.

## What this product does about it
Upload (or bulk-upload) a device configuration -> vendor and platform are detected -> the configuration is audited
against the selected frameworks -> the result states what is *observed*, what is an *assumed platform default* and what
could *not be assessed* -> CVE exposure, post-quantum readiness and attack-path analytics are added -> vendor-specific
fix commands with impact, prerequisites and rollback are generated -> an evidence report is produced for the auditor,
with formal risk acceptance and sign-off. Re-audits run on a schedule; drift and new critical findings raise webhooks.

## Who buys it, and why
| Buyer | Pain | What they pay for |
|---|---|---|
| Compliance / GRC lead (regulated: banks, telcos, government, healthcare) | Audit evidence each cycle; auditors want per-control proof | Evidence packs, sign-off trail, framework coverage |
| Network security manager | Cannot review every device; fixes are vendor-specific | Whole-fleet coverage, prioritised findings, copy-ready fixes |
| MSSP / consultancy | Repeated audits for many clients | Multi-tenant, branded reports, bulk onboarding |
| CISO | Board asks "are we hardened, and quantum-ready?" | Fleet posture score, trend, PQC roadmap |

## Why it can win (and why it might not)
* **Strengths:** read-only (no device credentials needed), multi-vendor in one tool, honest coverage reporting
  (no inflated scores from guessed defaults), fix guidance, built-in audit workflow, self-hostable with data kept in the
  customer's database (configurations encrypted at rest), PQC readiness view.
* **Competition:** vendor-neutral compliance tools (Tenable, Qualys, Nipper, Batfish, RedSeal, Forescout) are mature and
  trusted. The wedge is price, simplicity, self-hosting and evidence workflow for mid-market and regional buyers.
* **Honest weaknesses today:** parsers are validated on authored samples, not yet on large real-world corpora; fix
  templates are documented, not lab-verified; control catalogues are a subset; no live device collection and no SSO.
  These determine whether a pilot succeeds - see `REMAINING_WORK.md`.

## Pricing hypotheses (to test with 3 design partners)
* **Per-device annual subscription** (the natural unit for network teams): roughly USD 20-60 per device per year at
  volume, with a floor of ~USD 3-5k per year per organisation. Fleets of 200-2,000 devices land at USD 6-60k per year.
* **MSSP tier:** multi-tenant and white-label, priced per managed client (e.g. USD 150-400 per client per month).
* **Services attach:** onboarding, custom control packs, and lab-verification of fix templates for the customer's
  exact OS versions are the premium differentiator and are sold as one-off work.
* **Free tier / pilot:** up to ~10 devices to remove adoption friction.

Value check for a buyer: one manual device review is ~2-4 hours; at 200 devices audited twice a year that is
800-1,600 engineer-hours. Even at a conservative loaded cost this exceeds the subscription several times over, before
counting avoided audit findings.

## What proves the product (success metrics for a pilot)
1. Parse accuracy on the customer's real configs: >= 95% of device lines understood, zero false "compliant" on a seeded
   set of known-bad settings.
2. Time to first result for a new user: under 5 minutes, unaided (the Quick-audit flow).
3. Engineer time saved per device vs. the current process: measured, target >= 70%.
4. At least one real finding per fleet that the team did not know about.
5. The auditor accepts the evidence pack without asking for re-work.

## Go-to-market sequence
1. Two or three design partners (regulated mid-market, one MSSP). Free pilot against *their* configs; tune parsers and
   fix templates on what breaks.
2. Publish a vendor-by-vendor coverage statement (what is checked, what is not) - credibility with auditors.
3. Convert pilots to annual contracts; add SSO and live collection in the order the first customers demand them.
