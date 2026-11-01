# Pilot kit: 30 days with a design partner

A pilot is the only thing that turns "built" into "valuable". This kit makes it cheap to start, safe for the customer, and
measurable. Nothing here can be completed by writing more code - it needs a customer - but every tool it uses exists.

## 1. Who and what
* **Partners (2-3):** one regulated mid-market network team (bank / telco / hospital / government body), one MSSP or
  consultancy that audits for several clients. Ask for 20-50 devices across at least two vendors.
* **Offer:** free 30-day pilot, self-hosted in their environment (or ours with anonymised data), a named engineer from us
  on a weekly call. In exchange: real configurations (anonymised is fine), honest feedback, and a reference call if it works.

## 2. Data handling (put this in the first e-mail)
* Configurations never need to leave their network: deploy with Docker Compose on their host, database in their account.
* If they prefer to send samples, they run the anonymiser **on their machine** first:
  `python -m app.cli anonymize router1.cfg router1.anon.cfg --salt "<their secret>" --map router1.map.json`
  It removes secrets, hashes, addresses, host/domain/user names, MACs, e-mails, descriptions and banners, keeps all syntax and
  factory defaults (`admin`, `public`) that audits look for, and writes a private mapping file they keep. Our tests prove
  the eight sample configurations give identical audit verdicts before and after anonymising.
* Live collection is optional and off until an admin adds a read-only account (see `COLLECTION.md`).

## 3. Timeline
| Week | Activity | Output |
|---|---|---|
| 0 | NDA/terms, install, create the org, SSO or local admins with MFA | running system |
| 1 | Upload / collect 10-20 devices; run the first audits; walkthrough of results | first report |
| 2 | Customer marks 5-10 settings per vendor they KNOW are wrong (seeded checks); we run `corpus-eval`; we fix parser/rule gaps | accuracy numbers |
| 3 | Remediation: customer applies 3-5 fixes in a maintenance window or lab; record before/after/rollback configs and verify them (`remediation-verifications`) | lab-verified fixes |
| 4 | Evidence pack for their next audit; webhook/ticket integration; scheduled re-audits; success review | decision |

## 4. Success metrics (measured, not argued)
Run `python -m app.cli corpus-eval <dir> --md pilot_report.md` on the anonymised or in-place configs with sidecars
`<file>.expect.json` (`{"vendor": "cisco", "must_fail": ["<control id>", ...]}`):

| Metric | Bar | How it is measured |
|---|---|---|
| Lines understood | >= 95 % overall | `corpus-eval` summary |
| False "compliant" on seeded known-bad settings | **0** | `corpus-eval` (`false_compliant_total`) |
| Vendor detection | 100 % on their fleet | `corpus-eval` (labelled files) |
| Time to first result for a new engineer | < 5 minutes unaided | observe one person; use the Get-started page |
| Engineer time saved per device vs. today | >= 70 % | their before/after estimate for 5 devices |
| At least one real finding they did not know about | >= 1 | customer confirms |
| Evidence pack accepted by their auditor without re-work | yes | customer confirms |
| Fixes lab-verified | >= 3 | `GET /api/v1/remediation-verifications` |

`corpus-eval` exits with status 2 when the bar is not met, so it can gate a CI job.

## 5. Questions to ask every week
1. Which finding was wrong or noisy? (record the config line and control id; each becomes a test)
2. Which control did you expect that we did not have? (feeds `catalogue-import` + mappings)
3. What did you do outside the tool to finish the job? (the next feature)
4. Who else needs to see this, and in what format? (reports, tickets, SIEM)
5. Would you pay for it, how much, and what would you stop paying for? (see `PRODUCT_BRIEF.md` pricing hypotheses)

## 6. Exit decision
Convert to a paid annual plan only if the bars in section 4 are met **and** the customer names a budget owner. If the
accuracy bars are not met, the output of the pilot is a prioritised parser/rule backlog - still a success if it is
specific.
