# Integrations: signed webhooks

Push audit results to a SIEM, chat channel or ticketing gateway instead of polling. Admin-only
(`/api/v1/integrations/webhooks`, UI: **Integrations**). Code: `app/core/webhooks.py`, `app/services/events.py`,
`app/core/urlcheck.py`. Tests: `backend/tests/test_webhooks.py`. Migration 008.

## Events
| Event | When |
|---|---|
| `audit.completed` | any audit finished (manual, batch or scheduled) |
| `finding.new_critical_high` | the run introduced new CRITICAL/HIGH findings versus the previous run of the asset |
| `job.failed` | an audit/report job failed permanently |
| `ping` | the "Send test" button |

Payload (`format=json`): `{"id","event","created_at","org_id","data":{...}}` - summaries and ids only
(score, coverage, counts, changes, asset name). **Never** configuration text, evidence lines or secrets.
`format=slack|teams` send a one-line human message instead.

Further formats (same HMAC signature headers, same SSRF checks, same summaries-and-ids-only rule):

- `cef` - one ArcSight/Splunk-style CEF line as `text/plain` (`CEF:0|NSCA|...|<event>|<name>|<0-10>|k=v ...`);
  header fields escape `\` and `|`, extension values escape `\`, `=` and newlines so a value cannot forge fields or events.
- `jira` - body for `POST <jira>/rest/api/2/issue` (`fields.project.key` from `WEBHOOK_JIRA_PROJECT`, issue type from
  `WEBHOOK_JIRA_ISSUE_TYPE`).
- `servicenow` - body for `POST <instance>/api/now/table/incident` (`short_description`, `description`, `urgency`/`impact`).
- Optional `auth_header` (`"Authorization: Basic ..."`, `"X-Api-Key: ..."`) is sent to the receiver. It is encrypted at rest
  (`webhooks.auth_header_enc`, migration 013), never returned by the API (only `has_auth_header`) and never logged.
  `PATCH` with `auth_header: ""` clears it.
- Not built yet: RFC 5424 syslog over TCP/TLS.

## Report endpoints (P2-5)
`GET /reports/fleet?format=json|csv|pdf`, `GET /reports/evidence/{audit_id}?framework=CIS&format=csv|json`,
`POST /reports/{id}/signoff` (APPROVER) and `GET /reports/{id}/signoffs`. White-label PDFs: `REPORT_BRAND_NAME`, `REPORT_BRAND_FOOTER`.

## Verifying a delivery (receiver side)
```
X-Timestamp:     <unix seconds>
X-Signature-256: sha256=<hex HMAC-SHA256(secret, timestamp + "." + raw_body)>
X-Event / X-Delivery-Id
```
Compute the HMAC over the **raw** body bytes, compare in constant time, and reject timestamps older than ~5 minutes
(replay protection). The secret (`whsec_...`) is shown once at creation / rotation and stored encrypted.

## Reliability
* Deliveries run as `webhook` jobs on the Postgres queue: 2xx = success; 5xx/408/425/429/network errors retry with
  exponential backoff (up to 5 attempts); other 4xx fail permanently (a retry cannot fix them). Redirects are not followed.
* Every attempt is logged (`GET .../deliveries`). After `WEBHOOK_DISABLE_AFTER` (20) consecutive failures the hook is
  disabled with a visible reason; re-enabling clears it.
* A failing webhook never creates further events (no feedback loops); a notification failure never fails an audit.

## SSRF policy (the URL is chosen by a tenant admin)
Always refused: loopback, link-local (including the 169.254.169.254 cloud metadata address), multicast, unspecified,
reserved, IPv4-mapped forms of those, credentials in the URL, non-http(s) schemes. RFC1918 private networks are refused
unless `WEBHOOK_ALLOW_PRIVATE=true` (needed for an internal SIEM). Plain `http` is refused in production unless
`WEBHOOK_ALLOW_HTTP=true`. The check runs on save **and again before every delivery**.
Known limit: DNS rebinding between the check and the connection - keep egress firewall rules on worker hosts as the
authoritative control.

## Not built yet
Ticketing connectors (Jira / ServiceNow), SIEM-native formats (CEF/syslog), per-asset / per-severity routing rules,
and delivery for the training/remediation approval events.
