# Context-aware remediation

How a failed control becomes a safe, vendor-specific fix plan. Code: `okf/src/remediation_gen.py`. Templates:
`okf/knowledge/remediation/fixes/<vendor>.yaml`. Tests: `backend/tests/test_remediation_gen.py`.

## What it does differently from a static "fix text"

1. **Works out what is actually unmet.** It re-evaluates the control's condition against this audit's own
   canonical IR. For `ALL` conditions only the failing parts get fixes; for `ANY` conditions it picks the **least
   disruptive** alternative (e.g. "move SNMP to v3" before "disable SNMP").
2. **Names the real objects.** Parsers attach the offending objects to each fact (`targets`), so the plan edits
   *that* FortiGate interface (keeping its other `allowaccess` entries), *those* vty lines, *that* BGP neighbour and
   AS number, *that* policy / community / account - not a generic example.
3. **Carries the safety information**: impact, prerequisites ("a second SSH session is open", "your source is
   inside the permitted subnet"), validation commands, rollback (per target), and the **placeholders you must fill**
   (`<SYSLOG_IP>`, `<MGMT_SUBNET>`...) with descriptions.
4. **Is honest about verification.** Every plan says whether it is `documented` or `lab-verified`. All current
   templates are `documented` (written from vendor documentation, **not tested on a device**) and the UI/API say so.
5. **Never leaks across vendors.** A device only receives its own vendor's templates. The previous behaviour of
   falling back to *any* vendor's pack (so a Palo Alto device could be shown Cisco commands) was removed, and
   NX-OS receives no plan rather than IOS syntax.
6. **Never stores secrets.** A non-default SNMP community string is referenced by config line
   (`<COMMUNITY_L119>`), not copied into the stored audit.

## Coverage (controls that could get a plan if they failed)

| Platform | Templates | Controls with a fix | Notes |
|---|---|---|---|
| Cisco IOS / IOS-XE | 66 | 82 / 82 | |
| Juniper Junos | 51 | 67 / 82 | |
| Fortinet FortiOS | 39 | 60 / 82 | many others are N/A on a firewall |
| Arista EOS | 40 | 59 / 82 | |
| Palo Alto PAN-OS | 32 | 49 / 82 | many others are N/A on a firewall |
| Cisco NX-OS | 0 | 0 / 82 | deliberately none until NX-OS syntax is written and reviewed |

Fixes that need a design decision (replace an any/any rule, CoPP policy, IKEv2 migration, default-account
replacement) are marked `manual`: the plan is a starting point and the UI says so.

## Template format

```yaml
fixes:
  TELNET.ENABLED:                 # canonical property the control checks
    title: Disable telnet on the VTY lines
    value: false                  # the compliant value this template achieves
    per_target: true              # repeat once per offending object found in the config
    skip_if_no_targets: false     # (optional) emit nothing when no object was identified
    setup: [...]                  # once, before the per-target commands (e.g. create an ACL)
    commands: ["line {name}", " transport input ssh", " exit"]   # {name}, {asn}, {allowaccess}, {mode} ...
    validation: [...]
    rollback: [...]               # [] when none exists (must be stated)
    impact: "..."                 # required for disruption: high
    prerequisites: [...]
    approval_required: true
    disruption: low | medium | high   # used to choose between ANY alternatives
    includes: [OTHER.PROPERTY]    # compose other fixes (e.g. MGMT.ENCRYPTED_ONLY = telnet + http)
    manual: true                  # needs human judgement
```
`pytest tests/test_remediation_gen.py` enforces: known properties, titles, validation + rollback stated, impact for
high-disruption fixes, every `<PLACEHOLDER>` described, no literal IP addresses, `{name}` only in per-target fixes,
no unknown `includes`.

## Limits
* Syntax differs between software releases; each file says to verify option names (`?`) before committing.
* Fixes cannot know your topology (which uplinks are DHCP-trusted, which peers must change at the same time) - that
  is what *prerequisites* and *impact* are for.
* Lab verification is the next step: set `verification: lab-verified` per vendor file only after the templates have
  been run on a device or emulator (Containerlab / vendor virtual images).
