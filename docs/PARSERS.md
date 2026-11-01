# Structured vendor parsers

How a raw device configuration becomes the canonical properties the compliance, analytics and PQC engines
evaluate. Code: `okf/src/vendor_parsers/`. Tests: `backend/tests/test_vendor_parsers.py`,
`backend/tests/test_e2e_vendors.py`. Corpus: `okf/tests/corpus/`.

## Pipeline

```
upload ─► fingerprint (structural markers, deterministic)  ──┐
          M1 model (statistical)  ───────────────────────────┴─► vendor + platform + version
       ─► structured parser for that vendor  ─► facts{property: value, line, basis, note} + N/A set
       ─► registry regex mappings (gap-fill)   (human-approved mappings override the parser)
       ─► unknown lines  ─► training queue / AI suggestion (human approves)
       ─► compliance engine ─► verdict per control: PASS / FAIL / UNKNOWN / NOT_APPLICABLE + coverage
```

Precedence for a property: **human-approved mapping > structured parser > curated regex > AI suggestion.**

## What a fact is

| Field | Meaning |
|---|---|
| `value` | the canonical value (e.g. `TELNET.ENABLED = true`) |
| `basis = config` | read from an actual line; `line_no` + `line` give the evidence |
| `basis = default` | the line is absent and the documented platform default decides (e.g. Junos has no telnet unless `system services telnet`); carries a `note`, confidence 0.6 |
| *(absent)* | not determinable from this config -> the control is **UNKNOWN / not assessed**, never PASS |
| `not_applicable` | the property cannot exist on this platform/role (e.g. `service pad` on FortiOS, STP guards on a router); controls whose every property is N/A leave the score |

Every audit reports **assessment coverage** (`assessed / applicable`), how many verdicts are `assumed`, how many
were `not assessed`, and how many controls are N/A. The PDF, the results page and every finding show this.

## Supported syntaxes

| Vendor | Platforms | Formats |
|---|---|---|
| Cisco | IOS, IOS-XE, NX-OS | running-config (blocks, banners, certificates, `no` negation, per-interface rules) |
| Arista | EOS | running-config incl. `management ssh/telnet/api`, EOS banners |
| Juniper | Junos (EX/QFX/MX/SRX) | hierarchical `{}` **and** `set` format; `inactive:` / `deactivate` honoured; `## SECRET-DATA` markers |
| Fortinet | FortiOS | `config / edit / set / next / end` incl. nested blocks |
| Palo Alto | PAN-OS | `set` format, hierarchical CLI, **XML** snapshots (with real line numbers) |

## Capability matrix (measured on the corpus; 66 properties are used by the 82 controls)

| Platform | Read from config | Default-based only | N/A | Not determinable |
|---|---|---|---|---|
| Cisco IOS / IOS-XE | 56 | 5 | 3 | 2 |
| Cisco NX-OS | 35 | 19 | 6 | 6 |
| Arista EOS | 36 | 17 | 6 | 7 |
| Juniper Junos | 50 | 8 | 7 | 1 |
| Fortinet FortiOS | 34 | 11 | 14 | 7 |
| Palo Alto PAN-OS | 31 | 13 | 14 | 8 |

"Read from config" = determined from a configuration line for at least one corpus file; some depend on the feature
being present (e.g. IKE version needs an IPsec tunnel). Not determinable today:

* IOS-XE: `CRYPTO.IKE_VERSION`, `CRYPTO.RSA_KEY_SIZE` (key sizes are not in a running-config)
* NX-OS: SSH cipher/MAC/timeout settings, OSPF auth
* EOS: console security, redirects/proxy-ARP, BGP auth, SSH retries
* FortiOS / PAN-OS: AAA accounting, console, NTP source, SSH MAC/timeout, uRPF, (PAN) SNMP ACL

## Measured effect on the authored corpus (before = registry only, after = structured parsers)

| Config | Controls assessed before -> after (of ~75 applicable) | Score before -> after |
|---|---|---|
| Arista EOS leaf | 0 -> 72 | 0 -> 76 |
| Cisco IOS-XE hardened | 48 -> 79 | 58 -> 97.5 |
| Cisco IOS-XE insecure branch | 31 -> 78 | 32 -> 33 |
| Cisco NX-OS | 13 -> 72 | 12 -> 43 |
| FortiOS edge | 0 -> 66 | 0 -> 49 |
| Junos EX | 0 -> 74 | 0 -> 69 |
| Junos SRX | 12 -> 74 | 6 -> 65 |
| PAN-OS | 0 -> 65 | 0 -> 60 |

## Honest limitations

1. **The corpus is authored, not captured.** Configs were written from vendor documentation and expectations were
   verified line by line, but real customer devices contain syntax these parsers have never seen. Accuracy on real
   data is **unmeasured** - collect and label real configs (gap register P1-2) before quoting accuracy.
2. **Defaults are encoded from documentation and can differ by software release** (e.g. SSH defaults, IOS vty
   transport). They are labelled `assumed default`; confirm on the device when a verdict matters.
3. Running-config only: runtime state, certificates in flash, AAA server behaviour, and anything configured out of
   band are invisible.
4. Panorama templates/device-groups, Junos `groups`/`apply-groups` inheritance, FortiOS multi-VDOM and Cisco
   `vrf`-scoped settings are only partly modelled.
5. Weak-crypto detection is keyword/value based (DES/3DES/MD5/SHA-1/DH group 1,2,5/old TLS/type 4-5 secrets);
   it does not evaluate negotiated algorithms.

## Adding a platform
1. Add a module in `okf/src/vendor_parsers/` returning a `ParseResult` via `Facts` (`put` for observed values,
   `default` only for documented defaults with a note, `na` for non-existent properties).
2. Register it in `__init__.parse` and add structural markers to `fingerprint.py`.
3. Add a corpus config + hand-verified expectations in `backend/tests/test_vendor_parsers.py`. The suite also fuzzes
   every parser with malformed input: a parser must never raise and a failing extractor is reported as
   "degraded", never swallowed.
