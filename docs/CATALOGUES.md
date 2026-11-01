# Control catalogues: coverage you can state honestly

The product ships a curated set of machine-checkable controls (CIS / NIST / STIG / ISO 27001 / CERT-In mappings). It does
**not** ship the full texts of licensed benchmarks, and must not redistribute them. A customer that holds the licence can
import its own copy; the product then reports the framework's real size, not just the part it can check.

## Rules the importer enforces
* Every imported entry becomes a control. **An entry without a machine-checkable condition evaluates to UNKNOWN** ("could
  not be assessed") and counts against coverage; it can never report PASS.
* A `--license` and a `--source` are mandatory and are stored on every control, so provenance is never lost.
* The output (`okf/knowledge/controls/imported_<framework>.yaml`) is git-ignored because it may contain licensed text.
* XCCDF input is parsed with `defusedxml`; any `DOCTYPE` / `ENTITY` is rejected.

## Formats
* **DISA STIG** XCCDF (the public STIG Viewer download; the STIG data itself is public): `--format xccdf` (auto-detected).
* **CSV** with columns `id,title[,description,severity,category]` - e.g. an export from a CIS SecureSuite benchmark.
* **JSON** `{"controls":[{"id","title","description","severity","category"}]}` or a bare list.

## Commands
```bash
python -m app.cli catalogue-import U_Cisco_IOS-XE_Router_STIG.xml --framework STIG \
    --license "DISA public release" --source "https://public.cyber.mil/stigs/"
python -m app.cli catalogue-coverage          # per framework: entries vs entries with an automated check
```
Add `--dry-run` to see the counts without writing. Restart the API afterwards so the control set is reloaded.

## Turning an entry into an automated check
Write a mapping file: control id -> condition on canonical properties (the vocabulary is `okf/knowledge/properties`):
```yaml
CISC-RT-000010:
  condition: {property: REMOTE_ACCESS.TELNET_ENABLED, operator: EQUALS, value: false}
  severity: HIGH
  applies_to: {vendor: [cisco]}
```
`catalogue-import ... --mapping map.yaml` re-writes the catalogue with those entries switched to automated checks. Review
each mapping like code: a wrong condition is a wrong audit. `docs/product_readiness_gaps.md` P1-5 tracks how many controls
are automated per framework.

## What this does not do
It does not write the conditions for you, and it does not make an unreviewed mapping trustworthy. The honest statement for
a report is "N of M controls assessed automatically, the rest need manual evidence" - which is exactly what the coverage
figure on every audit now says once a catalogue is imported.
