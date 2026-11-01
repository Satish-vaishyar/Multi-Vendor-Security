# okf-cloud/ - cloud knowledge pack

Cloud counterpart of `../okf/` (properties, mappings, controls, crosswalks, remediation). Kept **separate** on
purpose: the network OKF loader reads every `*.yaml` under `okf/knowledge/*`, so cloud content placed there would be
evaluated against router configs and change existing audit scores. Nothing in `okf/` is edited.

Status: **S01 skeleton, empty.** Content arrives in S12 (`docs/CLOUD_MODULE_RTM.md`).

## Rules carried over from the network OKF
* Deterministic rules decide pass/fail; an LLM never does.
* A control that cannot be evaluated is UNKNOWN, never PASS.
* Every control records its source, version and licence. Mappings to licensed benchmarks stay `unverified` until
  checked against the customer's licensed edition; no invented control IDs.
* Imported licensed catalogue text is git-ignored (`.gitignore` in this folder).
