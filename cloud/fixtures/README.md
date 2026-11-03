# cloud/fixtures - real cloud files used as regression fixtures

Deliberately misconfigured (`vuln/`), hardened (`secure/`) and unresolvable (`unknown/`) cloud files. They are scanned
by `tests/test_fixture_corpus.py`. Nothing here is deployable; the credentials in tests are assembled at runtime.

| File | Proves |
|---|---|
| `vuln/netpol-nsselector.yaml` | allow-all NetworkPolicy via `namespaceSelector: {}` fails `CLOUD-K8S-008` |
| `secure/netpol-port-scoped.yaml` | a port-scoped policy is not "all traffic" and must stay clean |
| `vuln/cloud-init-passwd.yaml` | clear-text `users[].passwd` fails `CLOUD-INIT-002` |
| `secure/main.tf` | `http_tokens = "required"` is not a hard-coded secret (no `CLOUD-SEC-001`) |
| `unknown/volume.tf` | an unresolvable value is `UNKNOWN_STATIC`, never PASS |
