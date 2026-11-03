# Changelog

All notable changes to Orbit - Multi-Vendor Security are recorded here.
This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and semantic versioning for the documented API surface.

## [Unreleased] - 2026-11-03

### Fixed

- Cloud: allow-all NetworkPolicy written with `namespaceSelector: {}` (CLOUD-K8S-008) and clear-text cloud-init
  `users[].passwd` (CLOUD-INIT-002) are now detected; hashed passwords and port-scoped policies stay clean.
- Cloud secret scan: no more false `CLOUD-SEC-001` on `http_tokens`, token-setting keys (`*_token_ttl`, `*_audience`)
  and crypt hashes.
- Cloud: platforms recognised without rules (VMware, Nutanix) are reported under `coverage.not_assessed`.
- okf-cloud manifest/README and the cloud RTM corrected; `okf` gateway tests no longer need a real API key.
- Frontend: `npm audit` clean, Playwright dependency and `test:e2e` script added.

### Added

- CI job running the cloud test-suite (100 % coverage gate); `cloud/fixtures/` regression corpus.
- `docs/ORBIT_VERIFICATION_FIXES.md`.

## [Unreleased] - 2026-11-01

### Changed

- Repository moved to
  [Qirova-Technologies/Orbit-Multi-Vendor-Security](https://github.com/Qirova-Technologies/Orbit-Multi-Vendor-Security).
  The original SIH submission repository is left untouched.
- Documentation refresh: README, `APPLICATION_SETUP.md`, `FRONTEND_GUIDE.md`,
  `backend/README.md`, `backend/docs/API_REFERENCE.md`,
  `backend/docs/ARCHITECTURE.md` and `backend/docs/BUILD_STATUS.md` now describe
  the current build (106 documented routes / 103 under `/api/v1`, 30 frontend
  page components, 40 routes).
- `docs/product_readiness_gaps.md` progress log updated with the items that have
  since been closed (self-hosted fonts, E2E auth fixtures, scheduling).

### Added

- `.gitignore` hardening for: local agent session transcripts (`session-*.md`),
  `okf/.env`, key material (`.p12`, `.pfx`), Vite/TS build caches,
  `docker-compose.override.yml`, local copies (`* - Copy.*`) and PID files.
- `CHANGELOG.md` documenting the move and the documentation refresh.
- Documentation for the operations surface: live collection, background jobs,
  recurring audits and drift, signed webhooks, risk exceptions, admin/RBAC/MFA/
  SSO and control catalogue import (see `docs/`).

### Notes

- No application code changed in this release; it packages work that was already
  present in the working tree.
- Test and endpoint figures in the docs come from the last full run
  (`pytest --collect-only` and the live OpenAPI schema). Re-run the commands in
  README §16 to confirm on another machine.
