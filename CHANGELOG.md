# Changelog

All notable changes to Veritrail are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses semantic
versioning.

## [0.3.0]

### Added
- **PostgreSQL backend** for shared, concurrent-safe, multi-replica deployments
  (`PostgresStore`), alongside the existing SQLite backend. Selected via a URL
  through the new `open_store()` factory and the `VERITRAIL_DB` environment
  variable (`postgresql://...` or `sqlite:///...`).
- **Coordinated, append-only ledger.** Ledger appends are serialized — across
  every replica in the Postgres case via a transaction-scoped advisory lock — so
  the tamper-evident hash chain stays linear and verifiable under concurrency.
- **Read-through lookups.** One replica resolves delegations, actions, and
  principals written by another, so authorization decisions are globally
  correct rather than per-process.
- `Ledger.append_prebuilt()` and `Ledger.verify_against_head()` for
  store-coordinated entries and external-witness truncation detection.
- `[postgres]` optional dependency extra; the published Docker image now
  installs it so it supports both backends.
- `SECURITY.md`, `CONTRIBUTING.md`, and this changelog.

### Notes
- The deterministic authorization checks (signature, chain, scope, expiry,
  revocation, ledger integrity) are globally correct across replicas. The
  behavioral heuristics (consent fatigue, fan-out) use a per-replica recent
  view and are best-effort across replicas — see the README.

## [0.2.3]

### Fixed
- A backslash inside an f-string expression in `forensics.py` caused a
  `SyntaxError` on Python 3.10 and 3.11 (it was only valid on 3.12+). The CI
  matrix now passes on all supported versions.

## [0.2.2]

### Changed
- Hardened the REST API: typed domain errors raised at the source, global
  exception handlers that never leak stack traces, security headers on every
  response (including errors), a relaxed CSP scoped only to the docs routes so
  Swagger renders, bounded-memory rate limiting, and optional trusted-host and
  docs-disable controls.

### Fixed
- Malformed input (e.g. an invalid public key) returned a 500 with a stack
  trace; it now returns a clean 422.

## [0.2.0]

### Added
- Initial release: cryptographic delegation provenance with attenuation,
  tamper-evident hash-chained ledger, OWASP ASI-mapped hijack detection,
  revocation, forensic HTML reports, SDK, REST API, CLI, Docker deployment, and
  a property-based test suite.
