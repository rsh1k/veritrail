# Security Policy

## Reporting a vulnerability

Please report security issues privately. **Do not open a public GitHub issue
for a suspected vulnerability.**

Use GitHub's private vulnerability reporting (the **Security → Report a
vulnerability** tab on the repository), which opens a confidential advisory
visible only to the maintainers.

When reporting, please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal proof of concept is ideal),
- affected version(s) or commit, and
- any suggested remediation if you have one.

We aim to acknowledge a report within a few days and to agree on a disclosure
timeline with you. We follow coordinated disclosure: we ask that you give us a
reasonable window to ship a fix before any public disclosure, and we are happy
to credit you in the release notes unless you prefer otherwise.

## Supported versions

Veritrail is pre-1.0 and moves quickly. Security fixes are made against the
latest released minor version. Please upgrade to the latest release before
reporting, in case the issue is already fixed.

## Scope and honest limitations

Veritrail is an open-source **reference implementation** of agent action
provenance and forensics. It has not undergone an independent third-party
security audit. Before relying on it for a regulated production workload,
review the "Production hardening" section of the README and commission your own
cryptographic and application-security review.

The cryptography relies on well-established primitives (Ed25519, SHA-256) via
the `cryptography` library. Reports about the *design* of the provenance,
attenuation, ledger, revocation, or detection logic are especially welcome,
as are reports about the REST service surface.
