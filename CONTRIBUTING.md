# Contributing to Veritrail

Thanks for your interest in improving Veritrail. Contributions of all kinds are
welcome — bug reports, fixes, tests, docs, and new features.

## Getting set up

```bash
git clone https://github.com/rsh1k/veritrail.git
cd veritrail
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # add ,postgres for the Postgres backend
pytest -q
```

The suite runs on Python 3.10–3.12. Please make sure `pytest -q` passes on at
least 3.10 before opening a pull request — CI tests all three versions.

## Running the Postgres tests

The Postgres integration tests are skipped unless you point them at a database:

```bash
export VERITRAIL_TEST_PG="postgresql://user:pass@localhost:5432/veritrail"
pip install -e ".[dev,postgres]"
pytest tests/test_postgres.py -q
```

## Guidelines

- **Keep the security core honest.** Anything touching `crypto`, `scope`,
  `delegation`, `ledger`, `revocation`, or `engine` should come with tests that
  include the adversarial case, not just the happy path.
- **Raise typed errors** (`VeritrailError` subclasses) at the source rather than
  returning sentinel values or raising raw library exceptions.
- **No secrets in code, logs, or tests.** The server must never accept, store,
  or log private key material.
- **Run the linter.** `python -m pyflakes veritrail tests examples` should be
  clean.
- Add or update tests for any behavior change. The property-based tests in
  `tests/test_fuzz_1000.py` are a good place to encode invariants.

## Pull requests

Keep PRs focused and describe the motivation. If you are changing behavior,
explain the threat model or use case. By contributing you agree that your
contributions are licensed under the project's Apache-2.0 license.

## Reporting security issues

Please do not file public issues for vulnerabilities — see
[SECURITY.md](SECURITY.md) for private reporting.
