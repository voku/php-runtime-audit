# Security Policy

PHP Runtime Audit is a security-focused tool, so we take vulnerabilities in it itself seriously — including in its advisory catalog, its remediation-plan generator, and the collector's handling of hostile or malformed local input.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Instead, use [GitHub's private vulnerability reporting](https://github.com/voku/php-runtime-audit/security/advisories/new) for this repository. This opens a private advisory visible only to the maintainers until a fix is ready.

Please include:

- The affected version/commit.
- A minimal reproduction (ideally a fixture or input, not a live production host).
- The impact you believe the issue has — e.g. a fail-open condition where the tool should report `unknown` but instead reports `verified_fixed`, a path where untrusted input reaches a shell command, or a way for generated output (JSON report or `REPORT.md`) to leak unintended local data.

## Scope

In scope:

- The collector, evaluator, and remediation-plan generator (`src/`, `bin/`).
- The bundled advisory catalog and JSON Schemas (`resources/`).
- Anything that could turn untrusted local evidence (a crafted `/proc` entry, package-database file, or evidence JSON record) into unintended behavior — command injection, path traversal, a false `verified_fixed`/`none_observed` verdict, or unintended remote network access.

Out of scope:

- The PHP vulnerabilities this tool is designed to *detect* (e.g. the PHP2Shell CVEs) — report those to the PHP project or your distribution, not here.
- Findings that require the attacker to already have write access to the audited host's package database or `/proc`, since this tool's documented trust boundary is the local package database, not independent vendor signing (see the `RuntimePackageProvenance` class docblock).

## Our commitment

We'll acknowledge a report within a few days and aim to ship a fix (or an explanation of why the behavior is intended, given the trust boundary above) before any public disclosure.
