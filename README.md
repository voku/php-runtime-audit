# PHP Runtime Audit

**Find out which PHP code is *actually* running on your server — not what the package manager says is installed.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%3E%3D8.2-8892BF.svg)](composer.json)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%20max-brightgreen.svg)](composer.json)
[![Code style](https://img.shields.io/badge/code%20style-PER--CS-blue.svg)](composer.json)

> **Status:** early, local-first CLI. It gathers real Linux PHP runtime evidence and evaluates it against a versioned PHP2Shell advisory pack. When the running SAPI, package provenance, or configuration can't be established with confidence, the tool says `unknown` — it never guesses.

A patched `php -v` or a 200 OK from a health-check endpoint tells you nothing about which binary is actually loaded into the Apache or FPM process serving traffic right now. **PHP Runtime Audit** closes that gap: it inspects the live `/proc` state of your PHP workers, cross-checks it against your distro's package database, and gives you an evidence-backed verdict instead of a guess.

## Why

- **Evidence over assumptions.** Verdicts are backed by cited facts (process identity, loaded binary, dpkg/rpm/apk package records, source digests) — never by a version string alone.
- **Runs where your code runs.** 100% local. No network calls, no telemetry, no uploading your server's data anywhere.
- **Fail-closed by design.** Can't verify something? It stays `unknown`. A tool that quietly guesses "probably fine" is worse than no tool at all.
- **No active exploitation.** Read-only collection. No payloads, no intrusive production tests, no automatic remediation.
- **Built for humans *and* agents.** Produces machine-readable evidence and reviewable, step-by-step remediation plans — every proposed action still requires explicit human approval.
- **Extensible by design.** Advisories live in a versioned, data-driven catalog (`resources/advisories/`), not hardcoded to a single CVE.

See [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) for the full roadmap and delivery gates.

## Quick start

```bash
composer install --no-dev --no-interaction --prefer-dist

# Collect evidence from the running host (read-only, no network access)
php bin/php-runtime-audit-inventory > runtime-report.json

# Turn that report into a reviewable, human-approved remediation plan
php bin/php-runtime-audit-inventory | php bin/php-runtime-audit-report --report REPORT.md > remediation-plan.json
```

Run it as the account that can read the system's process and package information (root or a user with equivalent `/proc` and package-database read access). Nothing is written to disk, no packages are changed, and no service is restarted.

### Use a prebuilt PHAR

Each successful [Build PHAR workflow](https://github.com/voku/php-runtime-audit/actions/workflows/build-phar.yml) run uploads a self-contained `php-runtime-audit.phar` and its SHA-256 checksum. Choose a successful run for `main` and download its artifact using the run ID and commit SHA shown by GitHub Actions:

```bash
gh run download RUN_ID \
  --repo voku/php-runtime-audit \
  --name php-runtime-audit-phar-COMMIT_SHA \
  --dir php-runtime-audit-phar
cd php-runtime-audit-phar
sha256sum --check php-runtime-audit.phar.sha256
```

The artifact is retained for 30 days. To get a newer build, download the artifact from a later successful `main` run. The PHAR supports the same PHP 8.2+ runtime as the source install:

```bash
# Collect evidence from the running host
php php-runtime-audit.phar inventory > runtime-report.json

# Generate a reviewable remediation plan
php php-runtime-audit.phar inventory \
  | php php-runtime-audit.phar report --report REPORT.md \
  > remediation-plan.json
```

The PHAR also provides `evidence` and `profile` commands. Use `php php-runtime-audit.phar --help` to list the available commands. Inventory is the default when no command is given.

## The toolkit

| Command | What it does |
|---|---|
| `bin/php-runtime-audit-inventory` | Collects local runtime evidence (process identity, loaded binary, package provenance, relevant `.ini` settings) and evaluates it against the advisory catalog. Prints a versioned JSON report. |
| `bin/php-runtime-audit-report` | Turns an inventory report into a reviewable remediation plan: machine-readable JSON plus a human-readable `REPORT.md`. Pure transformation — no new evidence is collected. |
| `bin/php-runtime-audit-evidence` | Validates a standalone evidence record (observation, applicability, assessment, coverage, or finding) against the versioned JSON Schema. |
| `bin/php-runtime-audit` | Guidance-mode profile selector for coding agents: given an intent (`runtime-patch`, `configuration`, `incident-triage`, `source-review`) and known facts, returns which bounded audit profile to read next. It never issues a verdict itself. |

## What it checks today

This version covers Linux process/package inventory for **CLI**, **PHP-FPM**, and **Apache `mod_php`** workers, evaluated against the PHP2Shell advisory pack: `CVE-2026-109618`, `CVE-2026-109619`, and `CVE-2026-115560`. It is not a general security certification — review the evidence and source revisions before making operational decisions.

Every assessment resolves to one of four verdicts:

| Verdict | Meaning |
|---|---|
| `verified_fixed` | The loaded binary, not just an installed package, is cryptographically matched against the distro's package-integrity record. |
| `potentially_affected` | Evidence indicates the running code predates the fix. |
| `needs_investigation` | A suspicious configuration or ambiguous signal needs a human look — this never implies a fix or a compromise. |
| `unknown` | Evidence is missing, conflicting, or insufficient. This is the honest default, not a failure state. |

A fixed *installed* package never implies a fixed *running* worker on its own — an Apache or FPM process can keep an old binary mapped in memory long after `apt upgrade`. For Debian/Ubuntu, the tool additionally fingerprints the loaded executable (or, for an unversioned `libphp.so` Apache module, the one package whose own manifest claims that exact file) and compares it against the local package database's own integrity record. This trusts the local package database — it does not independently authenticate a compromised host. RPM/APK loaded-binary integrity isn't established yet, so an exact package version alone stays `unknown` there.

Compromise evidence is always reported separately from patch status: a `verified_fixed` result never claims the host was never compromised.

## Generate a reviewable remediation plan

```bash
php bin/php-runtime-audit-inventory | php bin/php-runtime-audit-report --report REPORT.md > remediation-plan.json
```

Every proposal states its own prerequisites, risk, rollback, and verification steps. `requires_human_approval` is hardcoded `true` and cannot be set otherwise — no proposal, however confident, applies itself. A `verified_fixed` verdict that cites no evidence actually present in the report is flagged rather than trusted. The input report is treated as untrusted: malformed or unresolvable records are skipped and recorded as warnings, never guessed at, and all generated text is bounded and stripped of control characters before it reaches the Markdown report.

## Validate a standalone evidence record

```bash
php bin/php-runtime-audit-evidence validate tests/fixtures/evidence/v1/observation.valid.json
```

The validator accepts only a local file path (no URLs, no UNC paths), reads at most 1 MiB, rejects duplicate JSON keys, and never resolves source locators contained in the record itself. Source freshness is derived only from digests already present in the JSON — missing digest evidence stays `unknown`. Schema version `1.0` lives under `resources/schemas/evidence/v1/`; unknown record types and schema versions fail closed.

## Security model

- Never trust `php -v`, response headers, or an HTTP 200 as proof of a patched web-facing runtime.
- No shell interpolation from remote or user-controlled input — subprocess commands are fixed, allowlisted argv with bounded output and timeouts.
- Subprocess probes require an observed loopback-only network namespace with restricted capabilities, or fail closed with their facts left `unknown`.
- Generated instructions and collected logs are treated as untrusted data throughout the pipeline.
- No credentials are ever collected, stored, or required.

Found a security issue in this tool itself? See [`SECURITY.md`](SECURITY.md) — please don't open a public issue for it.

## Delivery milestones

The **Local MVP** requires independently verified runtime/patch evidence and reviewable remediation instructions. The **Public MVP** adds documentation and reproducible, security-reviewed download bundles. Source analysis and incident forensics are separate follow-up slices. See [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) for current gates — this checkout does not claim a completed public release.

## Testing against real disposable PHP workers

The unit/integration suite runs against offline fixtures, but you can also exercise the collector against real, disposable Docker containers (Docker and the dev dependencies above are required):

```bash
bash tests/fixtures/runtime/run-disposable-runtime-checks.sh
```

The harness uses pinned FPM/Apache images without network access or published ports during collection, and removes only its own fixtures afterward. Initial image acquisition may need network access. It does not execute exploits.

## Contributing

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the local dev setup, test/lint commands, and PR expectations. Please read [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) first.

This repository additionally uses [`voku/agent-loop`](https://github.com/voku/agent-loop) as a governed development-lifecycle tool for maintainers and coding agents. That workflow is optional tooling, not a requirement for sending a plain pull request — see [`AGENTS.md`](AGENTS.md) if you're curious or are an AI agent working in this repo.

## License

MIT — see [`LICENSE`](LICENSE).
