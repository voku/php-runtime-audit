# Contributing to PHP Runtime Audit

Thanks for considering a contribution. This is a security-focused tool, so correctness and conservative defaults matter more than speed of delivery — a fail-closed `unknown` is always preferable to a wrong `verified_fixed`.

Please read the [Code of Conduct](CODE_OF_CONDUCT.md) before participating. If you've found a security vulnerability in this tool itself, see [`SECURITY.md`](SECURITY.md) instead of opening a public issue.

## Local setup

```bash
git clone https://github.com/voku/php-runtime-audit.git
cd php-runtime-audit
composer install
```

Requires PHP 8.2+ and Composer.

## Before opening a pull request

Run the full local check suite — all of these also run in CI, so catching problems locally saves a review round:

```bash
composer test            # PHPUnit, with warnings treated as failures
composer analyse          # PHPStan at --level=max
composer format-check     # PHP-CS-Fixer, @PER-CS rules, dry-run
```

For changes touching the real-worker collector, you can also exercise it against disposable Docker containers (requires Docker):

```bash
bash tests/fixtures/runtime/run-disposable-runtime-checks.sh
```

## What a good pull request looks like

- **Tests for both the happy path and hostile/missing input.** Every collector and evaluator change in this codebase ships with fixtures for the realistic failure modes (ambiguous evidence, replaced binaries, truncated/symlinked metadata, unsupported distros) — not just the clean case. Look at `tests/RuntimeInventory/RuntimePackageProvenanceTest.php` for the expected depth.
- **No new shell interpolation.** Subprocess commands must stay fixed, allowlisted argv with bounded output and timeouts — never built from untrusted strings.
- **No automatic remediation.** Nothing in this codebase restarts a service, changes a package, or applies a fix on its own. Remediation proposals always require `requires_human_approval: true`.
- **Fail-closed on uncertainty.** If evidence is missing, ambiguous, or conflicting, the result should be `unknown` (or `needs_investigation` for configuration risk), never a guessed `verified_fixed`.
- **New advisories are data, not code forks.** The advisory catalog under `resources/advisories/` is versioned and data-driven — avoid hardcoding a new CVE's logic directly into the evaluator when it can instead be expressed as catalog data.
- **A focused diff.** Keep unrelated refactors out of a bug-fix or feature PR; it makes review (and bisecting a future regression) much easier.

## Code style

- `declare(strict_types=1)` everywhere.
- PHPStan at `--level=max` must pass with no suppressions. If you need an inline `@var` cast after narrowing, make sure it's actually safe (document why if it's not obvious).
- Formatting follows `@PER-CS` via PHP-CS-Fixer — run `composer format-check` (or `php-cs-fixer fix` without `--dry-run` to auto-apply).

## Governed workflow (optional, for maintainers and coding agents)

This repository also uses [`voku/agent-loop`](https://github.com/voku/agent-loop) as an optional, governed development-lifecycle layer — task contracts, structured review, and durable learning notes. It is **not** required to send a plain pull request as described above. If you're an AI coding agent working in this repo, see [`AGENTS.md`](AGENTS.md) for the router into that workflow.

## Reporting bugs and requesting features

Please use the [issue templates](.github/ISSUE_TEMPLATE) so we get the information we need (PHP version, SAPI, distro, and — for a suspected false verdict — the relevant `runtime-report.json` excerpt) without a back-and-forth.
