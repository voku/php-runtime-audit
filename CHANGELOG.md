# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

There are no tagged releases yet — the project is still on its way to the
Local MVP (see [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)
for current delivery gates). Entries below track notable merges to `main`.

## [Unreleased]

### Added

- Reverse dpkg lookup (`RuntimePackageProvenance::checkApacheModule()`) that identifies an Apache `mod_php` module's package even when the loaded `.so` filename carries no version, by checking which installed `libapache2-mod-php*` package's own manifest claims the exact loaded path (#11).
- PRA-5: reviewable, human-approved remediation plans generated from a runtime audit report (`bin/php-runtime-audit-report`), plus a human-readable `REPORT.md` (#10).
- Real, disposable Docker-based PHP 8.5 FPM and Apache worker coverage in CI, alongside the existing 8.2/8.4 pair (#9).
- Side-by-side multi-runtime (CLI + web worker) inventory and PHP-FPM/Apache worker package provenance (#7).
- PRA-3: versioned evidence records (observation, applicability, assessment, coverage, finding) with JSON Schema validation (`bin/php-runtime-audit-evidence`).
- PRA-2: guidance-mode audit-profile selector for coding agents (`bin/php-runtime-audit`).
- PRA-1: initial local runtime/patch inventory and PHP2Shell advisory evaluation (`bin/php-runtime-audit-inventory`).

### Fixed

- Apache worker package-provenance lookups are now cached per module path, so many worker processes sharing one module file don't redundantly re-hash it against the shared integrity-check budget (#11).
