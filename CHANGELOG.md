# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

There are no tagged releases yet — the project is still on its way to the
Local MVP (see [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)
for current delivery gates). Entries below track notable merges to `main`.

## [Unreleased]

### Added

- Read-only `session.save_handler` and `session.save_path` collection per SAPI, configuration root and FPM pool. Save paths that are not plain filesystem paths (redis/memcached DSNs, URLs) are stored only as a scheme label plus a per-run keyed digest, so stores can be compared without exposing credentials (#38).
- Cross-install session-store correlation for `CVE-2026-115560`: contexts that use different serialization handlers on an explicitly shared store (or the default location within one install), while upload progress is explicitly enabled in at least one of them, raise `needs_investigation`. Configuration-file evidence only; applications can register their own save handler (#38).
- `CVE-2026-126714` configuration exposure follows the configured backend: `files` asks for investigation, anything else stays `unknown`; the verdict remains patch-driven (#38).
- November 19 advisory update (#38): `CVE-2026-115560` now carries the upstream fixed releases from GHSA-658j-r8rw-q6mx (8.2.36, 8.3.37, 8.4.28, 8.5.13) and sourced shared-store/serializer mitigations, and `CVE-2026-126714` (GHSA-fm2m-fjf5-v3cp, partially overwritten session files) is added. No vendor backports and no 8.6 threshold are encoded until they are sourced.
- Per-target `configuration_exposure` facts for `CVE-2026-115560` and `CVE-2026-126714`, kept independent of `patch_status` and compromise evidence (#38).
- Reverse dpkg lookup (`RuntimePackageProvenance::checkApacheModule()`) that identifies an Apache `mod_php` module's package even when the loaded `.so` filename carries no version, by checking which installed `libapache2-mod-php*` package's own manifest claims the exact loaded path (#11).
- PRA-5: reviewable, human-approved remediation plans generated from a runtime audit report (`bin/php-runtime-audit-report`), plus a human-readable `REPORT.md` (#10).
- Real, disposable Docker-based PHP 8.5 FPM and Apache worker coverage in CI, alongside the existing 8.2/8.4 pair (#9).
- Side-by-side multi-runtime (CLI + web worker) inventory and PHP-FPM/Apache worker package provenance (#7).
- PRA-3: versioned evidence records (observation, applicability, assessment, coverage, finding) with JSON Schema validation (`bin/php-runtime-audit-evidence`).
- PRA-2: guidance-mode audit-profile selector for coding agents (`bin/php-runtime-audit`).
- PRA-1: initial local runtime/patch inventory and PHP2Shell advisory evaluation (`bin/php-runtime-audit-inventory`).

### Fixed

- `session.upload_progress.enabled = yes` (and other trimmed ini boolean spellings) is now recognised as enabled (#38).
- FPM `php_flag[...]` / `php_admin_flag[...]` pool directives are now parsed like `php_value` / `php_admin_value` (#38).
- The advisory catalog rejects leading-zero branch and version segments (#38).
- The advisory catalog no longer hardcodes PHP branches 8.2–8.5; any `major.minor` branch is accepted when its fixed version is a final release on the same branch (#38).
- `CVE-2026-115560` patch status is derived from the same vendor-rule/provenance path as other advisories instead of an unconditional `unknown`. Even with a verified fix the verdict stays `needs_investigation` (never a no-action `verified_fixed`), because administrative scope, per-directory overrides and other writers of a shared session store are not collected, and an unpatched runtime keeps `potentially_affected` so the upgrade action is not lost (#38).
- Apache worker package-provenance lookups are now cached per module path, so many worker processes sharing one module file don't redundantly re-hash it against the shared integrity-check budget (#11).
