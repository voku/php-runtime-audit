# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

There are no tagged releases yet — the project is still on its way to the
Local MVP (see [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)
for current delivery gates). Entries below track notable merges to `main`.

## [Unreleased]

### Added

- The remaining 15 php-src advisories published on 2026-11-19 (CVE-2026-129289, 129496, 129474, 129182, 129481, 129291, 127960, 128064, 128090, 15353, 129506, 129501, 129438, 129292, 129538) are in the bundled catalog as data, each verified against its GHSA: fixed releases exactly as listed per branch (8.5-only and 8.4+ advisories only on those branches, no 8.6, no fix claimed for 8.1), mitigations only where the GHSA names a concrete setting, and no vendor backports. CVE-2026-129438 is GHSA-mg3p-mxj9-g2mm; GHSA-q23r-hr55-xmpg is CVE-2026-15353 only (#38).
- Disposable real-worker session-store scenarios (#38): pinned, network-less official PHP 8.2 FPM and 8.4 Apache containers with shared, isolated and same-serializer stores, missing configuration, administratively disabled upload progress, `files` and redis backends. The shared-store case is also checked through the remediation plan and the built PHAR, and the fixture credential is asserted absent from every JSON output. The two-pool scenarios are validated against ground truth: benign loopback FastCGI requests write a session through one pool and read it through the other, and the shared-store finding must be raised exactly when the store is really shared and the reader really cannot decode it.
- Read-only `session.save_handler` and `session.save_path` collection per SAPI, configuration root and FPM pool. Save paths that are not plain filesystem paths (redis/memcached DSNs, URLs) are stored only as a scheme label plus a per-run keyed digest, so stores can be compared without exposing credentials (#38).
- Cross-install session-store correlation for `CVE-2026-115560`: contexts that use different serialization handlers on an explicitly shared store or a shared default location (pools of one install; Debian/Ubuntu packages of every SAPI and version share `/var/lib/php/sessions`), while upload progress is explicitly enabled in at least one of them, raise `needs_investigation`. Configuration-file evidence only; applications can register their own save handler (#38).
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

- A large advisory catalog no longer aborts the report through the assessment, fact, source or 1 MiB limits. Runtime subjects are admitted in relevance order only while the measured advisory output still fits the 256-assessment, 1024-fact, 256-source and 1 MiB limits (vendor-rule sources count only when a selected subject matches the rule); when the inventory and catalog leave no room, every subject is listed as not assessed and the report keeps the catalog facts. The catalog is rejected at load time when its distinct source URLs (advisory, mitigation and vendor rule) exceed 96 or its catalog-level facts exceed 256, and source URLs are limited to the 256 bytes a report source locator may hold (previously a longer URL made the report fail schema validation). Identical workers of an unpackaged build (same FPM binary path and version, or same Apache module path, same provenance result, not deleted) now rank after packages like packaged pool children, so official `php:*-fpm` and `php:*-apache` containers with many workers keep their CLI assessed with the larger November catalog. Still not covered: an inventory whose own facts or sources together with the catalog-level ones exceed the 1024-fact or 256-source limits (with the bundled catalog: more than 966 inventory facts or 236 inventory sources; the collector does not bound its inventory below that), two identical package lines (same name and version), and catalog CVE ids long enough to exceed the evidence identifier limit (#38).
- The assessment budget also respects the 1024-fact evidence limit, so a host with very many PHP packages is reported with a coverage gap instead of aborting. Identical workers of a packaged runtime (same package, version and provenance, not deleted) no longer push out CLI runtimes or packages. Also, the summary carries `omitted_subject_count`. In the disposable checks, an isolated-store result now requires a reader that actually started, and the FastCGI probe reads complete records (#38).
- A large advisory catalog on a host with many PHP runtimes no longer aborts the whole report. The evaluator now stays within a 256-assessment budget, assessing running web workers first, then CLI runtimes, then packages. Subjects beyond the budget are listed in a `blocked` `advisory.assessment-budget` coverage entry, and the remediation plan warns that absence of a proposal is not evidence of safety (#38).
- `session.upload_progress.enabled = yes` (and other trimmed ini boolean spellings) is now recognised as enabled (#38).
- FPM `php_flag[...]` / `php_admin_flag[...]` pool directives are now parsed like `php_value` / `php_admin_value` (#38).
- The advisory catalog rejects leading-zero branch and version segments (#38).
- Quoted ini values followed by an inline comment are unquoted correctly, and assessment rationales are truncated without splitting UTF-8 characters (#38).
- The advisory catalog no longer hardcodes PHP branches 8.2–8.5; any `major.minor` branch is accepted when its fixed version is a final release on the same branch (#38).
- `CVE-2026-115560` patch status is derived from the same vendor-rule/provenance path as other advisories instead of an unconditional `unknown`. Even with a verified fix the verdict stays `needs_investigation` (never a no-action `verified_fixed`), because administrative scope, per-directory overrides and other writers of a shared session store are not collected, and an unpatched runtime keeps `potentially_affected` so the upgrade action is not lost (#38).
- Apache worker package-provenance lookups are now cached per module path, so many worker processes sharing one module file don't redundantly re-hash it against the shared integrity-check budget (#11).
