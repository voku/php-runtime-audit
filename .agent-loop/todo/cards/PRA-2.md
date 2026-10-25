# PRA-2: Dynamic PHP audit skill

- **Ticket:** PRA-2
- **Lane:** READY
- **Status:** Selected
- **Created:** 2026-10-25T07:57:00+00:00
- **Updated:** 2026-10-25T07:57:00+00:00
- **Summary:** Build a deterministic evidence-driven selector and thin PHP skill router.
- **Format version:** 1

## Agent Task Brief
Guidance-mode PRA-2: define a thin resources/skills/php-runtime-audit/SKILL.md router and a deterministic typed PHP profile selector for runtime-patch, configuration, incident-triage, and source-review intents. Select only profiles supported by read-only facts including PHP version, SAPI, OS and vendor provenance, runtime or container facts, enabled extensions, and relevant configuration. Missing facts remain unknown, unsupported SAPI is explicit, and Debian PHP-FPM must not load Apache mod_php or container checks unless evidence applies. Keep patch assessment separate from compromise evidence. Adapt Cloudflare six-phase evidence, coverage, and independent-verification methods selectively without copying the full skill or claiming endorsement. Add deterministic tests for stable selection, unknown or missing facts, unsupported SAPI, cross-profile isolation, no mutation, and bounded context. Exclude active network scanning, exploit payloads, production scans, sensitive evidence upload, automatic remediation, PRA-3 evidence engine, PRA-4 collectors, PRA-5 remediation, and PRA-6 website.
