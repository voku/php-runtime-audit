# PHP Runtime Audit: governed implementation plan

## Decision record (2026-10-25)

**Goal:** A public, SEO-discoverable, local-first PHP audit service that generates environment-specific defensive checks and AI-ready, reviewable remediation. PHP2Shell is the first advisory module, not the identity or architecture of the entire product.

**Owner boundaries:**
- `voku/agent-loop` is the **development lifecycle** owner: task contract, Map/Recall/Learning, validation, review and human authority. Never reimplement its phase state machine.
- `cloudflare/security-audit-skill` is a **methodology reference**: architecture reconnaissance, coverage ledger, separate candidate verification, structured verdicts, and sourced reports. Adapt selected methods; don't transplant its large prompt corpus verbatim or claim Cloudflare endorsement.
- This project's deterministic PHP adapters are the **product**. They produce facts. An LLM may explain evidence and propose next steps but must not invent facts, silently alter hosts, or decide that an installation is safe.

## Slices, in dependency order

### PRA-1: Repository workflow bootstrap (current)

1. Declare `voku/agent-loop` as a Composer dev dependency, and establish a repeatable CI bootstrap.
2. Run official `init scaffold --prefix=PRA --agent=codex`, `init doctor`, `init host-status --format=json` on a clean installed consumer.
3. Review and commit generated `.agent-loop/`, managed `AGENTS.md`, and projected host assets; create the first durable PRA task through `enter` rather than hand-authoring governance state.
4. Commit the resolved `composer.lock` once Composer has run successfully.

**Exit:** Exact-head CI passes; project-owned asset provenance, host-status and lockfile are inspected; no product code is started until this boundary is established.

### PRA-2: Dynamic PHP audit skill, guidance mode first

Define `resources/skills/php-runtime-audit/SKILL.md` as a thin selector over **typed audit profiles**, not a monolithic prompt. Provide profiles by task intent (`runtime-patch`, `configuration`, `incident-triage`, `source-review`) and applicability (`apache-mod-php`, `fpm`, `cli`, `container`, distribution family, enabled extensions).

Read-only facts drive profile selection. Missing facts retain `unknown`. Project the skill using `agent-loop init sync-skills --agent=codex --skills-root=resources/skills` after dry-run inspection. The skill asks for owner authorization before requesting anything that accesses live infrastructure. Source/code auditing is separate from production runtime forensics.

**Exit:** Unit tests prove stable selection, unsupported SAPI handling, no cross-profile leakage, zero unapproved mutations, and bounded agent context. No replay of PHP2Shell exploit payloads.

### PRA-3: Versioned evidence and coverage contracts

Define typed PHP models and JSON schemas:
- `observation`: collector, schema version, timestamp, asset identity, source provenance, redaction state.
- `applicability`: runtime/version, SAPI, OS/vendor, configuration, source of each fact, `true|false|unknown`.
- `assessment`: `verified_fixed|potentially_affected|unknown|needs_investigation`, with reason, advisory revision and evidence IDs.
- `coverage`: stable subject/check IDs, attempted/skipped/blocked state and precise gaps.
- `finding`: `confirmed|needs_validation|rejected`, bounded observed impact and independently verified evidence.

Use separate `patch_status` and `compromise_evidence`. Never infer a confirmed compromise from version strings, OOM logs, a crash or a multipart request alone. Require an independent verifier for material security findings, in the Cloudflare pattern.

**Exit:** Schemas have validators, hostile/missing-input fixtures, negative tests and explicit source-ref freshness.

### PRA-4: Local collectors and advisory packs

Implement a minimal Linux runtime inventory: PHP CLI vs web worker, loaded Apache module or FPM binary, resolved package identity, known vendor backports, extensions, relevant INI files and worker restart evidence.

Advisory rules must distinguish CVE-2026-109618, CVE-2026-109619 and CVE-2026-115560, including differing mitigations and applicability. Every fact carries an advisory URL and as-of revision.

Use `proc_open` only with fixed allowlisted argv when required, with timeouts and explicit bounded output; no unsanitized shell interpolation. No active network scanning, OOM triggers or upload-progress exploit chains on production.

**Exit:** Disposable Debian/Ubuntu, RHEL-family, Alpine and container fixtures, including installed-vs-running mismatch and vendor-backport cases; PHPStan max, PHPUnit, PHP-CS-Fixer and security review.

### PRA-5: Remediation plans and offline incident triage

Generate local JSON plus a readable `REPORT.md`. A proposed patch plan includes prerequisites, maintenance window, exact package/vendor provenance, rollback and independent post-fix verification; **no automatic apply**. The LLM handoff states what is unverified and includes mandatory human approval before changes, service restarts or log exports.

Opt-in log triage can correlate request-startup OOM, unusually large cookies, crashes and web-worker child-process events, but categorizes attempts separately from process-level execution. Redact cookie values, IPs and secrets by default.

**Exit:** No fabricated green verdict, no command injection, redaction tests, provenance checks and approval tests.

### PRA-6: Public site and discoverability

Publish useful landing pages for PHP Runtime Audit, PHP2Shell Checker, PHP-FPM checks and patch verification. Provide downloadable generated read-only audit bundles, license, hashes, signed provenance if available and reproducible offline tests.

No remote execution API and no server credentials. Expose minimal analytics and an opt-in privacy boundary. Do not present diagnostic `unknown` as `safe`.

**Exit:** Threat model of input generation and bundle download, rate limits, content security policy, SSRF/path traversal tests, reproducible builds and independent reviewer approval.

## Reuse / avoid

**Reuse:** agent-loop package-owned workflow assets and typed lifecycle; PHPStan, PHPUnit, PHP-CS-Fixer; Cloudflare's coverage-ledger, hostile verifier and finding-state patterns; official PHP/vendor advisory sources.

**Avoid:** running Cloudflare's audit on arbitrary submitted URLs; importing its source indiscriminately; dynamic shell generation from LLM text; vendoring agent-loop's state machine; storing customers' secrets; early SSH or hosted agent execution; unnecessary new process-orchestrator abstraction.

## Project success criteria

A successful audit means **bounded evidence and justified next steps**, not a guaranteed clean bill of health. Every risk status must name the exact runtime/SAPI/vendor assumptions, their provenance and missing evidence. Every AI-generated fix plan remains a proposal until validated and approved.
