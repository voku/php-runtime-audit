# PHP Runtime Audit: governed implementation plan

## Current delivery status

PRA-1 bootstrap assets are present, but PRA-1 remains `legacy_inferred` and incomplete: it has no Contract, governed Run, or review record. PRA-2 is complete with verification passed and review `ok`. PRA-3 is complete with verification passed and review `warn`; its historical warning remains recorded. PRA-4-MAINLINE is complete with verification passed and review `warn`; its recorded limitation is fixture-tested PHP 8.5 parity without a real PHP 8.5 container smoke. PRA-4-MULTIRUNTIME extends inventory across legacy and side-by-side PHP installations and must be marked complete only by its governed workflow. The earlier PRA-4 run remains preserved with verification passed and review `warn`. Local and Public MVPs have separate release gates; neither is declared released here.

- **Local MVP:** verified local runtime and patch checks, vendor-backport evidence, three-valued applicability, and reviewable environment-specific remediation instructions. PRA-1, PRA-2, PRA-3, PRA-4, and PRA-5 must complete their canonical workflows.
- **Public MVP:** verified Local MVP plus PRA-7A documentation and PRA-7B reproducible, independently security-reviewed downloadable bundles.
- Full source analysis, incident forensics, Windows and NativePHP do not block the narrow Local MVP.

## Decision record (2026-10-25)

**Goal:** A public, SEO-discoverable, local-first PHP audit service that generates environment-specific defensive checks and AI-ready, reviewable remediation. PHP2Shell is the first advisory module, not the identity or architecture of the entire product.

**Owner boundaries:**
- `voku/agent-loop` is the **development lifecycle** owner: task contract, Map/Recall/Learning, validation, review and human authority. Never reimplement its phase state machine.
- `cloudflare/security-audit-skill` is a **methodology reference**: architecture reconnaissance, coverage ledger, separate candidate verification, structured verdicts, and sourced reports. Adapt selected methods; don't transplant its large prompt corpus verbatim or claim Cloudflare endorsement.
- This project's deterministic PHP adapters are the **product**. They produce facts. An LLM may explain evidence and propose next steps but must not invent facts, silently alter hosts, or decide that an installation is safe.

## Slices, in dependency order

### PRA-1: Repository workflow bootstrap (assets present; workflow incomplete)

1. Declare `voku/agent-loop` as a Composer dev dependency, and establish a repeatable CI bootstrap.
2. Run official `init scaffold --prefix=PRA --agent=codex`, `init doctor`, `init host-status --format=json` on a clean installed consumer.
3. Review and commit generated `.agent-loop/`, managed `AGENTS.md`, and projected host assets; create the first durable PRA task through `enter` rather than hand-authoring governance state.
4. Commit the resolved `composer.lock` once Composer has run successfully.

**Exit:** Exact-head CI passes; project-owned asset provenance, host-status and lockfile are inspected; no product code is started until this boundary is established.

### PRA-2: Dynamic PHP audit skill, guidance mode first (complete; review `ok`)

Define `resources/skills/php-runtime-audit/SKILL.md` as a thin selector over **typed audit profiles**, not a monolithic prompt. Provide profiles by task intent (`runtime-patch`, `configuration`, `incident-triage`, `source-review`) and applicability (`apache-mod-php`, `fpm`, `cli`, `container`, distribution family, enabled extensions).

Read-only facts drive profile selection. Missing facts retain `unknown`. Project the skill using `agent-loop init sync-skills --agent=codex --skills-root=resources/skills` after dry-run inspection. The skill asks for owner authorization before requesting anything that accesses live infrastructure. Source/code auditing is separate from production runtime forensics.

**Exit:** Complete. Unit tests cover stable selection, unsupported SAPI handling, no cross-profile leakage, zero unapproved mutations, and bounded agent context. Agent-loop records verification passed and review `ok`. No replay of PHP2Shell exploit payloads.

### PRA-3: Versioned evidence and coverage contracts (complete; review `warn`)

Define typed PHP models and JSON schemas:
- `observation`: collector, schema version, timestamp, asset identity, source provenance, redaction state.
- `applicability`: runtime/version, SAPI, OS/vendor, configuration, source of each fact, `true|false|unknown`.
- `assessment`: `verified_fixed|potentially_affected|unknown|needs_investigation`, with reason, advisory revision and evidence IDs.
- `coverage`: stable subject/check IDs, attempted/skipped/blocked state and precise gaps.
- `finding`: `confirmed|needs_validation|rejected`, bounded observed impact and independently verified evidence.

Use separate `patch_status` and `compromise_evidence`. Never infer a confirmed compromise from version strings, OOM logs, a crash or a multipart request alone. Require an independent verifier for material security findings, in the Cloudflare pattern.

**Exit:** Complete. Schemas have validators, hostile/missing-input fixtures, negative tests and explicit source-ref freshness. Agent-loop records verification passed and review `warn`; that warning remains part of the historical result.

### PRA-4: Local collectors and advisory packs (in progress)

Implement a minimal Linux runtime inventory: PHP CLI vs web worker, loaded Apache module or FPM binary, resolved package identity, known vendor backports, extensions, relevant INI files and worker restart evidence.

Advisory rules must distinguish CVE-2026-109618, CVE-2026-109619 and CVE-2026-115560, including differing mitigations and applicability. Every fact carries an advisory URL and as-of revision.

Use `proc_open` only with fixed allowlisted argv when required, with timeouts and explicit bounded output; no unsanitized shell interpolation. No active network scanning, OOM triggers or upload-progress exploit chains on production.

**Exit:** Disposable Debian/Ubuntu, RHEL-family, Alpine and container fixtures, including installed-vs-running mismatch and vendor-backport cases; PHPStan max, PHPUnit, PHP-CS-Fixer and security review.

### PRA-5: Reviewable remediation plans (Local MVP gate)

Generate local JSON plus a readable `REPORT.md`. A proposed patch plan includes prerequisites, maintenance window, exact package/vendor provenance, rollback and independent post-fix verification; **no automatic apply**. The LLM handoff states what is unverified and includes mandatory human approval before changes, service restarts or log exports.

Full incident triage is deferred to PRA-4C; it is not a prerequisite for these remediation instructions.

**Exit:** No fabricated green verdict, no command injection, redaction tests, provenance checks and approval tests.

### PRA-4B / PRA-4C: Separate follow-up Contracts

PRA-4B adds session/serialization source reachability and negative fixtures. PRA-4C adds opt-in incident and availability triage. Crashes, OOM and suspicious requests cannot establish RCE or compromise. Both require independent review and preserve sensitive evidence locally.

### PRA-6: Optional platforms

Windows and NativePHP remain isolated, separately scoped work. No Linux applicability may be inferred for these platforms.

### PRA-7A: Public documentation and discoverability

Publish accurate PHP Runtime Audit, PHP2Shell and vendor-backport guidance. Documentation may ship before the checker, provided it explicitly states which functionality is available. Explain that separate unserialize()/var_destroy() bugs have their own causes and fixes; their existence does not invalidate fixes for the two reported PHP2Shell CVEs.

### PRA-7B: Reproducible audit bundles (Public MVP gate)

Package the verified local tool with locked dependencies, licenses, hashes, reproducible offline tests and independently reviewed provenance. Keep all collection local; no domain-scanning endpoint, credentials or exploit payloads. Review archive traversal, generated instructions, output disclosure and distribution integrity. Public hosting is a separate deployment step with evidence of the actual deployment.

## Reuse / avoid

**Reuse:** agent-loop package-owned workflow assets and typed lifecycle; PHPStan, PHPUnit, PHP-CS-Fixer; Cloudflare's coverage-ledger, hostile verifier and finding-state patterns; official PHP/vendor advisory sources.

**Avoid:** running Cloudflare's audit on arbitrary submitted URLs; importing its source indiscriminately; dynamic shell generation from LLM text; vendoring agent-loop's state machine; storing customers' secrets; early SSH or hosted agent execution; unnecessary new process-orchestrator abstraction.

## Project success criteria

A successful audit means **bounded evidence and justified next steps**, not a guaranteed clean bill of health. Every risk status must name the exact runtime/SAPI/vendor assumptions, their provenance and missing evidence. Every AI-generated fix plan remains a proposal until validated and approved.

## Bounded reuse decision (2026-10-26)

These are pinned research candidates, not adopted dependencies or verified detection rules:

| Candidate | Revision | License | Current decision |
| --- | --- | --- | --- |
| cloudflare/security-audit-skill | `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` | MIT | Retain bounded coverage and independent verification methods; avoid duplicating lifecycle/evidence owners. |
| andreysheva/php2shell-doctor | `f961a04ab0f6215e711c9d6516add1a0cbac5a01` | Apache-2.0 | Evaluate package ordering against native Debian/RPM oracles before adopting code; no engine replacement justified yet. |
| KnickLighter/p2selfcheck | `d452e4cc2faa3ceebfe6507e18be7f2eb7663bb9` | MIT | Optional shared-hosting investigation only; unknown newer branches must not become likely-fixed, and public runtime disclosure needs protection. |

ACD421 remains attributed research input, with no copied unlicensed implementation. Official vendor advisories, upstream commits and research retain separate scope and freshness. An upstream commit alone is not proof of a vendor package or running worker fix. Vendor contradictions and missing package-ordering evidence remain unknown rather than green.

## Current runtime validation boundaries

The disposable harness uses pinned PHP 8.2 FPM and PHP 8.4 Apache images, no network or exposed ports, production-only dependencies, real worker identity and local pool overrides. Source-built image provenance stays unknown. Offline distro fixtures supplement these real runtimes; they are not claims of real distro-container coverage. Child commands require an observed isolated namespace or a fixed namespace wrapper and fail closed if unavailable. Successful wrapper creation still needs platform-specific validation; failure cannot trigger an unrestricted fallback.

### Runtime integrity gate

A worker's executable basename and matching upstream version are not package provenance. Debian/Ubuntu FPM fixed verdicts require bounded local dpkg metadata and integrity checks, agreement with package inventory, and loaded-versus-installed executable identity. The local package database is a stated trust assumption, not independent signed verification of a compromised machine. RPM/APK and unsupported executable layouts remain unknown until independently reviewed integrity adapters exist. Synthetic integrity fixtures are labeled and do not represent vendor binaries. Remote advisory URLs remain uncaptured citations; only the bundled catalog has a captured content digest.
