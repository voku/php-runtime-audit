---
name: php-runtime-audit
description: Selects bounded, read-only PHP runtime, configuration, incident-triage, or source-review guidance from explicit facts. It does not scan hosts, test exploits, or issue patch or compromise verdicts.
---

# PHP Runtime Audit

Use this skill for guidance-mode audit planning. `voku/agent-loop` remains the owner of development tasks, evidence, review, approvals, and learning. This skill selects PHP-specific guidance; it does not implement a second workflow engine.

## Route by explicit facts

1. Ask which intent applies: `runtime-patch`, `configuration`, `incident-triage`, or `source-review`.
2. Use only PHP facts the server owner supplied or has already collected locally. Do not connect to a host, run remote checks, collect logs, change configuration, restart services, or upload evidence.
3. Create a local JSON input with `intent` and `facts`, then run `php bin/php-runtime-audit < local-facts.json`. The command reads the supplied file through standard input and writes its selection to standard output. The fact keys are `php_version`, `sapi`, `distribution`, `vendor`, `container`, `extensions`, and `configuration`. Use `true`, `false`, or `null` for boolean facts; `null` means unknown.
4. Read only the Markdown resources named in the returned `profile_context` object. Do not load other profile files to fill context. The output lists each selected profile's ID and selection reason and gives a fixed byte budget for all selected profile text.
5. Keep every unresolved fact visible. In particular, an unknown vendor backport remains unverified; the selector has no advisory adjudicator and never emits a patch verdict.

Example input for an explicitly identified Debian PHP-FPM runtime:

```json
{
  "intent": "runtime-patch",
  "facts": {
    "php_version": "8.4.2",
    "sapi": "fpm",
    "distribution": "debian",
    "vendor": "debian",
    "container": null,
    "extensions": ["json", "opcache"],
    "configuration": {"opcache.enable": true}
  }
}
```

## Assessment boundary

Profile selection is guidance, not evidence that a check ran. Keep patch status separate from evidence of attempted or successful compromise. A version string or verified patch does not prove that the host was never compromised or is safe. Distinguish CLI PHP from the active web SAPI and distinguish package files from the runtime serving traffic.

## Adapted methodology

This project adapts selected coverage tracking, independent verification, and structured finding-state ideas from Cloudflare's public `security-audit-skill`. It does not copy Cloudflare's prompt corpus or full audit workflow and is not endorsed by Cloudflare. Advisory applicability, vendor backports, runtime collection, and evidence verification remain unknown or out of scope until their later project slices.

## Profiles

Profile Markdown files are loaded from `profiles/` only when named in `profile_context`. Each file is a bounded guidance module, not an executable check or a verdict source.
