# Reuse lab: first CI evidence and adoption decisions

**Evaluated:** 2026-10-26 UTC. **Successful GitHub Actions run:** [40286660962](https://github.com/voku/php-runtime-audit/actions/runs/40286660962). **Prior failed run:** [40286534312](https://github.com/voku/php-runtime-audit/actions/runs/40286534312).

All four candidate jobs passed from the pinned upstream commits in `candidates.json`. Artifacts contain `result.json`, `upstream-commit.txt`, `output.log` and partial `source-file-hashes.txt` (14-day retention). This proves only the stated upstream tests/checks, **not** production security or suitability for incorporation.

| Candidate | Observed evidence | Reuse decision |
|---|---|---|
| Cloudflare security-audit-skill (MIT) | 65/65 Node validator tests passed | **Adapt** bounded coverage/finding validators; don't duplicate agent-loop governance. |
| php2shell-doctor (Apache-2.0) | Go package test suite passed | **Fork/adapter candidate** for vendor DB, version comparison, runtime discovery; independently verify advisories and process identity. |
| p2selfcheck (MIT) | PHP 8.3 syntax + CLI smoke passed | **Do not reuse verdicts unchanged**: output claims the full RCE chain needs an application LFI sink, contradicted by confirmed PHP-engine PHP2Shell paths. The local identity probe might still be reusable behind access controls. |
| bashclub forensic-check (MIT) | `bash -n` passed | **Reference only** pending offline functional/security tests; syntax is not a forensic accuracy test. |

## The real first-run failure

The first php2shell-doctor job failed `fork/exec /tmp/go-build.../*.test: permission denied` because the sandbox's scratch tmpfs was non-executable. The CI harness now explicitly permits test binaries in a **bounded scratch tmpfs**, while keeping network disabled, the checkout and filesystem read-only, non-root UID, no Linux capabilities, and CPU/process/memory limits. The subsequent run passed. **This was our harness defect**, not an upstream Go defect.

## Evidence that still needs proof

- Compare vendor-fix data to authoritative advisories, including Ubuntu Jammy package revisions `.27` and `.28`; report provenance and date.
- Verify live FPM/Apache worker binaries, not just installed package or binary modification timestamps. The observed Go test output lists `internal/stale` with no tests.
- Validate Cloudflare schema integration and JSON input handling independently. Do not impose Node as a dependency on PHP target hosts.
- Shared-hosting PHP probes must be access-protected, time-limited and remove unsupported application-LFI exploitability claims.
- Forensics needs redaction and explicit `attempt` / `execution_observed` distinctions with fixtures.

## Governance

This is a separate experimental branch and draft PR. It does not modify PRA-2/PRA-4 worktrees, Contracts, or accepted evidence. `agent-loop#836` was closed through merged PR #837; consumer package adoption and exact-candidate review still require evidence. No upstream code is vendored and no merge or release is authorized.
