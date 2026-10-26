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

## Synthetic package and worker fixture result (2026-10-26)

**Pinned upstream:** `andreysheva/php2shell-doctor@f961a04ab0f6215e711c9d6516add1a0cbac5a01`.

**Exact-head GitHub Actions run:** [40287971767](https://github.com/voku/php-runtime-audit/actions/runs/40287971767),
candidate head `f77474456adef25e0a8f662ead968e1452e39df4`. The job reports **9 fixtures,
0 unexpected upstream mismatches, 5 product adapter gaps**. A machine-readable
`vendor-worker-fixtures.json` is included in the `reuse-lab-php2shell-doctor`
artifact. The fixtures run offline in a non-root container and inspect no live
workers.

- **Jammy vendor evidence (2 gaps):** The pinned upstream vendor DB returns
  `VERIFY_VENDOR` for both Ubuntu 22.04 `8.1.2-1ubuntu2.27` and
  `8.1.2-1ubuntu2.28`. Canonical
  [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) establishes
  `.28` as fixed. The product must preserve package-level distinction without
  asserting anything about running PHP workers from packages alone.
- **Noble/RHEL control cases:** The pinned source correctly distinguishes
  Noble `.12` vs `.13`, and retains `VERIFY_VENDOR` for an unverified RHEL
  package.
- **Worker evidence (3 gaps):** The upstream stale-worker detector is
  appropriately bounded to matching process names/paths, but
  `checked=0,stale=0` cannot prove the web runtime is patched when process
  identity is missing or conflicting. Likewise `checked=1,stale=0` by
  modified-time comparison alone is not a verified running binary/configuration
  attestation.

These are product contract gaps, not claims of upstream exploitation or false
security verdicts from a real server. **PRA-4 source code was not available in
this CI context**; the fixture data remains reference material pending a
separate, approved integration and exact-candidate review. No product code or
existing Contracts changed.
