# CI-only vendor/package and worker identity fixture comparison

The fixtures are **synthetic**. The upstream `php2shell-doctor` package is pinned in
`../candidates.json` and executed in a network-disabled, non-root container. The
Go comparison program is copied into a temporary module inside that container,
with no upstream source changes and no host/process inspection.

Cases cover:
- Ubuntu 22.04 `php8.1-fpm`: vulnerable `.27` versus fixed `.28` as stated by
  [Canonical USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1)
- Ubuntu 24.04 `php8.3-fpm`: `.12` versus `.13`
- RHEL-family unverifiable backport
- Real PHP worker executable mismatch, stale matching worker, and missing attestation

The outputs separate upstream observed behavior from the desired **future
PHP Runtime Audit** evidence policy. An upstream `VERIFY_VENDOR` result can be
correctly conservative yet less precise than a vendor-supported per-package rule.
A zero stale-worker count cannot prove a serving worker is patched when its
identity is missing or conflicting.

The benchmark must not be called a PRA-4 regression pass: the current local,
uncommitted PRA-4 candidate is unavailable to GitHub Actions. Integrating the
same fixtures into PRA-4 requires its own approved Contract and exact-candidate
review, after Gate 0 is completed.
