# Reuse lab: bounded GitHub Actions experiment

This research-only CI evaluates pinned upstream snapshots. It is **not** a new
PRA Contract, not the active PRA-2 or PRA-4 candidate, and not a product feature.
It intentionally runs in a separate branch and draft PR targeting the existing
bootstrap branch. Do not merge or release without owner review.

## Candidates

The exact repositories, SHAs, declared licenses and checks live in
`candidates.json`. Changes to those pinned values must be reviewed. No
unlicensed ACD421 code, exploit payloads, remote scanning, SSH access or
production processes are involved.

- Cloudflare: tests for coverage and findings validators.
- php2shell-doctor: Go package tests; evaluate integration rather than
  claiming the Go binary is automatically safe to distribute.
- p2selfcheck: PHP syntax plus local CLI smoke in the isolated container.
  This is **not** a proof of a patched web runtime.
- bashclub: Bash syntax check only, **not** its host scanning logic.

## Trust boundary

GitHub checks out the consumer with credentials disabled. Upstream source is
fetched into a scratch directory **by exact commit** and only executed inside
Docker with network disabled, read-only filesystem and source mount, no
privileges/capabilities, non-root UID, and CPU/process/memory limits. The
upstream source is not copied into the product. No upstream code runs on the
host runner. The CI job has `contents: read` only.

Each matrix job uploads its own `result.json`, output log, source SHA and
partial source hashes, including its resolved Docker image identity. A green
upstream test does **not** mean the project meets our evidence contract, is
fit for production, or is approved for incorporation.

## After CI

Review the artifacts, licenses and gaps. Choose **fork/adapt**, **dependency/
adapter**, **reference only**, or **reject** by measurable integration cost,
provenance quality, false-verdict risk and packaging footprint. Create an
approved follow-up Contract for actual integration after Gate 0 resolves.
