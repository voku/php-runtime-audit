# First-host dogfood: separate CI experiment

This is a **non-product** experiment based on the current PRA-4 PR #13 head.
It uses a real ephemeral `ubuntu-24.04` GitHub-hosted Linux runner,
installs a distribution `php8.3-fpm` package, starts its FPM master and
workers, builds the repo's PHAR and runs inventory -> remediation directly
against the runner's **actual** `/proc`, package database and configuration.

Raw inventory, remediation JSON and Markdown stay under the private
`RUNNER_TEMP` directory and are never uploaded or printed. Only aggregate
verdict/coverage counts and safety invariants are kept as a short-lived
artifact. There is no exploit, network target probe or automatic remediation.
FPM uses its Ubuntu package's default local Unix-domain socket.

The collector may fail closed if Linux user/network namespaces are disabled
by the GitHub-hosted environment. A passing job shows a real-host
integration run under **these** runner capabilities, not correctness on an
independent VPS or web service. Worker identity, loaded modules and vendor
backports still require a separate operator-run proof on a real target.

**Workflow scope:** experiment only. This separate draft PR targets the PRA-4
feature branch, keeps PR #13 untouched, and should not be merged into
the product until its own evidence is reviewed.

## Read-only dpkg fallback feasibility test

This experiment additionally reads the runner's actual `/var/lib/dpkg/status`
with an 8 MiB cap, regular-file/inode checks, duplicate-target rejection and
no symlink traversal. A separate CI control runs `dpkg-query` after package
installation and compares only in memory. The file-only PHP probe makes **no
network requests or subprocess calls**, regardless of whether `unshare`
works. Negative tests cover duplicate records, missing/conflicting metadata,
malformed versions, symlinks and oversized status files.

Only boolean agreement is published; package versions, identities and raw
status contents stay on the ephemeral runner. This validates that **some
installed-package evidence is recoverable** on namespace-restricted hosts.
It does **not** authenticate the dpkg database, prove live PHP worker
identity, establish a vendor backport or change any security assessment.
Do not integrate this research parser directly into the production collector
without a separately approved Contract, review and hostile-file testing.
