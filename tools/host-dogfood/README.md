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
