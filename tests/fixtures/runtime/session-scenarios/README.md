# Disposable session-store scenarios

Configuration-only inputs for `tests/fixtures/runtime/run-disposable-runtime-checks.sh`
(issue #38, slice 4). Each directory is mounted read-only into a pinned, network-less
official PHP container: `pools.conf` as an extra PHP-FPM pool file and `session.ini` as a
`conf.d` fragment. Expected results live in `assert-disposable-session-report.php`.

The scenarios contain no exploit payloads and never create or read session data. The
redis DSN credential is a fixture marker that must never appear in any report.

## Validation against ground truth

For the two-pool scenarios (`writer` and `reader`), the script does not stop at checking
that the audit is self-consistent. After the read-only inventory it sends benign FastCGI
requests over the container's own loopback (the container still has no network) to
`tests/fixtures/runtime/session-probe`: one plain-string session is written through the
writer pool and read through the reader pool. `assert-session-ground-truth.php` then
requires the audit's shared-store finding to be raised exactly when the writer's session
file really lands in the reader's live `save_path` and the reader really cannot decode it.

The probe reads settings with `ini_get_all()`, not `ini_get()`: the official images enable
an OPcache shared by all pools of one master, and it folds `ini_get('session.*')` at
compile time, so a script first compiled in one pool reports that pool's value in another.
