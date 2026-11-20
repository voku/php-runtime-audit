# Disposable session-store scenarios

Configuration-only inputs for `tests/fixtures/runtime/run-disposable-runtime-checks.sh`
(issue #38, slice 4). Each directory is mounted read-only into a pinned, network-less
official PHP container: `pools.conf` as an extra PHP-FPM pool file and `session.ini` as a
`conf.d` fragment. Expected results live in `assert-disposable-session-report.php`.

The scenarios contain no exploit payloads and never create or read session data. The
redis DSN credential is a fixture marker that must never appear in any report.
