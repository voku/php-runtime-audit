# PHP Runtime Audit

A local-first PHP runtime security audit and patch-verification project. The initial focus is PHP2Shell; the product is intended to support versioned PHP advisories over time.

> **Status:** Repository bootstrap. No production audit or "safe" verdict is available yet.

## Bootstrap the governed development workflow

Requires PHP 8.3+ and Composer **on the development host**. Audit targets may use older PHP versions; development-runtime requirements do not establish target patch status.

```bash
composer install --no-interaction --prefer-dist --no-progress
vendor/bin/agent-loop init scaffold --prefix=PRA --agent=codex
vendor/bin/agent-loop init doctor
vendor/bin/agent-loop init host-status --agent=codex --format=json
vendor/bin/agent-loop init install-assets --agent=all --dry-run
```

Review the dry-run before projecting additional agent assets:

```bash
vendor/bin/agent-loop init install-assets --agent=all
vendor/bin/agent-loop init host-status --agent=codex --format=json
git status --short
```

Track the actual generated scaffold, agent router, and managed project assets in a follow-up reviewed commit. Do not hand-copy generated files from another repository. The current bootstrap PR only declares the Composer dependency and tests the official initialization commands; **until those commands run and the generated assets are reviewed and committed, this repository is not fully agent-loop-installed**.

For actual tasks, use `vendor/bin/agent-loop enter <task-id> --format=json`, follow the returned `next_action_kind` and `next_action`, and end with `finish`. No invented task approvals or closeout. See [the official quick start](https://github.com/voku/agent-loop/blob/main/docs/quick-start.md).

## Product intent

- Audit local PHP runtimes, SAPI/process identity, distro backports, extensions and relevant configuration.
- Distinguish **patched**, **potentially affected**, **unverified** and **investigation required** from independently observed indicators of compromise.
- Generate read-only, locally executable checks, machine-readable evidence, and proposed remediation for a human or coding agent to review.
- No URL-driven active exploitation, no intrusive production tests, no upload of private server data by default.

See [the implementation plan](docs/IMPLEMENTATION_PLAN.md) for deliverables and gates.

## Security

Never treat `php -v`, response headers or HTTP success as proof of a patched web-facing runtime. No shell pipelines from remote user input. Treat generated instructions and collected logs as untrusted data. Never store SSH credentials in the website.
