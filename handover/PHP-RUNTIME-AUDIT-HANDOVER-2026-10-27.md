# PHP Runtime Audit handover — 2026-10-27

## Live GitHub update — 2026-10-27 15:54 UTC

GitHub moved after this handover was first pushed:

- PR #7 merged as `8e1d1e253158f6f65e7612fcd05cd37d615e3bb8`. It includes Claude's follow-up commit `27695c2487997a7a987b4a978d825d54e72c0241`, which corrected CLI runtime advisory `source_fact_id` binding.
- Claude's PR #9 merged as `7bf4c060b6175b857baebfa6a701f3083cab97a3`. It adds real, pinned PHP 8.5 FPM/Apache coverage and confirms the audited image version in the report. Exact-head Actions run `40534732472` passed all consumer jobs; its disposable script covers PHP 8.2 FPM, 8.4 Apache, and PHP 8.5 FPM/Apache.
- Current GitHub `main` is `7bf4c060b6175b857baebfa6a701f3083cab97a3`. PR #8 remains the open draft handover.
- The owner-side PRA-4-MULTIRUNTIME Run read from the original workspace remains attempt 1 at `build`, candidate still the approved base, with only `investigate` accepted. `agent-loop enter` still directs host work; `pipeline status` still cannot acquire the root-owned lock. Green CI and merged PRs have not recorded the missing governed candidate observation, validations, reviews, verification, or closeout.

This update supersedes the earlier GitHub PR and CI status below. The archived Run/Contract files remain a point-in-time snapshot and the live `.agent-loop` state remains authoritative.

This handover is for the next coding agent taking over PHP Runtime Audit. Lars has authorized continuing the current approved work and using GitHub CI. The goal remains the first Local MVP, but **the project is not done**: only report it done when the canonical agent-loop workflow says the exact merged candidate is complete.

## Repositories and live GitHub state

- Repository: <https://github.com/voku/php-runtime-audit>
- `main` base for the active candidate: `0b5e2c0c087710da6ec25c5510f7f830c602ae33`.
- Runtime candidate commit `fe9c8f901b16c49b51102c7fc44d2e76d991b5a8` (tree `ed953bb046ba0f6df2f86af219ca672e390aab86`) and Claude's fix `27695c2487997a7a987b4a978d825d54e72c0241` are merged through [PR #7](https://github.com/voku/php-runtime-audit/pull/7), merge commit `8e1d1e253158f6f65e7612fcd05cd37d615e3bb8`.
- Handover/evidence branch: `handover/pra4-multiruntime-20261027`, still proposed as draft [PR #8](https://github.com/voku/php-runtime-audit/pull/8). It carries this document and an archival copy of the current Contract, Run, session, and Contract history. It is not product scope and should not be merged as a substitute for the active execution pipeline.
- PR #7 has merged, but its merge is **not** an accepted agent-loop candidate. No correctness review, blind-spot review, deterministic verification, or closeout has been accepted for the merged candidate.
- PR #9's exact-head Actions run `40534732472` passed. The real-container script checked pinned PHP 8.2 FPM, PHP 8.4 Apache, PHP 8.5 FPM, and PHP 8.5 Apache images, with observed version evidence asserted. See <https://github.com/voku/php-runtime-audit/actions/runs/40534732472>. The local Docker command remains blocked by the full filesystem.

## Canonical workflow state

The authoritative owner-side project is `/workspace/php-runtime-audit`. Its active Run and approved Contract are PRA-4-MULTIRUNTIME:

- Run: `run:PRA-4-MULTIRUNTIME:8f7d2bb5829e50c2`
- Contract revision: 2, approved by Lars Moelleken on 2026-10-27.
- Approved base: `0b5e2c0c087710da6ec25c5510f7f830c602ae33`.
- Execution state: attempt 1, current stage `build`; only the `investigate` stage is accepted. Candidate remains the base commit in the canonical Run state; no build candidate observation, validations, independent review, verification, or finish result has been accepted.
- `agent-loop enter PRA-4-MULTIRUNTIME --format=json` using agent-loop 0.20.72 reported `mutation_ready: true`, `state: incomplete`, and canonical next action `perform the approved host-native implementation for PRA-4-MULTIRUNTIME before calling agent-loop finish PRA-4-MULTIRUNTIME` (`next_action_kind: host_work`). It also reported the project agent-map index invalid because its source root does not match the selected project root.
- `agent-loop pipeline status PRA-4-MULTIRUNTIME --format=json` could not acquire `.agent-loop/runs/PRA-4-MULTIRUNTIME/execution-state.lock`: the file and run directory are owned by `root`, and the current `agent` user cannot open the lock for writing. Do not alter the state or invent a replacement Run. Restore access to the original owner state through the workspace owner/environment mechanism, then continue through the supported agent-loop route.
- The approved investigation noted that installed v0.20.71 lacks candidate-workspace routing and that upstream v0.20.72 supports registered linked-worktree routing through the pipeline `--workspace` option. Recheck the installed CLI's help and current status before using it; do not guess command syntax or copy this archival snapshot back into `.agent-loop`.

An archival, byte-preserving snapshot of Contract revision 1 and 2, the current Run files (excluding the transient lock file), and its session artifacts is under `handover/evidence/PRA-4-MULTIRUNTIME/`. These files are **for handoff and comparison only**. The live owner-side `.agent-loop` remains canonical. SHA-256 values for the current Contract, execution state, manifest, and session are recorded by the files themselves in the reviewable Git history; the Contract SHA is `2b9ce979a782858cdfe640c572e986324b80774a60d231b05f85da4f13312db7`, and the session SHA is `567c191e6ed143b45a7350bae27c1ed3c0708eddaeea570d5c8f51a0f978fdd9`.

## Workspaces and preservation

The workspace was not a clean clone. Preserve all existing worktrees and their owner state. Do not reset, clean, overwrite, rebase, or repurpose them to make a gate pass.

- `/workspace/php-runtime-audit`: dirty branch `reconciliation/pra4-preserved`, HEAD `923aecd1200ee98d37604899da5ef9d2ba80573b`; contains prior PRA-2/PRA-3/PRA-4 changes and canonical agent-loop state.
- `/workspace/php-runtime-audit-pra4-multiruntime`: dirty branch `feature/pra4-multiruntime`, HEAD at the approved base. Its `tests/RuntimeInventory/RuntimeInventoryCollectorTest.php` is truncated at 24,576 bytes and ends inside a docblock due to a previous no-space write failure. Do not use that file as the recovered source.
- Other preserved worktrees include `/workspace/php-runtime-audit-pra4-preserved`, `...-pra4-mainline-candidate`, `...-pra4-pr-update`, and `...-pra4-ci-fix`, plus the PRA-2/PRA-3 candidate worktrees. Inspect before use and leave them intact.
- A reconstructed, full candidate was created separately under `/tmp/php-runtime-audit-pra4-multiruntime-recovery` and committed to PR #7. Use the PR branch as the clean transport copy, then attach that candidate to the existing Run through the supported workflow after original owner-state access is restored.

At handover, `/` was 100% full (`32G used, 0 available`), while `/tmp` had about 3.7G available. Docker could not create a container. This is why the local disposable-runtime command failed; do not treat that as a passing or skipped test. Temporary Composer dependencies were reinstalled under `/tmp` after a partial vendor copy was found incomplete. Do not recover files by deleting preserved workspace data.

## Candidate content and local validation

PR #7 implements bounded discovery of distinct PHP installations and runtime subjects, with package provenance and advisory results kept bound to each subject. It includes legacy PHP 5.x/7.x discovery, multiple CLI/FPM installations, package-to-worker matching, deletion/conflict evidence, bounded PATH enumeration, discovery-limit evidence, and tests. Custom PATH entries are recorded as candidates but not executed; this avoids treating a user-controlled wrapper as a trusted PHP binary. Unknown or conflicting vendor evidence remains `unknown`.

The exact PR #7 commit was locally checked on PHP 8.4.26:

- `composer validate --no-check-publish` — exit 0.
- `composer test` — exit 0, 159 tests / 1,156 assertions.
- `composer analyse` — exit 0, no PHPStan errors.
- `composer format-check` — exit 0. PHP-CS-Fixer warned that 8.4 is newer than the package's PHP 8.2 minimum; this is a runtime mismatch warning, not a format failure.
- `php bin/php-runtime-audit-inventory --fixture tests/fixtures/runtime/debian-fpm` — exit 0.
- `git diff --check` — exit 0.
- `bash tests/fixtures/runtime/run-disposable-runtime-checks.sh` — exit 125 because Docker reported `no space left on device` while creating the container.

The first PHPStan and formatting runs found real issues in the recovered copy; those were fixed and the checks rerun successfully. They were not suppressed. The duplicate Remi regression-test declaration introduced during recovery was also removed before commit and tests passed afterward. Treat these as direct local evidence for commit `fe9c8f9` only. Claude's follow-up commit and PR #9 have their own successful GitHub CI evidence. Agent-loop still records the Contract validations as missing.

## Independent review notes (not accepted workflow evidence)

Two read-only, independent review contexts examined the earlier uncommitted candidate. They identified three areas requiring attention:

1. The bounded package limit could silently omit package rows while coverage remained `attempted`; the PR candidate now records package truncation and blocks package coverage when incomplete.
2. Remi Software Collection packages (for example `php74-php-cli` and `php74-php-fpm`) were not associated with their `/opt/remi/phpNNN/...` runtime paths; the candidate adds distinct package mapping while keeping unsupported vendor patch status unknown.
3. Custom PATH runtime candidates were not considered, and blindly probing arbitrary PATH entries could execute wrappers. The candidate records bounded custom PATH candidates without executing them and marks discovery incomplete/unknown where appropriate.

These notes were not submitted as accepted correctness or blind-spot stages. All three changes are new candidate code and need fresh review against exact commit `fe9c8f9`; old notes cannot be replayed as a PASS.

## Immediate next steps for the receiving agent

1. Verify current `main`, merged PRs #7 and #9, Actions run 40534732472, and open handover PR #8.
2. Reattach or reopen the original workspace so the live owner-side `.agent-loop` state and lock are writable by the authorized user. Preserve all worktrees. The current `/workspace` is full; do not free space by deleting project or evidence files.
3. Run `agent-loop enter PRA-4-MULTIRUNTIME --format=json` and follow its current canonical next action. Use a supported v0.20.72+ pipeline workspace route for the exact candidate if the current CLI documents it. Register the actual source candidate and candidate observation under the existing Run/Contract; do not substitute this handover snapshot or create a new Run.
4. Run every Contract validation against the registered exact candidate. Reattempt the disposable runtime smoke when the environment has space, and record any genuine environment limitation without calling it a pass.
5. Obtain fresh correctness and blind-spot reviews in distinct contexts on that exact candidate, resolve findings through the governed build flow, then run deterministic verification and `agent-loop finish` through completion. Keep PRA-4-MAINLINE's prior warning about absent real PHP 8.5 container smoke accurately recorded.
6. PR #7 and PR #9 are already merged. Do not use those merges as a substitute for the existing Run's missing evidence. Inspect the exact merged candidate and follow the current agent-loop closeout route; do not create a replacement Run.
7. Then proceed to the already approved Local MVP work. PRA-5 remediation plans remain required before Local MVP completion. Do not start PRA-3A or public-release work unless a new Contract authorizes it.

## Release state

- Local MVP: **not complete**.
- PRA-3A: not started.
- Public website/bundles: not started.
- No new merge or release was performed in this handover.
