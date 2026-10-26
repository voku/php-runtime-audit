# Consumer recovery release adoption

This experimental branch is based on `feature/agent-loop-bootstrap`, and does
not touch the local dirty PRA-2 and PRA-4 worktrees or their governed Contracts.

- The upstream fix for a completed execution pipeline unable to accept new
  review evidence was merged in `agent-loop#837`.
- Signed/annotated tag `0.20.70` points to
  `d5e77d400ebd7bdbd8e5fe875a2e894e2b99f70e`.
- The branch sets the Composer development floor to `^0.20.70`.
- Only a same-repository pull request from branch
  `dependency/agent-loop-recovery-0.20.70` can run the guarded dependency
  migration that regenerates `composer.lock`. Composer runs with scripts and
  plugins disabled. The pipeline verifies the exact release reference,
  then commits *only* the regenerated lockfile back to this branch.
- No production PHP target, credentials, remote endpoint, worker, project
  Contract, or governed reviewer state is inspected or modified.
- Once the lock is updated, the main bootstrap workflow must independently
  validate canonical assets and exact-head CI. Review any projection drift
  as its own owned change.

**Boundary:** A successful CI install does not close PRA-2. The actual current
candidate is still uncommitted in another worktree and cannot be independently
reviewed by GitHub Actions unless it is lawfully published into a reviewable,
correctly scoped candidate. Do not fabricate a recovery receipt or merge this
PR as a workaround for missing workflow evidence.

## Remote lock evidence

The guarded Actions execution on 2026-10-26 generated `composer.lock` with
`voku/agent-loop` **0.20.70**, source commit
`d5e77d400ebd7bdbd8e5fe875a2e894e2b99f70e`, and confirmed that the
installed `pipeline recover` command is available. These statements concern
the published *consumer dependency* only. They are not a PRA-2 candidate
recovery or review receipt. The follow-up exact-head bootstrap job must still
pass before this change can be considered ready for independent review.
