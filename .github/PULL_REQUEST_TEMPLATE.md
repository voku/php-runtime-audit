## Summary

<!-- What does this change, and why? -->

## Test plan

- [ ] `composer test` passes locally
- [ ] `composer analyse` (PHPStan max level) passes locally
- [ ] `composer format-check` passes locally
- [ ] New/changed behavior has test coverage for both the happy path and hostile/missing/ambiguous input
- [ ] If this touches the real-worker collector: ran `bash tests/fixtures/runtime/run-disposable-runtime-checks.sh` (or explain why not applicable)

## Security checklist

- [ ] No new shell interpolation from untrusted/remote input
- [ ] No new automatic remediation (every remediation proposal still requires explicit human approval)
- [ ] Uncertain or conflicting evidence still resolves to `unknown` / `needs_investigation`, never a guessed fix
- [ ] A new advisory, if any, was added as data in `resources/advisories/`, not hardcoded into the evaluator
