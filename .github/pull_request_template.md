## What changed

<!-- A short description of the change and why it is needed. -->

## How it was tested

<!-- Commands you ran, and anything you verified manually. -->

- [ ] `npm run verify` passes (lint, type check, tests, build)
- [ ] New behaviour is covered by tests

## Invariants

Tick the ones this change touches, and say how you verified them.

- [ ] **AWS stays read-only** — no new mutating call path; any new operation was
      added to `src/aws/allowlist.ts` and is genuinely read-only
- [ ] **Configuration cannot widen AWS access** — no new path from config/env/UI to
      the allowlist
- [ ] **Failed checks are not reported as passes** — permission and availability
      failures still surface as "unable to evaluate"
- [ ] **AI is never automatic** — no new code path invokes AI without an explicit
      user action
- [ ] **Nothing reaches AI unsanitized** — all payloads still pass through the
      sanitizer
- [ ] **Raw AWS data is not persisted**
- [ ] None of the above apply

## Notes for reviewers

<!-- Anything you want a reviewer to look at closely. -->
