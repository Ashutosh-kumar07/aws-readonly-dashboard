# Contributing to aws-readonly-dashboard

Thanks for your interest. This document covers how to get set up, what the project's
non-negotiable invariants are, and what a good pull request looks like.

## Getting started

```bash
git clone https://github.com/Ashutosh-kumar07/aws-readonly-dashboard.git
cd aws-readonly-dashboard
npm install
npm run verify   # lint + typecheck + test + build
npm run dev      # run the dashboard from source
```

Node.js 18.17 or newer is required. No AWS account is needed to develop or to run
the tests: every test uses injected fake AWS clients and never touches the network.

## Project invariants

These are the properties the project exists to guarantee. A change that weakens one
will not be merged, however convenient it is.

1. **The application cannot modify AWS.** Every AWS call goes through
   `AwsAccessLayer`. No module may construct an SDK client and call `send` directly.
   New operations must be added to `src/aws/allowlist.ts`, must be genuinely
   read-only, and must be accompanied by tests.
2. **Configuration can only narrow AWS access, never widen it.** There must be no
   code path by which a file, environment variable, CLI flag or UI action adds an
   operation to the allowlist.
3. **A failed check is never reported as a pass.** When a check cannot run, it must
   surface as "unable to evaluate", with the missing permission where AWS tells us
   what it was.
4. **AI is never automatic.** AI may only be invoked from an explicit user action.
   If you add a new AI capability, add a test proving it does not fire on load,
   refresh or navigation.
5. **Nothing reaches an AI provider unsanitized.** All AI payloads pass through
   `src/ai/sanitizer.ts`. Do not add a provider path that bypasses it.
6. **Raw AWS data is never persisted.** AWS responses live in memory for the server
   session. Only user preferences, finding decisions and sanitized AI history are
   written to disk.
7. **No invented data.** If AWS does not provide a figure (a savings estimate, a
   performance risk), show that it was not provided rather than estimating one.
8. **Partial results are labelled as partial.** A view that is still loading must
   say so — progress and the "still scanning" banner exist so an incomplete scan is
   never mistaken for a finished one. Progress counts must be real positions
   reported by the work itself, never interpolated or estimated.
9. **External commands are resolved and quoted, never guessed.** Anything spawned as
   a child process goes through `src/ai/providers/command-resolver.ts`, which
   resolves the executable against `PATH`/`PATHEXT` and builds the `cmd.exe`
   command line itself for Windows shims (`.cmd`/`.bat`), quoting every argument.
   **Never pass `shell: true` to `spawn`.** It does not quote: Node joins the
   arguments with spaces, so `['-p', 'two words']` reaches the program as a flag
   plus two positional arguments.

10. **Listings are paged, and a partial listing is still a result.** Never ask an AWS
    list API for an unbounded inventory: pass an explicit page size and follow the
    continuation token, stopping when the configured limit is reached. If a later
    page fails, evaluate what was listed and report the rest as partially
    evaluated — the alternative is an all-or-nothing failure that leaves the user
    with nothing.

11. **An AWS SDK command object is single-use.** Sending a command applies its
    middleware plugins to its own stack, and applying them twice is refused — the
    S3 Control client throws `Duplicate middleware name`. The access layer builds a
    fresh command for every retry; never re-send an instance.

## Testing against the real SDK

`tests/s3-scenarios.test.ts` drives the real `S3Client` and `S3ControlClient`
through the access layer with a stubbed transport: real commands, real middleware,
real response parsing, scripted HTTP answers. The hand-written `FakeClient` used
elsewhere never builds a middleware stack, so it cannot catch a fault in how this
package uses the SDK — the duplicate-middleware bug lived behind exactly that gap.
Anything touching retries, endpoints, pagination or response parsing needs a test
at this level, not only a fixture one.

## Long-running sections

Sections that can take more than a few seconds stream their results:

1. The service accepts an `onProgress` / `onPartial` callback and calls it as each
   unit of work completes, passing an **absolute** position (`completed`, `total`)
   and a label — never a delta.
2. `src/server/routes.ts` wraps the fetch in `jobs.start(...)` from
   `src/server/job-runner.ts` when the request asks for `stream: true`.
3. The browser polls `GET /api/jobs/<id>` and renders each snapshot.

Units from different levels (per-check and per-profile) must be aggregated, not
summed — see the `unitProgress` map in `src/server/dashboard-service.ts` for why.
Add a job-runner test for any new streaming path.

## Adding a security check

Each check is a self-contained module:

1. Create `src/services/security/checks/<name>.ts` exporting a `SecurityCheck`.
2. Give it an `id`, `title`, `service`, `scope`, `description` and
   `requiredPermissions`.
3. Return `evaluated: true` only when the check actually ran to completion. On a
   permission or availability failure, return issues and `evaluated: false`.
4. Every finding needs evidence taken from the AWS response, a plain-language "why
   this matters", and a recommendation phrased as something a human does in AWS.
5. Register it in `src/services/security/registry.ts`.
6. Add tests: at least one finding case and one "cannot evaluate" case.

## Adding an AWS operation

1. Add the entry to `src/aws/allowlist.ts` with its category and IAM action.
2. Confirm it is read-only. If the operation name does not start with a read verb,
   it does not belong here.
3. The allowlist tests will automatically assert the new entry is read-only and
   correctly shaped.
4. Update the README's permission reference if it changes the required policy.

## Frontend

`public/` is dependency-free ES modules with no build step. Please keep it that way:
no framework, no bundler, no third-party runtime code. Match the existing patterns
in `public/js/ui.js`, keep the UI accessible (labels, roles, keyboard reachability),
and make sure every data view has loading, empty, error and permission states.

## Tests

```bash
npm test                # full suite
npm run test:watch      # watch mode
npm run test:coverage   # with coverage
```

Use `tests/helpers.ts` (`FakeClient`, `makeCommand`, `awsError`, `withTempDir`) so
tests stay hermetic. Tests must never make a real AWS, network or AI call.

## Commit and pull request style

- Keep commits focused; use a short imperative subject line
  (`fix: report Config recorder failures as unevaluated`).
- User-visible changes need a CHANGELOG entry under `## [Unreleased]`; the release
  workflow publishes that section verbatim as the GitHub release notes.
- Run `npm run verify` before pushing.
- In the PR description, say what changed, why, and how you tested it. If the change
  touches AWS access, sanitization or AI invocation, say explicitly which invariant
  you checked and how.
- New behaviour needs new tests.

## Review requirements

`main` is protected. Every change reaches it through a pull request that must:

- pass CI (lint, formatting, type check, the full test suite and the packaging
  checks, on Node 18.17, 20 and 22), and
- carry an approving review from a code owner (see `.github/CODEOWNERS`).

Pull requests from forks do not run workflows until a maintainer approves the
run, so a first-time contributor should expect a short wait before CI reports.

## Reporting bugs

Open an issue with your OS and Node version, the package version, the exact command
you ran, and what you expected versus what happened. Redact account IDs, ARNs, bucket
names and any other identifying data — a redacted report is always enough.

Security vulnerabilities go through the private process in [SECURITY.md](./SECURITY.md),
not the public issue tracker.
