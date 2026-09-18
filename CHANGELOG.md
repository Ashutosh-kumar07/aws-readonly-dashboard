# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-09-18

### Fixed

- **Analyze failed on Windows with "Cannot use both a positional prompt and the
  --prompt (-p) flag together".** 1.1.0 launched the Gemini CLI through a shell so
  that Windows `.cmd` shims would run, and Node does not quote arguments when it
  does that — it joins them with spaces, so `['-p', 'Follow the instructions…']`
  arrived as a flag plus five positional arguments. The shell is gone: a Windows
  shim is now launched through `cmd.exe /d /s /c` with a command line the dashboard
  builds and quotes itself. Detection was unaffected because `--version` takes no
  arguments, which is why the CLI showed as *Available* and only Analyze failed.
- An argument containing something Windows command processing would reinterpret
  (`%`, `!`, a line break) is refused with an explanation rather than mangled.
- **"Unable to evaluate — unexpected error" hid the reason.** Error classification
  preferred `error.name`, which is the useless string `Error` for every plain Node
  failure, so the specific code beside it was never read. A proxy's TLS
  interception, a refused connection and an unreachable host all landed in
  "unexpected". They are now reported as **network or TLS failure**, naming the
  code and pointing out that the AWS CLI reads `HTTPS_PROXY` automatically while
  the AWS SDK for JavaScript does not.
- A refusal by the read-only access layer (for example an API category disabled in
  configuration) is reported as such instead of as an unexpected error.

### Added

- **Every "unable to evaluate" row now shows the underlying message**, in both the
  security table and the section notices. The cause was always in the payload and
  never on the screen, which left "unexpected error" impossible to act on.
- **One-click coverage.** The notice that reports partial coverage now carries the
  action it was describing — *Inspect every function*, *Inspect all N buckets* —
  which raises the limit and rescans. Progressive loading means the longer scan
  shows its results as it goes.

### Changed

- `security.maxLambdaPolicyLookupsPerRegion: 0` now means **no limit** rather than
  "switch the check off"; disabling a check belongs in the check list, where it
  already lived. A configuration migration moves the old intent across: a stored `0`
  disables `lambda-public-resource-policy` and restores the default limit, so nobody
  who meant "off" gets a full scan of every function in every region.
- Settings copy for the scan limits updated to match.

## [1.1.0] - 2026-09-18

### Added

- **Progressive loading for slow sections.** Billing, security, CloudWatch and
  Compute Optimizer now run as cancellable jobs that report partial results. The
  first findings appear as soon as they exist instead of after the whole scan, with
  a progress bar showing a real position (`12 / 22`) and the check or profile
  currently running.
- **"Still scanning — these results are incomplete" banner**, so a partial view can
  never be mistaken for a finished one.
- Job API: `stream: true` on the section routes, `GET /api/jobs/:id` to poll, and
  `DELETE /api/jobs/:id` to cancel. Cancellation is honoured by the work itself:
  the scan stops at the next check boundary, makes no further AWS calls, and the
  half-finished result is neither cached nor shown as complete. Identical in-flight
  requests are de-duplicated rather than starting a second scan.
- **"Gemini CLI: Not authenticated"** as a distinct startup state, separate from
  Non-LLM mode: an installed-but-unauthenticated CLI is a different problem with a
  different fix, and is now reported as such.
- `src/ai/providers/command-resolver.ts`: cross-platform executable resolution with
  `PATH`/`PATHEXT` lookup, an explicit refusal for commands containing shell
  metacharacters, and `ENOENT`/`EACCES`-specific guidance.
- Dependabot configuration for GitHub Actions and npm dependencies.
- 55 new tests (310 total), covering the job runner, cancellation, Gemini CLI
  detection and the S3 region and permission-reporting fixes, including Windows
  `.cmd` resolution and an oversized-prompt argument-length check.

### Fixed

- **Gemini CLI was reported as unavailable on Windows.** The CLI installs as
  `gemini.cmd`, which Node cannot execute directly, so the capability probe failed
  with `ENOENT` even when the CLI was installed and working. The command is now
  resolved against `PATH`/`PATHEXT` and a shell is used only when the resolved
  target genuinely requires one.
- The Gemini provider now runs headlessly and deterministically: the instruction is
  passed with `-p` while the payload stays on standard input, which keeps a large
  payload clear of the Windows 8191-character command-line limit.
- A spawn failure is now distinguishable from a command that ran and failed, so
  "not installed" is no longer conflated with "returned an error".
- Section progress could display a nonsensical ratio (`23 / 1`) when per-check and
  per-profile units were summed. Progress is now an absolute position aggregated per
  profile.
- **S3 checks reported timeouts as missing permissions.** A timed-out request was
  labelled "needs `s3:GetBucketLocation`" — the classifier read the IAM-shaped
  `service:Operation` out of the dashboard's own timeout message. A missing action is
  now only reported when AWS says the failure was about permissions, and the internal
  message no longer looks like an IAM action.
- **A timed-out request is now cancelled, not abandoned.** The deadline raced a timer
  and left the HTTP request running, so the socket stayed checked out of the SDK's
  connection pool (50 per client). Enough abandoned requests and every later call
  waited for a free socket and timed out too — one slow endpoint became a
  section-wide outbreak of timeouts that read as a permissions problem. Verified
  against the real SDK: the socket is released the moment the deadline passes.
- A timeout is retried once rather than once per configured retry, so one slow call
  costs seconds rather than minutes.
- **S3's legacy location values are translated.** `GetBucketLocation` answers `EU`
  for older buckets, which was passed straight to a client and built the unroutable
  endpoint `s3.EU.amazonaws.com`. `EU`, `US` and the empty value now map to real
  regions, and an unrecognised value is reported rather than guessed.
- A bucket whose region cannot be resolved is no longer queried in a guessed region.
  Four further calls to the wrong endpoint produced four more failures, each unrelated
  to the bucket's exposure and each displayed as its own permission gap.
- **A failed read can no longer become a finding.** When `GetPublicAccessBlock`
  failed, the bucket was reported as "does not have full Block Public Access" — a
  claim about a setting the dashboard had not managed to read. Findings now require
  the reads they rest on; anything else is reported as partially evaluated, naming
  the buckets and the reason.
- A cross-region S3 answer (`PermanentRedirect`) is classified as a region mismatch
  instead of an unexpected error.

### Changed

- The release workflow tags the published commit and creates the GitHub release,
  extracting the notes from this file, so a release is one dispatch rather than a
  manual tag plus a manual release.
- Release workflow requests npm provenance only where it is available, and skips a
  version that is already on the registry instead of failing the run.
- Documentation: a Progressive loading section, the three Gemini states, Windows
  Gemini troubleshooting, and two new project invariants in CONTRIBUTING.

## [1.0.0] - 2026-09-17

First public release.

### Added

**AWS read-only architecture**

- Centralised AWS access layer that every AWS call must pass through.
- Three independent read-only barriers: a mutating-verb denylist, a read-verb
  allowlist, and a per-service compile-time operation allowlist.
- Deep-frozen allowlist that no configuration, environment variable or UI action can
  widen; configuration can only narrow which categories are called.
- Session-scoped AWS API call tracker integrated into the same choke point, with a
  UI breakdown by category, operation, profile, account, region and triggering action,
  separating expected "not found" answers from genuine failures.

**Credentials and scope**

- Profile discovery for AWS CLI profiles, SSO / IAM Identity Center profiles,
  assume-role profiles, `credential_process` profiles and environment credentials.
- Two-phase validation: no AWS calls during discovery, one `sts:GetCallerIdentity`
  per profile when selected.
- Multi-profile analysis with per-profile sections and preserved account context.
- Region selection with Select All / Clear All, persisted locally; global resources
  always handled separately from regional selection.

**Analysis**

- Billing: daily, weekly and monthly charts; service and region breakdowns; rolling
  comparison over 1/7/14/30/60/90 days (default 7); configurable dollar and
  percentage thresholds (default `$20` / `10%`); increase, decrease, new-cost and
  removed-cost classification.
- Security analyzer with independent modules for Security Hub, GuardDuty, Inspector,
  IAM Access Analyzer, Trusted Advisor, AWS Config, CloudTrail configuration, S3
  public access, Lambda VPC and resource policy, security groups open to the
  internet, and IAM account hygiene.
- Finding severity (critical/high/medium/low), status workflow (open, acknowledged,
  ignored, resolved) with local persistence, and automatic resolution of findings
  that are no longer detected.
- Explicit "unable to evaluate" reporting, including the missing IAM action where
  AWS provides it — a failed check is never reported as a pass.
- Explicit "partially evaluated" reporting when a scan limit stops a check from
  inspecting the whole inventory, with configurable limits for Lambda policy
  lookups, S3 buckets and CloudWatch log groups.
- Compute Optimizer recommendations for EC2, Auto Scaling groups, EBS, Lambda, ECS,
  RDS and idle resources, using only AWS-provided estimates.
- CloudWatch log-group analysis: largest groups, rapid growth measured from the
  `IncomingBytes` metric with both percentage and absolute thresholds (default 5% /
  2 GB), missing retention and configurable long retention.
- CloudTrail search across profiles and regions with filtering by time, region, event
  name, service, IAM identity, resource, source IP, read/write type, outcome and free
  text, plus UI pagination and per-event selection.

**AI**

- Gemini CLI provider using the user's existing CLI authentication, with a startup
  capability probe and an explicit Non-LLM mode when it is unavailable.
- Configurable custom LLM REST provider (URL, method, headers, body template,
  response path) for internal gateways, with an explicit data-egress acknowledgement.
- AI invoked only from explicit user actions; per-section analysis and cross-section
  "Analyze Selected Data".
- Data minimisation: compact, aggregated section payloads rather than raw AWS data.
- PII sanitization and consistent pseudonymization, with a payload preview, a local
  placeholder decoder, user-configurable rules and always-on credential protection.
- Versioned prompts, structured response schema and response validation before
  rendering.
- Optional AI history (off by default, 7-day default retention, 30-day maximum)
  storing only sanitized requests and responses, with profile isolation and deletion.

**Application**

- CLI with `--port`, `--host`, `--profile`, `--region`, `--no-open`, `--config-dir`
  and `--log-level`, defaulting to port 9001 and automatically selecting the next
  free port.
- Loopback-bound local server serving a dependency-free ES module dashboard with
  loading, empty, error and permission states for every view.
- Local JSON configuration with schema versioning, migrations, atomic writes,
  owner-only permissions, and Delete All Local Configuration.
- 255 automated tests covering AWS safety, credentials, billing, security,
  CloudWatch, CloudTrail, AI behaviour and local configuration.

[1.2.0]: https://github.com/Ashutosh-kumar07/aws-readonly-dashboard/releases/tag/v1.2.0
[1.1.0]: https://github.com/Ashutosh-kumar07/aws-readonly-dashboard/releases/tag/v1.1.0
[1.0.0]: https://github.com/Ashutosh-kumar07/aws-readonly-dashboard/releases/tag/v1.0.0
