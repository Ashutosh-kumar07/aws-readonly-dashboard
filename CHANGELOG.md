# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/Ashutosh-kumar07/aws-readonly-dashboard/releases/tag/v1.0.0
