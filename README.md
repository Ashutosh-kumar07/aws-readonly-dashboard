# aws-readonly-dashboard

> A local, strictly read-only AWS dashboard for cost, security, observability and
> optimisation — with optional, explicitly triggered AI insights.

[![CI](https://github.com/Ashutosh-kumar07/aws-readonly-dashboard/actions/workflows/ci.yml/badge.svg)](https://github.com/Ashutosh-kumar07/aws-readonly-dashboard/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/aws-readonly-dashboard.svg)](https://www.npmjs.com/package/aws-readonly-dashboard)
[![node](https://img.shields.io/node/v/aws-readonly-dashboard.svg)](https://nodejs.org)
[![license](https://img.shields.io/npm/l/aws-readonly-dashboard.svg)](./LICENSE)

`aws-readonly-dashboard` starts a small server on your machine and opens a browser
dashboard that inspects your AWS accounts using your existing AWS credentials. It
shows what you are spending, where your security posture is weak, what AWS itself
recommends you resize, which log groups are quietly growing, and what happened in
CloudTrail — and it can hand a sanitized summary of any of that to an AI provider
when, and only when, you ask it to.

It **cannot change anything in AWS**. That is enforced in the architecture, not in
the UI: every AWS call passes through one access layer that refuses any operation
outside a compile-time read-only allowlist.

```
┌──────────┐   ┌──────────────┐   ┌─────────────────┐   ┌──────────────────┐
│ Dashboard│──▶│ AWS Access   │──▶│ Read-only       │──▶│ API call tracker │──▶ AWS SDK ──▶ AWS
│  / API   │   │ Layer        │   │ enforcement     │   │                  │
└──────────┘   └──────────────┘   └─────────────────┘   └──────────────────┘
```

---

## Contents

- [Quick start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Progressive loading](#progressive-loading)
- [AWS permissions](#aws-permissions)
- [The read-only guarantee](#the-read-only-guarantee)
- [AWS API usage accounting](#aws-api-usage-accounting)
- [Configuration](#configuration)
- [AI insights](#ai-insights)
- [Privacy](#privacy)
- [Security](#security)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## Quick start

```bash
npx aws-readonly-dashboard
```

```
AWS Read-Only Dashboard
Starting local server...
Port: 9001
AWS profiles discovered: 4
Gemini CLI: Available
AWS access: read-only (mutating API calls are refused by design)
Dashboard: http://127.0.0.1:9001
```

If port 9001 is busy, the next free port is used automatically — you never have to
kill another process to start the dashboard:

```
Port 9001 is occupied.
Using port 9002.
Dashboard: http://127.0.0.1:9002
```

---

## Features

**AWS access**

- **Strict read-only architecture** — a single access layer, three independent
  enforcement barriers, and a frozen operation allowlist that no setting, file or
  environment variable can widen.
- **AWS profile discovery** — AWS CLI profiles, SSO / IAM Identity Center profiles,
  assume-role profiles, `credential_process` profiles and environment credentials
  are all discovered from your local configuration.
- **Multi-profile support** — select several profiles and see each account in its
  own clearly labelled section. Profile and account context travels with every row.
- **Region selection** — checkbox selection with Select All / Clear All, persisted
  locally. Global resources (IAM, the S3 bucket inventory, Cost Explorer, Trusted
  Advisor) are always handled separately and never mislabelled as regional.
- **AWS API-call accounting** — a live counter of the AWS calls this tool makes,
  with a drill-down by category, operation, profile, account, region and the
  dashboard action that caused each call.

**Analysis**

- **Billing / cost** — daily, weekly and monthly charts; service and region
  breakdowns; rolling period comparison (1/7/14/30/60/90 days, default 7);
  configurable dollar and percentage thresholds (default `$20` / `10%`); explicit
  classification of increases, decreases, new costs and removed costs.
- **Security** — a modular analyzer covering Security Hub, GuardDuty, Inspector,
  IAM Access Analyzer, Trusted Advisor, AWS Config, CloudTrail configuration,
  public S3 buckets, Lambda VPC and policy exposure, security groups open to the
  internet, and IAM account hygiene. Findings carry severity, status, evidence,
  reasoning and a manual recommendation. Where a check inspects only part of a
  large inventory, it says so rather than implying full coverage.
- **Compute Optimizer** — EC2, Auto Scaling, EBS, Lambda, ECS, RDS and idle-resource
  recommendations, showing only the figures AWS itself provides.
- **CloudWatch** — largest log groups, rapid growth (percentage *and* absolute
  thresholds), missing retention and long retention.
- **CloudTrail** — a dynamic search over time, region, event name, service, IAM
  identity, resource, source IP, read/write type, outcome and free text, with UI
  pagination over large result sets.

**Dashboard**

- **Progressive loading** — sections that take a while (security especially) render
  their first results as soon as they exist and keep filling in, with a progress bar
  and an explicit "these results are incomplete" banner, instead of showing a blank
  spinner until everything has finished.

**AI (optional)**

- **Gemini CLI** as the default provider, reusing your existing Gemini
  authentication. The header reports one of three honest states — *Available*,
  *Not authenticated*, or **Non-LLM mode** — and never guesses which one applies.
- **Custom LLM REST endpoint** for teams with an internal gateway — you define the
  URL, method, headers, body template and response path.
- **Never automatic** — AI runs only when you press an Analyze button.
- **Data minimisation** — only the sections you select, compacted and aggregated.
- **PII sanitization and pseudonymization** before anything leaves the machine.
- **AI history**, off by default, storing only sanitized requests and responses.

---

## Installation

Global install:

```bash
npm install -g aws-readonly-dashboard
aws-readonly-dashboard
```

One-off, no install:

```bash
npx aws-readonly-dashboard
```

Requires **Node.js 18.17 or newer**.

---

## Usage

```
Usage:
  aws-readonly-dashboard [options]

Options:
  -p, --port <number>      Preferred port (default: 9001). If busy, the next free
                           port is used automatically.
      --host <address>     Interface to bind (default: 127.0.0.1). Binding to a
                           non-loopback address exposes the dashboard on your network.
      --profile <name>     Pre-select an AWS profile for this session.
      --region <list>      Pre-select regions for this session (comma separated).
      --no-open            Do not open a browser automatically.
      --config-dir <path>  Directory for local configuration
                           (default: ~/.aws-readonly-dashboard).
      --log-level <level>  debug | info | warn | error | silent (default: info).
  -v, --version            Print the version and exit.
  -h, --help               Print help and exit.
```

Examples:

```bash
aws-readonly-dashboard
aws-readonly-dashboard --port 8080 --profile prd --region us-east-1,eu-west-1
aws-readonly-dashboard --no-open --log-level debug
```

### Workflow

1. Start the dashboard; it opens in your browser.
2. Pick one or more **profiles** in the header. Each selected profile is validated
   with a single `sts:GetCallerIdentity` call.
3. Pick your **regions**. Global resources are always included separately.
4. Open a section. Opening it fetches that section's AWS data; returning to it
   reuses what is already in memory. Each section has its own **Refresh**, and the
   header has **Refresh All**. Sections that take more than a moment stream partial
   results as they arrive — see [Progressive loading](#progressive-loading).
5. Optionally press an **Analyze** button to send that section — sanitized — to your
   configured AI provider.

---

## Progressive loading

A full security scan across several profiles and a dozen regions is hundreds of AWS
calls. Waiting for all of them before drawing anything means staring at a spinner
long past the ten seconds that is generally accepted as the limit of a user's
attention, with no way to tell a slow scan from a stuck one.

Billing, security, CloudWatch and Compute Optimizer therefore load as *jobs*. The
browser starts the job, then polls it, and every poll returns whatever the scan has
produced so far:

```
POST   /api/sections/security  { "stream": true }
         -> { id, section, status: "running", progress, partial }
GET    /api/jobs/<id>
         -> { status, progress: { completed, total, label }, partial }
DELETE /api/jobs/<id>
         -> { cancelled: true }
```

What you see while a section is still working:

- the findings, rows and charts that already exist, rendered normally;
- a progress bar with a real count (`12 / 22`) and the name of the check or profile
  currently running;
- a **"Still scanning — these results are incomplete"** banner, so a partial view is
  never mistaken for a finished one.

The progress count is a true position, not an estimate: each check reports its own
completion and per-profile units are aggregated rather than summed into a
meaningless ratio. Identical requests are de-duplicated, so asking for the same
section again while a scan is in flight attaches to the running job instead of
starting a second one. `DELETE /api/jobs/<id>` stops a job at the next unit
boundary; no AWS calls are made after that point.

This is presentation only. It changes nothing about which AWS calls are made, the
read-only guarantee, or the API-call accounting — a partial render costs exactly the
calls it reports in **AWS API Usage**.

---

## AWS permissions

The dashboard needs read permissions only. Nothing in the allowlist can modify AWS,
and a policy granting write permissions would not enable any new behaviour: the
application would still refuse to call those APIs.

<details>
<summary>Least-privilege read-only policy for the full feature set</summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AwsReadOnlyDashboard",
      "Effect": "Allow",
      "Action": [
        "access-analyzer:GetFinding",
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings",
        "access-analyzer:ListFindingsV2",
        "ce:GetCostAndUsage",
        "ce:GetCostCategories",
        "ce:GetDimensionValues",
        "ce:GetTags",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:ListTrails",
        "cloudtrail:LookupEvents",
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "compute-optimizer:GetAutoScalingGroupRecommendations",
        "compute-optimizer:GetEBSVolumeRecommendations",
        "compute-optimizer:GetEC2InstanceRecommendations",
        "compute-optimizer:GetECSServiceRecommendations",
        "compute-optimizer:GetEnrollmentStatus",
        "compute-optimizer:GetIdleRecommendations",
        "compute-optimizer:GetLambdaFunctionRecommendations",
        "compute-optimizer:GetRDSDatabaseRecommendations",
        "compute-optimizer:GetRecommendationSummaries",
        "config:DescribeComplianceByConfigRule",
        "config:DescribeConfigRules",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeConfigurationRecorders",
        "config:DescribeDeliveryChannels",
        "config:GetComplianceDetailsByConfigRule",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroupRules",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "guardduty:GetDetector",
        "guardduty:GetFindings",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "iam:GetAccessKeyLastUsed",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "iam:ListMFADevices",
        "iam:ListRoles",
        "iam:ListUserPolicies",
        "iam:ListUsers",
        "inspector2:BatchGetAccountStatus",
        "inspector2:ListCoverage",
        "inspector2:ListFindings",
        "lambda:GetFunctionConfiguration",
        "lambda:GetPolicy",
        "lambda:ListFunctionUrlConfigs",
        "lambda:ListFunctions",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:ListTagsForResource",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:ListAllMyBuckets",
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "securityhub:GetFindings",
        "sts:GetCallerIdentity",
        "support:DescribeTrustedAdvisorCheckResult",
        "support:DescribeTrustedAdvisorCheckSummaries",
        "support:DescribeTrustedAdvisorChecks"
      ],
      "Resource": "*"
    }
  ]
}
```

</details>

You do not need all of these. Every check degrades independently: if a permission is
missing, that check reports **“Unable to evaluate — insufficient permissions”**, and
where AWS tells us which action was missing, the dashboard names it. A missing
permission is never reported as “secure” or “no findings”.

The AWS managed policies `ReadOnlyAccess` or `SecurityAudit` (plus `ce:*` read
actions for billing, and a Business/Enterprise support plan for Trusted Advisor)
also work.

Notable requirements:

- **Cost Explorer** must be enabled in the payer account, and `ce:GetCostAndUsage`
  charges per request — see [AWS API usage accounting](#aws-api-usage-accounting).
- **Trusted Advisor** via the Support API requires a Business, Enterprise On-Ramp or
  Enterprise support plan.
- **Compute Optimizer**, **Security Hub**, **GuardDuty**, **Inspector**, **Access
  Analyzer** and **AWS Config** must be enabled per account/region to return data.
  When they are not, the dashboard says so rather than implying a clean result.

---

## The read-only guarantee

This is the central design property of the package.

**Every** AWS call is made through `AwsAccessLayer` (`src/aws/access-layer.ts`). No
service module holds an SDK client directly. Before a request is dispatched, three
independent barriers are applied in `src/aws/readonly-guard.ts`:

1. **Mutating-verb denylist** — an operation beginning with `Create`, `Delete`,
   `Update`, `Put`, `Modify`, `Attach`, `Invoke`, `Start`, `Stop`, `Terminate`,
   `Authorize`, `Revoke`, … is refused outright.
2. **Read-verb allowlist** — the operation must begin with a recognised read verb
   (`Get`, `List`, `Describe`, `Lookup`, `Search`, `Filter`, `BatchGet`, …).
3. **Operation allowlist** — the operation must appear in the compile-time allowlist
   for that specific AWS service (`src/aws/allowlist.ts`).

The allowlist is a constant that is deep-frozen at module load. It is never read
from disk, never merged with user configuration, and never mutated at runtime. You
may *narrow* what the dashboard calls by disabling API categories in Settings; there
is no code path by which any configuration file, environment variable or UI action
can add an operation.

If enforcement refuses an operation, the request is rejected **before** an SDK call
is constructed — so a refused mutation is not even counted as an AWS call.

You can see the full allowlist in the running dashboard under **Settings → AWS
read-only guarantee → Show the allowlist**, or via `GET /api/permissions`.

The test suite asserts this directly: write operations across every service are
rejected, the allowlist cannot be widened at runtime, and a hand-edited
configuration cannot bypass enforcement.

---

## AWS API usage accounting

The header shows a live count:

```
AWS API Calls: 1,248
```

Click it to open **AWS API Usage**, which breaks the total down by category —
Billing / Cost Explorer, Security Hub, GuardDuty, Inspector, IAM, S3, Lambda,
Security Groups, CloudWatch, CloudTrail, Compute Optimizer, AWS Config, Trusted
Advisor, IAM Access Analyzer — and lists recent calls with their AWS service and
operation, profile, account, region, duration, outcome, and the dashboard action
that caused them.

Why it exists: some AWS read APIs are billed (Cost Explorer requests, for example)
and all of them consume request quota. This counter lets you see exactly how much
AWS activity the dashboard itself generates, rather than guessing.

The tracker sits inside the same access layer as read-only enforcement, so every AWS
request is both enforced and counted. Statistics are session based and reset when
the server restarts, because raw AWS data is never persisted.

AI provider calls are **not** AWS API calls and are deliberately excluded from this
counter.

---

## Configuration

Configuration lives in a small set of JSON files (no SQLite, nothing hidden) under
`~/.aws-readonly-dashboard`, or wherever `--config-dir` / `AWS_READONLY_DASHBOARD_HOME`
points:

| File | Contents |
| --- | --- |
| `config.json` | Selected profiles and regions, thresholds, filters, UI and CloudWatch preferences, AI provider configuration, sanitization rules, AI history settings |
| `security-findings.json` | Your decisions about findings (acknowledged / ignored / resolved) plus the minimum finding identity needed to keep them filterable |
| `ai-history.json` | Sanitized AI history — only when you enable it |

Files are written atomically (temp file + rename) with owner-only permissions
(`0600`, directory `0700`), and carry a schema version so future releases can migrate
them safely. A configuration file that is corrupt, hand-edited into an invalid shape,
or contains out-of-range values is normalised rather than trusted: unknown keys are
dropped, numbers are clamped, and sanitization rules that protect credentials are
restored.

**AWS data is never written to disk.** It lives in memory for the lifetime of the
server process.

**Settings → Local data → Delete All Local Configuration** removes every file above
and resets the application to defaults.

---

## AI insights

### Gemini CLI (default)

At startup the dashboard checks whether the [Gemini CLI](https://github.com/google-gemini/gemini-cli)
is available by running `gemini --version`. That is a capability probe, not an AI
call — no prompt and no data leave your machine.

The header reports one of three states, and they mean different things:

| State | Meaning | What to do |
| --- | --- | --- |
| **Gemini CLI: Available** | The CLI was found and ran. | Nothing. |
| **Gemini CLI: Not authenticated** | The CLI is installed and runs, but has no usable credentials. | Run `gemini` once and sign in, or set `GEMINI_API_KEY`. |
| **Non-LLM mode** | No CLI was found on `PATH` (or the configured command could not be executed). | Install it, point Settings at the right command, or use a custom endpoint. |

"Installed but not signed in" is deliberately *not* collapsed into "not installed" —
the fix is different, so the message is different. The probe reports why it failed,
including the specific `ENOENT` / `EACCES` cases, rather than a generic failure.

The dashboard does not install Gemini, does not call it on your behalf, and does not
silently switch to another provider. In Non-LLM mode every AWS feature still works,
and you can still preview exactly what *would* be sent.

**Windows.** The CLI installs as `gemini.cmd`, and Node cannot execute a `.cmd` or
`.bat` file directly. The dashboard resolves the command against `PATH` and
`PATHEXT` and only then decides whether a shell is required, so `gemini` works on
Windows exactly as it does on macOS and Linux. Because a shell is involved in that
case, a configured command containing shell metacharacters is refused rather than
executed — configure the plain path to the executable and use Settings for
arguments.

Authentication is entirely the CLI's: the dashboard invokes it as a child process
and inherits your existing session. **No Gemini credentials or API keys are stored
by this application.** The prompt is written to the CLI's standard input, never onto
a command line — that keeps it out of your shell history and process list, and it
also means a large payload cannot hit the Windows 8191-character command-line
limit.

### Custom LLM REST endpoint

For teams with an internal LLM gateway, **Settings → Custom LLM REST endpoint** lets
you configure:

- endpoint URL and HTTP method
- arbitrary headers (including authentication headers)
- a request body template, using `{{prompt}}` (the sanitized prompt as a JSON string)
  and `{{payload}}` (the sanitized payload as raw JSON)
- a response path such as `choices.0.message.content`, for APIs that wrap the text
- enable / disable, independent of Gemini

Because the template is yours, the provider works with APIs that are not
OpenAI- or Gemini-compatible.

> **The endpoint you configure receives the sanitized, pseudonymised payload.** You
> are responsible for trusting it. The dashboard will not send anything until you
> configure the endpoint, enable it, tick the acknowledgement, and press an Analyze
> button.

### AI calls are never automatic

AI is never invoked during startup, data loading, section loading, refresh, Refresh
All, CloudTrail search, security scanning, billing retrieval, background polling or
page navigation. It runs only on an explicit action:

- **Analyze Billing**, **Analyze Security**, **Analyze CloudWatch**,
  **Analyze CloudTrail**, **Analyze Compute Optimizer**
- **Analyze Selected Data** — pick several sections and let the model look for
  relationships between them (for example, a cost increase that lines up with a
  change visible in CloudTrail). The model is instructed not to assert causation
  that the evidence does not support.

In CloudTrail you can tick individual events and send only those.

### Grounding

Prompts are versioned (`src/ai/prompts.ts`) and instruct the model to use only the
supplied evidence, to quote the evidence behind every finding, to treat
“not evaluated” entries as unknown rather than healthy, and to state its limitations.
Responses are requested as structured JSON and validated before anything is
rendered; severities are constrained to `critical | high | medium | low`. When AI
analysis is requested, the model's severity replaces the dashboard's own.

If a response is malformed, the dashboard shows a clear error and keeps your AWS
data and dashboard state intact. It never fabricates a response and never silently
retries against a different provider.

### AI history

Off by default. When enabled:

- default retention 7 days, maximum 30, configurable
- stored as JSON, and expired entries are removed automatically
- **only** the sanitized prompt, the sanitized payload, the provider response,
  timestamp, profiles, regions and selected sections are stored — never raw AWS data,
  and never the placeholder→value mapping
- the UI states clearly that history is enabled and may be used for future analyses
- relevant history is scoped by profile: analysing `dev` never pulls in `prd` history
- **Delete AI history** is available in Settings and in AI Insights

---

## Privacy

The AI request pipeline is fixed:

```
AWS data → relevant-section selection → aggregation/compaction →
PII sanitization → pseudonymization → AI provider
```

There is no path to a provider that skips sanitization.

By default the following never leave your machine:

| Category | Treatment |
| --- | --- |
| AWS access keys, secrets, tokens | Redacted — always on, cannot be disabled |
| Email addresses | Redacted → `<EMAIL>` |
| IP addresses | Redacted → `<IP>` (but `0.0.0.0/0` and `::/0` are kept: they are policy values, not identifiers) |
| AWS account IDs | Pseudonymised → `<ACCOUNT_1>` |
| IAM user names | Pseudonymised → `<USER_1>` |
| IAM role names | Pseudonymised → `<ROLE_1>` |
| ARNs | Partially anonymised — service, region and resource type kept; account and resource name replaced |
| Hostnames | Redacted → `<HOST>` (AWS service endpoints such as `ec2.amazonaws.com` are kept) |
| Instance / volume / ENI identifiers | Pseudonymised → `<RESOURCE_1>` |

Deliberately **preserved**, because they carry infrastructure meaning without
identifying a person: S3 bucket names, Lambda function names and security group IDs.

Pseudonymisation is consistent within a request — the same entity always gets the
same placeholder, so the model can reason about relationships — and the
placeholder→value mapping stays on your machine. It is shown in the UI so you can
decode the model's output, and it is never sent to a provider or written to history.

In **Settings → AI data privacy** you can disable default rules and add your own
regular-expression rules (redacting or pseudonymising). Disabling a rule is
explicitly labelled as a choice to allow that category of data through. **Payload
preview** shows exactly what would be sent, before you send it.

---

## Security

- The server binds to `127.0.0.1` by default; it is not reachable from your network
  unless you pass `--host`, and the CLI warns you when you do.
- AWS credentials are never read into the application's own state, never logged and
  never persisted. The AWS SDK's own credential providers resolve them.
- The logger refuses to print values under credential-shaped keys and redacts
  credential-shaped values wherever they appear.
- AI payload bodies are never logged.
- Errors shown in the UI are sanitized AWS messages, not stack traces.
- Local files are written atomically with owner-only permissions.
- The dashboard page is served with a restrictive Content-Security-Policy and loads
  no third-party scripts, fonts or styles.

See [SECURITY.md](./SECURITY.md) for the vulnerability reporting process and the
full security model.

---

## Uninstalling

```bash
npm uninstall -g aws-readonly-dashboard
```

npm removes the package but does not touch your data. To remove everything this
application stored:

```bash
rm -rf ~/.aws-readonly-dashboard
```

Or, before uninstalling, use **Settings → Delete All Local Configuration** in the
dashboard, which removes the same directory.

That directory is the only place the application writes. It never writes to your AWS
configuration, and it never writes AWS data anywhere.

---

## Troubleshooting

**No AWS profiles discovered**
Run `aws configure` (or `aws configure sso`), or export `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`. The dashboard reads `~/.aws/config` and `~/.aws/credentials`.

**“Unable to evaluate — authentication failure”**
Your credentials are missing or expired. For SSO profiles, run
`aws sso login --profile <name>` and press Refresh.

**“Unable to evaluate — insufficient permissions”**
The dashboard names the missing IAM action where AWS provides it. Add that action, or
leave it out and accept that the check stays unevaluated — it will never be reported
as a pass.

**Cost Explorer returns nothing / access denied**
Cost Explorer must be enabled (once, in the payer account) and can take up to 24
hours to populate. Member accounts may not see data. You need `ce:GetCostAndUsage`.

**Trusted Advisor checks are unavailable**
The Support API requires a Business, Enterprise On-Ramp or Enterprise support plan.
Without one, these checks are reported as unevaluated.

**CloudTrail search returns fewer events than expected**
`LookupEvents` covers the last 90 days of management events and AWS evaluates one
lookup attribute per request; the remaining filters are applied locally while
paging. Narrow the time window or add a filter if a search is truncated.

**Compute Optimizer shows nothing**
The account must be opted in, and AWS needs enough metric history (typically 14 days
of CloudWatch data) before it will make a recommendation. The dashboard shows the
enrollment status rather than inventing recommendations.

**“Non-LLM mode”**
The Gemini CLI was not found on `PATH`. Install it (`npm install -g @google/gemini-cli`),
adjust the command in **Settings → AI**, or configure a custom LLM endpoint.
Everything except AI analysis works normally.

On Windows the CLI is `gemini.cmd`; the dashboard resolves that through `PATH` and
`PATHEXT` itself, so you do not need to configure the `.cmd` suffix. If you point
Settings at an absolute path, point it at the real executable — a command containing
shell metacharacters is refused rather than run through a shell.

**“Gemini CLI: Not authenticated”**
The CLI is installed and runs, but has no credentials. Run `gemini` once in a
terminal and complete the sign-in, or set `GEMINI_API_KEY` in the environment the
dashboard is started from. This is reported separately from Non-LLM mode on purpose:
installing the CLI again will not fix it.

**Custom LLM requests fail**
Check the endpoint URL, headers and response path in Settings. A configured response
path that does not exist in the response is reported as an error rather than being
guessed around. Use **Preview payload** to inspect the exact request first.

**Port conflicts**
The dashboard finds the next free port automatically and prints it. Use `--port` to
choose a different starting point.

**High AWS API call counts**
Open **AWS API Usage** to see exactly which category is responsible. The usual
culprits are per-resource checks: Lambda resource policies (one call per function)
and S3 bucket settings (up to five calls per bucket). Tune them under
**Settings → Security scan limits**, reduce the number of selected regions, or
disable API categories you do not need.

**"Partially evaluated — N of M inspected"**
A scan limit stopped the check before it covered the whole inventory. The resources
that were not inspected have an *unknown* status, not a clean one. Raise the limit
in **Settings → Security scan limits** to cover them; the cost is more AWS API calls.
The "Lambda functions outside a VPC" check is never limited — it always covers every
function and reports them as a single aggregated finding per region.

**Lots of "expected not found" calls in AWS API Usage**
That is normal. Several AWS APIs answer "not found" for an ordinary state — a bucket
with no policy, a Lambda function with no resource policy — and the counter shows
these separately from failures that need attention.

---

## Development

```bash
git clone https://github.com/Ashutosh-kumar07/aws-readonly-dashboard.git
cd aws-readonly-dashboard
npm install

npm run dev          # start the dashboard from TypeScript sources
npm test             # run the test suite
npm run test:watch   # watch mode
npm run lint         # ESLint
npm run typecheck    # tsc --noEmit
npm run format       # Prettier
npm run build        # compile to dist/ and verify the entry points
npm run verify       # lint + typecheck + test + build
```

The architecture is deliberately layered:

```
CLI (src/cli.ts)
  └─ Local server (src/server/)
       └─ Dashboard API (src/server/routes.ts)
            └─ Partial-result job runner (src/server/job-runner.ts)
            └─ Application services (src/server/dashboard-service.ts, src/services/)
                 └─ AWS read-only access layer (src/aws/)
                      ├─ read-only enforcement (readonly-guard.ts)
                      ├─ operation allowlist (allowlist.ts)
                      ├─ API call tracker (tracker.ts)
                      ├─ credential/profile context (profiles.ts)
                      └─ AWS SDK

Application services
  └─ AI orchestrator (src/ai/orchestrator.ts)
       ├─ Gemini CLI provider (src/ai/providers/gemini-cli.ts)
       │    └─ cross-platform command resolver (providers/command-resolver.ts)
       └─ Custom REST provider (src/ai/providers/custom-rest.ts)

Security analyzer (src/services/security/)
  └─ one self-contained module per check in checks/, registered in registry.ts
```

Adding a security check is a new file in `src/services/security/checks/` plus one
line in `registry.ts`; adding an AWS operation requires adding it to the allowlist,
which is the only place that can grant access.

The frontend in `public/` is dependency-free ES modules — no build step, no
framework, no third-party runtime code.

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) and the
[Code of Conduct](./CODE_OF_CONDUCT.md). Changes that would weaken the read-only
guarantee, the sanitization pipeline or the "AI is never automatic" rule will not be
accepted.

Publishing is documented in [PUBLISHING.md](./PUBLISHING.md).

---

## License

[MIT](./LICENSE)
