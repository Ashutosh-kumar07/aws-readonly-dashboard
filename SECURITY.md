# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | ✅ Security fixes provided |
| < 1.0 | ❌ Pre-release, not supported |

Security fixes are released as patch versions of the latest minor release.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

- Preferred: GitHub's private vulnerability reporting —
  <https://github.com/ashutosh-kumar07/aws-readonly-dashboard/security/advisories/new>
- Alternative: open an issue asking for a private contact channel, without
  including any details of the vulnerability.

Please include: affected version, reproduction steps, and the impact you believe it
has. Do **not** include AWS account IDs, ARNs, credentials, CloudTrail records or any
other data from a real account — a redacted reproduction is always sufficient.

We aim to acknowledge a report within 5 working days and to ship a fix or a mitigation
plan within 30 days. We will credit reporters in the changelog unless asked not to.

## Security model

### The application cannot modify AWS

This is the property most worth attacking, and the one most worth defending.

Every AWS request passes through one access layer (`src/aws/access-layer.ts`). Before
a request is dispatched, three independent barriers are applied:

1. an operation whose name begins with a mutating verb is refused outright;
2. an operation must begin with a recognised read-only verb;
3. an operation must appear in the compile-time allowlist for that AWS service.

The allowlist (`src/aws/allowlist.ts`) is a constant that is deep-frozen at module
load. It is never read from disk, never merged with user configuration, and never
mutated at runtime. Configuration can only *narrow* what the application calls.

There is no "force", "advanced", "expert" or "remediate" mode. Recommendations
describe what a human could do in the AWS console; the application never executes
them.

If you find a way to make this package issue a mutating AWS API call, that is a
security vulnerability and we want to hear about it.

### Credential handling

- AWS credentials are resolved by the AWS SDK's own providers from your local
  configuration (shared config files, SSO cache, environment, container/instance
  metadata). The application never reads, copies or stores credential material.
- Credentials are never written to disk by this application and never appear in the
  HTTP API, the UI or the logs.
- The logger refuses to print values under credential-shaped keys and redacts
  credential-shaped values (access key IDs, bearer tokens, secret-shaped strings)
  anywhere they appear.
- Gemini authentication belongs entirely to the Gemini CLI. No Gemini credentials or
  API keys are stored by this application. The prompt is passed on standard input,
  not on a command line, so it cannot leak through the process list or shell history.
- Headers you configure for a custom LLM endpoint (including authentication headers)
  are stored in your local configuration file with owner-only permissions. Treat that
  file accordingly.

### Network exposure

- The server binds to `127.0.0.1` by default. Binding elsewhere requires `--host`,
  and the CLI prints a warning when you do.
- The dashboard has no authentication because it is a loopback-only tool that acts
  with your own credentials. **Do not expose it to a network you do not fully trust.**
  If you must, put it behind an authenticating reverse proxy.
- Static assets are served with a restrictive Content-Security-Policy
  (`default-src 'self'`, `frame-ancestors 'none'`), and the UI loads no third-party
  scripts, styles or fonts.
- Static file serving rejects any path that escapes the `public/` directory.
- Request bodies are size-limited.

### Local data

| File | Contents | Permissions |
| --- | --- | --- |
| `~/.aws-readonly-dashboard/config.json` | Preferences, thresholds, AI provider configuration, sanitization rules | `0600` |
| `~/.aws-readonly-dashboard/security-findings.json` | Your finding decisions and the minimum finding identity | `0600` |
| `~/.aws-readonly-dashboard/ai-history.json` | Sanitized AI history, only when enabled | `0600` |

The directory itself is created with `0700`. Writes are atomic (temp file + rename).
Raw AWS data is never persisted; it lives in memory for the server session only.

Delete everything with **Settings → Delete All Local Configuration**, or
`rm -rf ~/.aws-readonly-dashboard`.

### AI data handling

- AI is never invoked automatically — only in response to an explicit user action.
- Only the sections the user selected are included in a request.
- Every request passes through sanitization and pseudonymization before it reaches a
  provider. There is no code path that bypasses it.
- The placeholder→value mapping stays on the machine: it is shown in the UI so the
  user can decode the output, and it is never sent to a provider or written to
  history.
- AI history is off by default and stores only sanitized requests and responses.
- If a user disables a default sanitization rule, the UI states plainly that the
  category will now be included. Rules protecting credential material cannot be
  disabled.

### Custom LLM endpoints — user responsibility

> **Configuring a custom LLM endpoint means sanitized application data will be sent
> to that endpoint. You are responsible for trusting the configured endpoint.**

The dashboard cannot verify who operates an endpoint you configure, what it logs, or
where it forwards data. Before enabling one, satisfy yourself that it is operated by
your organisation or a provider you have a data-processing agreement with. Nothing is
sent until you configure the endpoint, enable it, tick the acknowledgement, and press
an Analyze button. Use **Preview payload** to inspect exactly what will be sent.

### Supply chain

- Runtime dependencies are limited to the AWS SDK for JavaScript and one AWS shared
  config loader. There is no third-party UI framework, chart library or HTTP client.
- The published tarball contains only `dist/`, `public/` and documentation; sources,
  tests, CI configuration and development tooling are excluded.
- CI runs lint, type checking, tests and a packaging check on every push and pull
  request.
- Releases are published from an intentional, tagged release workflow — never
  automatically from a commit. Trusted publishing (OIDC) is recommended over
  long-lived npm tokens.
