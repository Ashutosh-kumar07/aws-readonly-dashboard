# Publishing and releasing

This document describes the complete release process for `aws-readonly-dashboard`.

> **Never commit an npm token to this repository**, and never paste one into an
> issue, a pull request or documentation. Use trusted publishing (OIDC) from GitHub
> Actions, or a local interactive `npm publish` with 2FA.

## Prerequisites

- An npm account with publish rights to the package
  (<https://www.npmjs.com/signup>).
- Two-factor authentication enabled on that account
  (**Account → Two-Factor Authentication**). For publishing, "Authorization and
  writes" is the stronger setting and is recommended.
- Node.js 18.17+ and npm 9+ locally.
- A clean working tree on the default branch, with CI green.

## One-time: verify the package name

```bash
npm view aws-readonly-dashboard
```

A `404 Not Found` means the name is free. If the name is taken, either choose a new
name or publish under a scope (see [Scoped packages](#scoped-packages)).

## Release checklist

Run through this list for every release.

```bash
# 1. Start clean
git switch main && git pull
rm -rf node_modules dist
npm ci

# 2. Quality gates
npm run lint
npm run typecheck
npm test
npm run build

# 3. Choose the version (semantic versioning)
npm version patch     # bug fixes
npm version minor     # new, backwards-compatible features
npm version major     # breaking changes
# pre-release: npm version prerelease --preid=rc
```

`npm version` updates `package.json`, creates a commit and tags it.

```bash
# 4. Inspect exactly what would be published
npm pack --dry-run

# 5. Build a real tarball and inspect its contents
npm pack
tar -tzf aws-readonly-dashboard-*.tgz | sort
```

The tarball must contain **only**:

- `package/dist/**` — compiled JavaScript and type declarations
- `package/public/**` — dashboard assets
- `package/README.md`, `package/LICENSE`, `package/CHANGELOG.md`, `package/SECURITY.md`
- `package/package.json`

It must **not** contain: `src/`, `tests/`, `scripts/`, `.github/`, `tsconfig*.json`,
`eslint.config.js`, `vitest.config.ts`, `node_modules/`, `.env*`, any `*.tgz`, any
AWS configuration, or anything from `~/.aws-readonly-dashboard`.

```bash
# 6. Verify no credentials or local data slipped in
tar -xzf aws-readonly-dashboard-*.tgz -O | grep -iE "AKIA[0-9A-Z]{16}|aws_secret_access_key|BEGIN [A-Z ]*PRIVATE KEY" && echo "FOUND SECRETS — DO NOT PUBLISH" || echo "clean"

# 7. Install the artefact into a scratch directory and smoke test it
mkdir -p /tmp/arod-verify && cd /tmp/arod-verify && npm init -y >/dev/null
npm install /path/to/aws-readonly-dashboard-1.0.0.tgz
npx aws-readonly-dashboard --version
npx aws-readonly-dashboard --help
npx aws-readonly-dashboard --no-open --port 9123 &
curl -s http://127.0.0.1:9123/api/status | head -c 200
kill %1
```

Also confirm:

- the `bin` entry is executable (`ls -l node_modules/.bin/aws-readonly-dashboard`);
- the dashboard page loads in a browser and its assets resolve;
- `engines.node` matches what you actually support;
- the README renders correctly — preview it on
  <https://npmjs.com/package/aws-readonly-dashboard> after publishing, or with a
  local Markdown preview before.

## Publishing

```bash
npm login
npm whoami          # confirm the expected account
npm publish
```

`prepublishOnly` runs `npm run verify` (lint, typecheck, test, build) as a final
gate, so a broken build cannot be published by accident.

With 2FA enabled you will be prompted for a one-time password.

### Pre-releases

Publish release candidates on a separate dist-tag so `npm install` keeps resolving to
the stable version:

```bash
npm version prerelease --preid=rc      # 1.1.0-rc.0
npm publish --tag next
```

Promote later with:

```bash
npm dist-tag add aws-readonly-dashboard@1.1.0 latest
```

### Scoped packages

If you publish under a scope, a scoped package is private by default, so public
releases need an explicit flag:

```bash
npm publish --access public
```

## Post-publish verification

```bash
npm view aws-readonly-dashboard version
npm view aws-readonly-dashboard dist-tags
npx aws-readonly-dashboard@latest --version
```

Then:

1. Push the release commit and tag: `git push --follow-tags`.
2. Create a GitHub release from the tag, using the matching `CHANGELOG.md` section.
3. Check the package page renders the README and the correct repository/homepage
   links.

## Automating releases

The repository ships two workflows:

- `.github/workflows/ci.yml` — runs on every push and pull request: install, lint,
  type check, test, build, pack, and verify the tarball contents. It never publishes.
- `.github/workflows/release.yml` — runs only when a `v*` tag is pushed (or when
  dispatched manually). It re-runs the full verification, then publishes.

### Trusted publishing (recommended)

Prefer npm's trusted publishing (OIDC) over storing a long-lived token:

1. On npmjs.com, open the package → **Settings → Trusted publishing**.
2. Add this GitHub repository and the `release.yml` workflow as a trusted publisher.
3. Ensure the job requests the OIDC token:

   ```yaml
   permissions:
     contents: read
     id-token: write
   ```

4. Publish with provenance:

   ```yaml
   - run: npm publish --provenance --access public
   ```

No secret is stored anywhere, and each published version carries a verifiable
provenance attestation.

### Token fallback

If trusted publishing is unavailable, create a **granular access token** scoped to
this package only, with a short expiry, and store it as the `NPM_TOKEN` repository
secret. Rotate it regularly and revoke it as soon as trusted publishing is in place.

## Releasing a follow-up version

1. Merge changes to the default branch; confirm CI is green.
2. Add a `CHANGELOG.md` entry under a new version heading.
3. `npm version <patch|minor|major>`.
4. `git push --follow-tags` — the release workflow publishes the tag.
5. Verify with `npm view aws-readonly-dashboard version`.

## Deprecating a version

Deprecation leaves the version installable but warns on install:

```bash
npm deprecate aws-readonly-dashboard@1.0.1 "Contains a CloudTrail pagination bug; upgrade to 1.0.2."
```

Deprecate a whole range if needed:

```bash
npm deprecate aws-readonly-dashboard@"<1.0.2" "Please upgrade to 1.0.2 or later."
```

Undo a deprecation by setting an empty message:

```bash
npm deprecate aws-readonly-dashboard@1.0.1 ""
```

Prefer deprecating over unpublishing. npm's unpublish policy only allows removal
within 72 hours and under narrow conditions, and unpublishing breaks anyone who
depends on that version. If a release contains a security problem, publish a fixed
version, deprecate the affected range with a message pointing at the fix, and open a
security advisory.
