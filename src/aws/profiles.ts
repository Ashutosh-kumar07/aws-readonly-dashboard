/**
 * AWS profile discovery.
 *
 * Discovery is deliberately two-phase:
 *
 *   - Lightweight discovery reads the shared config/credentials files and the
 *     process environment. It makes no AWS API calls at all.
 *   - Full validation happens only when the user selects a profile, and costs
 *     exactly one `sts:GetCallerIdentity` call per profile.
 *
 * Secret material is never returned to the UI and never written to disk.
 */

import { loadSharedConfigFiles } from '@smithy/shared-ini-file-loader';

export type ProfileKind =
  | 'static'
  | 'sso'
  | 'sso-session'
  | 'assume-role'
  | 'credential-process'
  | 'web-identity'
  | 'environment'
  | 'unknown';

export interface DiscoveredProfile {
  /** Profile name as used by the AWS SDK, or `__environment__` for env credentials. */
  name: string;
  /** Friendly label for the UI. */
  label: string;
  kind: ProfileKind;
  /** Default region declared by the profile, when it declares one. */
  region?: string;
  /** Source of the definition. */
  source: 'config' | 'credentials' | 'environment' | 'both';
  /** For assume-role profiles. */
  roleArn?: string;
  sourceProfile?: string;
  /** For SSO profiles. */
  ssoStartUrl?: string;
  ssoAccountId?: string;
  ssoRoleName?: string;
  ssoSession?: string;
}

/** Synthetic profile name used when credentials come from the environment. */
export const ENVIRONMENT_PROFILE = '__environment__';

function classify(entry: Record<string, string | undefined>): ProfileKind {
  if (entry.sso_start_url || entry.sso_account_id) return 'sso';
  if (entry.sso_session) return 'sso-session';
  if (entry.role_arn && entry.web_identity_token_file) return 'web-identity';
  if (entry.role_arn) return 'assume-role';
  if (entry.credential_process) return 'credential-process';
  if (entry.aws_access_key_id) return 'static';
  return 'unknown';
}

export function environmentHasCredentials(env: NodeJS.ProcessEnv = process.env): boolean {
  return Boolean(
    (env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY) ||
    env.AWS_WEB_IDENTITY_TOKEN_FILE ||
    env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI ||
    env.AWS_CONTAINER_CREDENTIALS_FULL_URI
  );
}

export interface DiscoverProfilesOptions {
  env?: NodeJS.ProcessEnv;
  /** Injectable for tests. */
  loader?: typeof loadSharedConfigFiles;
}

/**
 * Reads locally available AWS profiles. Never throws: a missing or unreadable
 * config file simply yields fewer profiles.
 */
export async function discoverProfiles(
  options: DiscoverProfilesOptions = {}
): Promise<DiscoveredProfile[]> {
  const env = options.env ?? process.env;
  const load = options.loader ?? loadSharedConfigFiles;
  const profiles = new Map<string, DiscoveredProfile>();

  let configFile: Record<string, Record<string, string | undefined>> = {};
  let credentialsFile: Record<string, Record<string, string | undefined>> = {};
  try {
    const files = await load({ ignoreCache: true });
    configFile = (files.configFile ?? {}) as typeof configFile;
    credentialsFile = (files.credentialsFile ?? {}) as typeof credentialsFile;
  } catch {
    // No shared config available; fall through to environment-only discovery.
  }

  const merge = (
    name: string,
    entry: Record<string, string | undefined>,
    source: 'config' | 'credentials'
  ): void => {
    if (name.startsWith('sso-session ')) return;
    const existing = profiles.get(name);
    const merged: Record<string, string | undefined> = { ...(existing ? {} : {}), ...entry };
    const kind = classify(merged);
    const profile: DiscoveredProfile = {
      name,
      label: name,
      kind: existing && existing.kind !== 'unknown' && kind === 'unknown' ? existing.kind : kind,
      source: existing && existing.source !== source ? 'both' : source,
      ...(merged.region
        ? { region: merged.region }
        : existing?.region
          ? { region: existing.region }
          : {}),
      ...(merged.role_arn ? { roleArn: merged.role_arn } : {}),
      ...(merged.source_profile ? { sourceProfile: merged.source_profile } : {}),
      ...(merged.sso_start_url ? { ssoStartUrl: merged.sso_start_url } : {}),
      ...(merged.sso_account_id ? { ssoAccountId: merged.sso_account_id } : {}),
      ...(merged.sso_role_name ? { ssoRoleName: merged.sso_role_name } : {}),
      ...(merged.sso_session ? { ssoSession: merged.sso_session } : {}),
    };
    profiles.set(name, existing ? { ...existing, ...profile } : profile);
  };

  for (const [name, entry] of Object.entries(configFile)) merge(name, entry ?? {}, 'config');
  for (const [name, entry] of Object.entries(credentialsFile))
    merge(name, entry ?? {}, 'credentials');

  if (environmentHasCredentials(env)) {
    profiles.set(ENVIRONMENT_PROFILE, {
      name: ENVIRONMENT_PROFILE,
      label: 'Environment credentials',
      kind: 'environment',
      source: 'environment',
      ...(env.AWS_REGION || env.AWS_DEFAULT_REGION
        ? { region: env.AWS_REGION ?? env.AWS_DEFAULT_REGION }
        : {}),
    });
  }

  return [...profiles.values()].sort((a, b) => {
    if (a.name === 'default') return -1;
    if (b.name === 'default') return 1;
    return a.name.localeCompare(b.name);
  });
}
