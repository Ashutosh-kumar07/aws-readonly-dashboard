/** AWS profile discovery from local configuration and the environment. */

import { describe, expect, it } from 'vitest';

import {
  discoverProfiles,
  environmentHasCredentials,
  ENVIRONMENT_PROFILE,
} from '../src/aws/profiles.js';
import {
  normaliseRegions,
  isKnownRegion,
  regionLabel,
  GLOBAL_SCOPE,
  REGIONS,
} from '../src/aws/regions.js';

function loader(files: {
  configFile?: Record<string, unknown>;
  credentialsFile?: Record<string, unknown>;
}) {
  return (async () => files) as never;
}

describe('profile discovery', () => {
  it('discovers several profiles and sorts default first', async () => {
    const profiles = await discoverProfiles({
      env: {},
      loader: loader({
        configFile: {
          default: { region: 'us-east-1' },
          'profile dev': { region: 'eu-west-1' },
          stg: { region: 'us-west-2' },
          prd: { role_arn: 'arn:aws:iam::111122223333:role/Reader', source_profile: 'default' },
        },
      }),
    });

    expect(profiles[0]?.name).toBe('default');
    expect(profiles.map((profile) => profile.name)).toEqual(
      expect.arrayContaining(['default', 'profile dev', 'stg', 'prd'])
    );
  });

  it('classifies profile kinds', async () => {
    const profiles = await discoverProfiles({
      env: {},
      loader: loader({
        configFile: {
          sso: {
            sso_start_url: 'https://example.awsapps.com/start',
            sso_account_id: '111122223333',
          },
          role: { role_arn: 'arn:aws:iam::1:role/R', source_profile: 'default' },
          proc: { credential_process: '/usr/bin/creds' },
          session: { sso_session: 'corp' },
        },
        credentialsFile: { static: { aws_access_key_id: 'AKIA...' } },
      }),
    });

    const byName = Object.fromEntries(profiles.map((profile) => [profile.name, profile.kind]));
    expect(byName.sso).toBe('sso');
    expect(byName.role).toBe('assume-role');
    expect(byName.proc).toBe('credential-process');
    expect(byName.session).toBe('sso-session');
    expect(byName.static).toBe('static');
  });

  it('never returns secret material', async () => {
    const profiles = await discoverProfiles({
      env: {},
      loader: loader({
        credentialsFile: {
          default: {
            aws_access_key_id: 'AKIAIOSFODNN7EXAMPLE',
            aws_secret_access_key: 'super-secret',
          },
        },
      }),
    });
    const serialised = JSON.stringify(profiles);
    expect(serialised).not.toContain('super-secret');
    expect(serialised).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('adds a synthetic profile for environment credentials', async () => {
    const profiles = await discoverProfiles({
      env: { AWS_ACCESS_KEY_ID: 'AKIA', AWS_SECRET_ACCESS_KEY: 'secret', AWS_REGION: 'ap-south-1' },
      loader: loader({}),
    });
    const environment = profiles.find((profile) => profile.name === ENVIRONMENT_PROFILE);
    expect(environment?.kind).toBe('environment');
    expect(environment?.region).toBe('ap-south-1');
  });

  it('returns an empty list when nothing is configured', async () => {
    expect(await discoverProfiles({ env: {}, loader: loader({}) })).toEqual([]);
  });

  it('survives an unreadable shared config file', async () => {
    const profiles = await discoverProfiles({
      env: {},
      loader: (() => {
        throw new Error('permission denied');
      }) as never,
    });
    expect(profiles).toEqual([]);
  });

  it('skips sso-session blocks, which are not profiles', async () => {
    const profiles = await discoverProfiles({
      env: {},
      loader: loader({
        configFile: { 'sso-session corp': { sso_start_url: 'https://x' }, dev: {} },
      }),
    });
    expect(profiles.map((profile) => profile.name)).toEqual(['dev']);
  });

  it('detects the several environment credential mechanisms', () => {
    expect(
      environmentHasCredentials({ AWS_ACCESS_KEY_ID: 'a', AWS_SECRET_ACCESS_KEY: 'b' } as never)
    ).toBe(true);
    expect(environmentHasCredentials({ AWS_WEB_IDENTITY_TOKEN_FILE: '/token' } as never)).toBe(
      true
    );
    expect(
      environmentHasCredentials({
        AWS_CONTAINER_CREDENTIALS_FULL_URI: 'http://169.254.170.2',
      } as never)
    ).toBe(true);
    expect(environmentHasCredentials({} as never)).toBe(false);
  });
});

describe('regions', () => {
  it('keeps known regions and drops junk', () => {
    expect(normaliseRegions(['us-east-1', 'nonsense', 'eu-west-1'])).toEqual([
      'us-east-1',
      'eu-west-1',
    ]);
  });

  it('accepts a region that looks valid but is not in the catalogue yet', () => {
    expect(normaliseRegions(['ap-southeast-9'])).toEqual(['ap-southeast-9']);
  });

  it('removes duplicates and never treats global as a region', () => {
    expect(normaliseRegions(['us-east-1', 'us-east-1', GLOBAL_SCOPE])).toEqual(['us-east-1']);
  });

  it('labels the global scope distinctly', () => {
    expect(regionLabel(GLOBAL_SCOPE)).toMatch(/non-regional/i);
    expect(regionLabel('us-east-1')).toBe('US East (N. Virginia)');
  });

  it('publishes a catalogue with grouped, labelled regions', () => {
    expect(REGIONS.length).toBeGreaterThan(20);
    expect(isKnownRegion('eu-central-1')).toBe(true);
    expect(isKnownRegion('mars-north-1')).toBe(false);
    for (const region of REGIONS) {
      expect(region.label).toBeTruthy();
      expect(region.group).toBeTruthy();
    }
  });
});
