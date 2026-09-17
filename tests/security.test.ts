/** Security checks, finding lifecycle and permission honesty. */

import { describe, expect, it } from 'vitest';
import { join } from 'node:path';

import {
  analyseRule,
  securityGroupCheck,
  SENSITIVE_PORTS,
} from '../src/services/security/checks/security-groups.js';
import { lambdaVpcCheck, lambdaPublicPolicyCheck } from '../src/services/security/checks/lambda.js';
import { iamHygieneCheck, accessKeyAgeDays } from '../src/services/security/checks/iam.js';
import {
  SECURITY_CHECKS,
  describeChecks,
  runSecurityAnalysis,
} from '../src/services/security/index.js';
import { FindingStore } from '../src/services/security/finding-store.js';
import { fingerprint } from '../src/services/security/types.js';
import { AwsAccessLayer } from '../src/aws/access-layer.js';
import { defaultConfig } from '../src/config/schema.js';
import { FakeClient, awsError, withTempDir } from './helpers.js';

function context(access: AwsAccessLayer, overrides: Record<string, unknown> = {}) {
  return {
    access,
    profile: 'dev',
    accountId: '111122223333',
    region: 'us-east-1',
    config: defaultConfig(),
    section: 'security:test',
    ...overrides,
  } as never;
}

describe('security group rule analysis', () => {
  it('treats an all-protocol rule open to the world as critical', () => {
    const rules = analyseRule({ IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] });
    expect(rules).toHaveLength(1);
    expect(rules[0]?.severity).toBe('critical');
    expect(rules[0]?.protocol).toBe('all');
  });

  it('treats an open administrative port as critical', () => {
    const rules = analyseRule({
      IpProtocol: 'tcp',
      FromPort: 22,
      ToPort: 22,
      IpRanges: [{ CidrIp: '0.0.0.0/0' }],
    });
    expect(rules[0]?.severity).toBe('critical');
    expect(rules[0]?.sensitivePorts[0]).toContain('SSH');
  });

  it('treats an open non-administrative port as high', () => {
    const rules = analyseRule({
      IpProtocol: 'tcp',
      FromPort: 8443,
      ToPort: 8443,
      IpRanges: [{ CidrIp: '0.0.0.0/0' }],
    });
    expect(rules[0]?.severity).toBe('high');
  });

  it('detects IPv6 exposure', () => {
    const rules = analyseRule({
      IpProtocol: 'tcp',
      FromPort: 3389,
      ToPort: 3389,
      Ipv6Ranges: [{ CidrIpv6: '::/0' }],
    });
    expect(rules[0]?.cidr).toBe('::/0');
    expect(rules[0]?.severity).toBe('critical');
  });

  it('ignores rules restricted to a specific CIDR or security group', () => {
    expect(
      analyseRule({
        IpProtocol: 'tcp',
        FromPort: 22,
        ToPort: 22,
        IpRanges: [{ CidrIp: '10.0.0.0/8' }],
      })
    ).toEqual([]);
    expect(
      analyseRule({
        IpProtocol: 'tcp',
        FromPort: 22,
        ToPort: 22,
        UserIdGroupPairs: [{ GroupId: 'sg-1' }],
      })
    ).toEqual([]);
  });

  it('flags a full 0-65535 port range as critical', () => {
    const rules = analyseRule({
      IpProtocol: 'tcp',
      FromPort: 0,
      ToPort: 65535,
      IpRanges: [{ CidrIp: '0.0.0.0/0' }],
    });
    expect(rules[0]?.severity).toBe('critical');
  });

  it('covers the well-known database and admin ports', () => {
    for (const port of [22, 3389, 3306, 5432, 1433, 27017, 6379, 9200]) {
      expect(SENSITIVE_PORTS[port]).toBeDefined();
    }
  });

  it('produces a finding with evidence and a recommendation', async () => {
    const client = new FakeClient({
      DescribeSecurityGroups: {
        SecurityGroups: [
          {
            GroupId: 'sg-0123456789abcdef0',
            GroupName: 'web',
            VpcId: 'vpc-1',
            IpPermissions: [
              { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] },
            ],
          },
        ],
      },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const result = await securityGroupCheck.run(context(layer));

    expect(result.evaluated).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe('critical');
    expect(result.findings[0]?.evidence).toMatchObject({
      groupId: 'sg-0123456789abcdef0',
      cidr: '0.0.0.0/0',
    });
    expect(result.findings[0]?.recommendation).toMatch(/never modifies/i);
  });

  it('reports a permission failure as "not evaluated", never as secure', async () => {
    const client = new FakeClient({
      DescribeSecurityGroups: awsError('UnauthorizedOperation', 'You are not authorized', 403),
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 0 });
    const result = await securityGroupCheck.run(context(layer));

    expect(result.evaluated).toBe(false);
    expect(result.findings).toHaveLength(0);
    expect(result.issues[0]?.kind).toBe('access-denied');
    expect(result.issues[0]?.label).toMatch(/insufficient permissions/i);
    expect(result.issues[0]?.missingPermission).toBe('ec2:DescribeSecurityGroups');
  });
});

describe('lambda checks', () => {
  it('flags functions with no VPC configuration', async () => {
    const client = new FakeClient({
      ListFunctions: {
        Functions: [
          {
            FunctionName: 'no-vpc',
            FunctionArn: 'arn:aws:lambda:us-east-1:111122223333:function:no-vpc',
          },
          { FunctionName: 'in-vpc', VpcConfig: { SubnetIds: ['subnet-1'] } },
        ],
      },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const result = await lambdaVpcCheck.run(context(layer));

    // One aggregated finding per region, with the functions in the evidence.
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.title).toContain('1 of 2 Lambda functions run outside a VPC');
    expect(result.findings[0]?.evidence).toMatchObject({
      functionsOutsideVpc: 1,
      functionsTotal: 2,
    });
    expect((result.findings[0]?.evidence.functions as Array<{ name: string }>)[0]?.name).toBe(
      'no-vpc'
    );
    expect(result.resourcesEvaluated).toBe(2);
  });

  it('does not raise a finding when every function is in a VPC', async () => {
    const client = new FakeClient({
      ListFunctions: {
        Functions: [{ FunctionName: 'in-vpc', VpcConfig: { SubnetIds: ['subnet-1'] } }],
      },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const result = await lambdaVpcCheck.run(context(layer));

    expect(result.evaluated).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it('stays at one finding however many functions are outside a VPC', async () => {
    const functions = Array.from({ length: 450 }, (_, index) => ({ FunctionName: `fn-${index}` }));
    const client = new FakeClient({ ListFunctions: { Functions: functions } });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const result = await lambdaVpcCheck.run(context(layer));

    // 450 individual low findings would bury the real issues in the UI and
    // dominate the AI payload.
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.title).toContain('450 of 450');
    expect((result.findings[0]?.evidence.functions as unknown[]).length).toBe(100);
    expect(result.findings[0]?.evidence.note).toContain('first 100');
  });

  it('paginates through every function in the VPC check', async () => {
    const functions = Array.from({ length: 450 }, (_, index) => ({
      FunctionName: `fn-${index}`,
      FunctionArn: `arn:aws:lambda:us-east-1:111122223333:function:fn-${index}`,
    }));
    let page = 0;
    const client = new FakeClient({
      ListFunctions: () => {
        const slice = functions.slice(page * 50, (page + 1) * 50);
        page += 1;
        return {
          Functions: slice,
          NextMarker: page * 50 < functions.length ? `m${page}` : undefined,
        };
      },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const result = await lambdaVpcCheck.run(context(layer));

    expect(result.resourcesEvaluated).toBe(450);
    expect(result.findings[0]?.evidence.functionsOutsideVpc).toBe(450);
    expect(result.truncated).toBeFalsy();
  });

  it('states partial coverage when the policy-lookup limit is reached', async () => {
    const functions = Array.from({ length: 120 }, (_, index) => ({
      FunctionName: `fn-${index}`,
      LastModified: `2026-03-${String((index % 28) + 1).padStart(2, '0')}T00:00:00Z`,
    }));
    const client = new FakeClient({
      ListFunctions: { Functions: functions },
      GetPolicy: awsError('ResourceNotFoundException', 'no policy'),
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 0 });
    const config = defaultConfig();
    config.security.maxLambdaPolicyLookupsPerRegion = 25;

    const result = await lambdaPublicPolicyCheck.run(context(layer, { config }));

    expect(result.resourcesEvaluated).toBe(25);
    expect(result.truncated).toBe(true);
    // The uninspected functions must be declared, not silently skipped.
    expect(result.issues.some((issue) => issue.label.includes('Partially evaluated'))).toBe(true);
    expect(result.issues.some((issue) => issue.message.includes('95 function(s)'))).toBe(true);
  });

  it('inspects every function when the limit is raised above the inventory', async () => {
    const functions = Array.from({ length: 300 }, (_, index) => ({ FunctionName: `fn-${index}` }));
    const client = new FakeClient({
      ListFunctions: { Functions: functions },
      GetPolicy: awsError('ResourceNotFoundException', 'no policy'),
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 0 });
    const config = defaultConfig();
    config.security.maxLambdaPolicyLookupsPerRegion = 500;

    const result = await lambdaPublicPolicyCheck.run(context(layer, { config }));

    expect(result.resourcesEvaluated).toBe(300);
    expect(result.truncated).toBe(false);
    expect(result.issues).toHaveLength(0);
  });

  it('reports the policy check as not evaluated when the limit is zero', async () => {
    const client = new FakeClient({ ListFunctions: { Functions: [{ FunctionName: 'fn' }] } });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const config = defaultConfig();
    config.security.maxLambdaPolicyLookupsPerRegion = 0;

    const result = await lambdaPublicPolicyCheck.run(context(layer, { config }));

    expect(result.evaluated).toBe(false);
    expect(result.findings).toHaveLength(0);
    expect(result.issues[0]?.label).toMatch(/disabled/i);
  });

  it('finds a public function policy within the inspected set', async () => {
    const client = new FakeClient({
      ListFunctions: {
        Functions: [
          {
            FunctionName: 'public-fn',
            FunctionArn: 'arn:aws:lambda:us-east-1:1:function:public-fn',
          },
        ],
      },
      GetPolicy: {
        Policy: JSON.stringify({
          Statement: [
            { Sid: 'open', Effect: 'Allow', Principal: '*', Action: 'lambda:InvokeFunction' },
          ],
        }),
      },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const result = await lambdaPublicPolicyCheck.run(context(layer));

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe('high');
  });

  it('does not claim compliance when Lambda cannot be listed', async () => {
    const client = new FakeClient({
      ListFunctions: awsError('AccessDeniedException', 'denied', 403),
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 0 });
    const result = await lambdaVpcCheck.run(context(layer));

    expect(result.evaluated).toBe(false);
    expect(result.issues).toHaveLength(1);
  });
});

describe('IAM hygiene', () => {
  it('flags root MFA and root access keys', async () => {
    const client = new FakeClient({
      GetAccountSummary: { SummaryMap: { AccountMFAEnabled: 0, AccountAccessKeysPresent: 1 } },
      GetAccountPasswordPolicy: {
        PasswordPolicy: {
          MinimumPasswordLength: 14,
          RequireSymbols: true,
          RequireNumbers: true,
          RequireUppercaseCharacters: true,
          RequireLowercaseCharacters: true,
          PasswordReusePrevention: 5,
        },
      },
      ListUsers: { Users: [] },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const result = await iamHygieneCheck.run(context(layer, { region: 'global' }));

    const titles = result.findings.map((finding) => finding.title);
    expect(titles.some((title) => title.includes('root user does not have MFA'))).toBe(true);
    expect(titles.some((title) => title.includes('root user has active access keys'))).toBe(true);
    expect(result.findings.every((finding) => finding.severity === 'critical')).toBe(true);
  });

  it('flags a console user without MFA', async () => {
    const client = new FakeClient({
      GetAccountSummary: { SummaryMap: { AccountMFAEnabled: 1, AccountAccessKeysPresent: 0 } },
      GetAccountPasswordPolicy: {
        PasswordPolicy: {
          MinimumPasswordLength: 20,
          RequireSymbols: true,
          RequireNumbers: true,
          RequireUppercaseCharacters: true,
          RequireLowercaseCharacters: true,
          PasswordReusePrevention: 24,
        },
      },
      ListUsers: {
        Users: [
          {
            UserName: 'console-user',
            PasswordLastUsed: new Date(),
            Arn: 'arn:aws:iam::1:user/console-user',
          },
        ],
      },
      ListMFADevices: { MFADevices: [] },
      ListAccessKeys: { AccessKeyMetadata: [] },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const result = await iamHygieneCheck.run(context(layer, { region: 'global' }));

    expect(result.findings.some((finding) => finding.title.includes('without MFA'))).toBe(true);
  });

  it('flags an old active access key', async () => {
    const old = new Date(Date.now() - 200 * 24 * 60 * 60 * 1000);
    const client = new FakeClient({
      GetAccountSummary: { SummaryMap: { AccountMFAEnabled: 1, AccountAccessKeysPresent: 0 } },
      GetAccountPasswordPolicy: {
        PasswordPolicy: {
          MinimumPasswordLength: 20,
          RequireSymbols: true,
          RequireNumbers: true,
          RequireUppercaseCharacters: true,
          RequireLowercaseCharacters: true,
          PasswordReusePrevention: 24,
        },
      },
      ListUsers: { Users: [{ UserName: 'bot', CreateDate: old }] },
      ListMFADevices: { MFADevices: [] },
      ListAccessKeys: {
        AccessKeyMetadata: [
          { AccessKeyId: 'AKIAIOSFODNN7EXAMPLE', Status: 'Active', CreateDate: old },
        ],
      },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const result = await iamHygieneCheck.run(context(layer, { region: 'global' }));

    expect(result.findings.some((finding) => finding.title.includes('days old'))).toBe(true);
  });

  it('computes access key age in whole days', () => {
    const now = new Date('2026-03-15T00:00:00Z');
    expect(accessKeyAgeDays(new Date('2026-01-15T00:00:00Z'), now)).toBe(59);
    expect(accessKeyAgeDays(undefined, now)).toBe(0);
  });
});

describe('finding identity and persistence', () => {
  it('produces a stable fingerprint for the same underlying issue', () => {
    const parts = { profile: 'dev', region: 'us-east-1', checkId: 'sg', resourceId: 'sg-1' };
    expect(fingerprint(parts)).toBe(fingerprint({ ...parts }));
    expect(fingerprint(parts)).not.toBe(fingerprint({ ...parts, profile: 'prd' }));
    expect(fingerprint(parts)).not.toBe(fingerprint({ ...parts, region: 'eu-west-1' }));
    expect(fingerprint(parts)).not.toBe(fingerprint({ ...parts, discriminator: 'tcp:22' }));
  });

  it('persists an ignored status across scans', async () => {
    await withTempDir(async (dir) => {
      const store = new FindingStore(join(dir, 'findings.json'));
      await store.load();

      const finding = {
        id: 'abc123',
        status: 'open' as const,
        checkId: 'sg',
        title: 'open port',
        severity: 'critical' as const,
        profile: 'dev',
        region: 'us-east-1',
        resourceId: 'sg-1',
        resourceType: 'AWS::EC2::SecurityGroup',
        firstSeenAt: '2026-03-01T00:00:00Z',
        lastSeenAt: '2026-03-01T00:00:00Z',
        updatedAt: '2026-03-01T00:00:00Z',
      };

      await store.upsertSeen([finding]);
      await store.setStatus('abc123', 'ignored', 'accepted risk');

      // A later scan sees it again; the user's decision must survive.
      await store.upsertSeen([{ ...finding, lastSeenAt: '2026-03-02T00:00:00Z' }]);

      const reloaded = new FindingStore(join(dir, 'findings.json'));
      await reloaded.load();
      const persisted = reloaded.get('abc123');
      expect(persisted?.status).toBe('ignored');
      expect(persisted?.note).toBe('accepted risk');
      expect(persisted?.firstSeenAt).toBe('2026-03-01T00:00:00Z');
    });
  });

  it('marks findings resolved once they stop being detected', async () => {
    await withTempDir(async (dir) => {
      const store = new FindingStore(join(dir, 'findings.json'));
      await store.load();
      await store.upsertSeen([
        {
          id: 'gone',
          status: 'open',
          checkId: 'sg',
          title: 'open port',
          severity: 'high',
          profile: 'dev',
          region: 'us-east-1',
          resourceId: 'sg-1',
          resourceType: 'AWS::EC2::SecurityGroup',
          firstSeenAt: '2026-03-01T00:00:00Z',
          lastSeenAt: '2026-03-01T00:00:00Z',
          updatedAt: '2026-03-01T00:00:00Z',
        },
      ]);

      const resolved = await store.markResolved(new Set(), {
        profiles: new Set(['dev']),
        regions: new Set(['us-east-1']),
      });

      expect(resolved).toHaveLength(1);
      expect(store.get('gone')?.status).toBe('resolved');
    });
  });

  it('does not resolve findings belonging to a profile outside the scan scope', async () => {
    await withTempDir(async (dir) => {
      const store = new FindingStore(join(dir, 'findings.json'));
      await store.load();
      await store.upsertSeen([
        {
          id: 'other-profile',
          status: 'open',
          checkId: 'sg',
          title: 'open port',
          severity: 'high',
          profile: 'prd',
          region: 'us-east-1',
          resourceId: 'sg-9',
          resourceType: 'AWS::EC2::SecurityGroup',
          firstSeenAt: '2026-03-01T00:00:00Z',
          lastSeenAt: '2026-03-01T00:00:00Z',
          updatedAt: '2026-03-01T00:00:00Z',
        },
      ]);

      await store.markResolved(new Set(), {
        profiles: new Set(['dev']),
        regions: new Set(['us-east-1']),
      });
      expect(store.get('other-profile')?.status).toBe('open');
    });
  });

  it('reopens a resolved finding that comes back', async () => {
    await withTempDir(async (dir) => {
      const store = new FindingStore(join(dir, 'findings.json'));
      await store.load();
      const finding = {
        id: 'flip',
        status: 'open' as const,
        checkId: 'sg',
        title: 'open port',
        severity: 'high' as const,
        profile: 'dev',
        region: 'us-east-1',
        resourceId: 'sg-1',
        resourceType: 'AWS::EC2::SecurityGroup',
        firstSeenAt: '2026-03-01T00:00:00Z',
        lastSeenAt: '2026-03-01T00:00:00Z',
        updatedAt: '2026-03-01T00:00:00Z',
      };
      await store.upsertSeen([finding]);
      await store.markResolved(new Set(), {
        profiles: new Set(['dev']),
        regions: new Set(['us-east-1']),
      });
      await store.upsertSeen([finding]);
      expect(store.get('flip')?.status).toBe('open');
    });
  });

  it('deletes resolved findings on request', async () => {
    await withTempDir(async (dir) => {
      const store = new FindingStore(join(dir, 'findings.json'));
      await store.load();
      await store.upsertSeen([
        {
          id: 'a',
          status: 'resolved',
          checkId: 'sg',
          title: 'x',
          severity: 'low',
          profile: 'dev',
          region: 'us-east-1',
          resourceId: 'r',
          resourceType: 't',
          firstSeenAt: '2026-01-01T00:00:00Z',
          lastSeenAt: '2026-01-01T00:00:00Z',
          updatedAt: '2026-01-01T00:00:00Z',
        },
      ]);
      expect(await store.deleteResolved()).toBe(1);
      expect(store.all()).toHaveLength(0);
    });
  });
});

describe('the security analyzer', () => {
  it('registers a modular, documented set of checks', () => {
    const checks = describeChecks();
    expect(checks.length).toBeGreaterThanOrEqual(12);
    for (const check of checks) {
      expect(check.id).toBeTruthy();
      expect(check.requiredPermissions.length).toBeGreaterThan(0);
      expect(['regional', 'global']).toContain(check.scope);
    }
    // The services the product explicitly requires are all represented.
    const services = new Set(checks.map((check) => check.service));
    for (const service of [
      'Security Hub',
      'GuardDuty',
      'Inspector',
      'IAM Access Analyzer',
      'Trusted Advisor',
      'AWS Config',
      'CloudTrail',
      'S3',
      'Lambda',
      'Security Groups',
      'IAM',
    ]) {
      expect(services.has(service), `${service} check is missing`).toBe(true);
    }
  });

  it('keeps every check independently runnable and failure-isolated', async () => {
    // Every client throws; the analyzer must still return a structured result.
    const client = new FakeClient(
      Object.fromEntries(
        [
          'DescribeSecurityGroups',
          'ListFunctions',
          'ListBuckets',
          'GetAccountSummary',
          'DescribeHub',
        ].map((operation) => [operation, awsError('AccessDeniedException', 'denied', 403)])
      )
    );
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 0 });

    await withTempDir(async (dir) => {
      const store = new FindingStore(join(dir, 'findings.json'));
      await store.load();

      const result = await runSecurityAnalysis({
        access: layer,
        config: defaultConfig(),
        store,
        profile: 'dev',
        accountId: '111122223333',
        regions: ['us-east-1'],
      });

      expect(result.data?.summary.notEvaluatedChecks).toBeGreaterThan(0);
      expect(result.data?.findings).toBeDefined();
      expect(result.issues.length).toBeGreaterThan(0);
      // "No findings" must never be implied when nothing could be evaluated.
      expect(result.status).toBe('partial');
    });
  });

  it('honours disabled checks from configuration', async () => {
    const client = new FakeClient({});
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 0 });
    const config = defaultConfig();
    config.security.disabledChecks = SECURITY_CHECKS.map((check) => check.id);

    await withTempDir(async (dir) => {
      const store = new FindingStore(join(dir, 'findings.json'));
      await store.load();

      const result = await runSecurityAnalysis({
        access: layer,
        config,
        store,
        profile: 'dev',
        regions: ['us-east-1'],
      });

      expect(client.calls).toHaveLength(0);
      expect(result.data?.checks.every((check) => check.state === 'disabled')).toBe(true);
    });
  });
});
