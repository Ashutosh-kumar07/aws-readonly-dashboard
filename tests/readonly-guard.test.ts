/**
 * AWS safety tests.
 *
 * These are the most important tests in the package: they assert that no write
 * API can be invoked, that unsupported operations are rejected, that a
 * hand-edited configuration cannot bypass enforcement, and that every AWS
 * request is counted.
 */

import { describe, expect, it } from 'vitest';

import {
  assertReadOnly,
  evaluateReadOnly,
  operationNameOf,
  MUTATING_VERB_PREFIXES,
  READ_ONLY_VERB_PREFIXES,
} from '../src/aws/readonly-guard.js';
import { ALLOWLIST, allAllowedOperations, SERVICE_KEYS } from '../src/aws/allowlist.js';
import { AwsAccessLayer } from '../src/aws/access-layer.js';
import { ReadOnlyViolationError } from '../src/util/errors.js';
import { FakeClient, makeCommand } from './helpers.js';

const WRITE_OPERATIONS: Array<[string, string]> = [
  ['ec2', 'AuthorizeSecurityGroupIngress'],
  ['ec2', 'RevokeSecurityGroupIngress'],
  ['ec2', 'TerminateInstances'],
  ['ec2', 'ModifyInstanceAttribute'],
  ['s3', 'PutBucketPolicy'],
  ['s3', 'DeleteBucket'],
  ['s3', 'PutPublicAccessBlock'],
  ['iam', 'CreateUser'],
  ['iam', 'DeleteAccessKey'],
  ['iam', 'AttachUserPolicy'],
  ['lambda', 'UpdateFunctionConfiguration'],
  ['lambda', 'InvokeFunction'],
  ['lambda', 'DeleteFunction'],
  ['cloudwatch-logs', 'PutRetentionPolicy'],
  ['cloudwatch-logs', 'DeleteLogGroup'],
  ['cloudtrail', 'StopLogging'],
  ['cloudtrail', 'UpdateTrail'],
  ['securityhub', 'BatchUpdateFindings'],
  ['guardduty', 'ArchiveFindings'],
  ['config-service', 'PutConfigRule'],
  ['compute-optimizer', 'UpdateEnrollmentStatus'],
  ['cost-explorer', 'CreateAnomalyMonitor'],
  ['support', 'CreateCase'],
];

describe('read-only enforcement', () => {
  it('rejects every mutating operation, for every service', () => {
    for (const [service, operation] of WRITE_OPERATIONS) {
      const decision = evaluateReadOnly(service, operation);
      expect(decision.allowed, `${service}:${operation} must be refused`).toBe(false);
      expect(() => assertReadOnly(service, operation)).toThrow(ReadOnlyViolationError);
    }
  });

  it('rejects a mutating operation against every known service key', () => {
    for (const service of SERVICE_KEYS) {
      expect(evaluateReadOnly(service, 'DeleteEverything').allowed).toBe(false);
      expect(evaluateReadOnly(service, 'PutSomething').allowed).toBe(false);
    }
  });

  it('rejects read-shaped operations that are not on the allowlist', () => {
    expect(evaluateReadOnly('s3', 'GetObject').allowed).toBe(false);
    expect(evaluateReadOnly('ec2', 'DescribeInstances').allowed).toBe(false);
    expect(evaluateReadOnly('iam', 'GetUser').allowed).toBe(false);
    expect(evaluateReadOnly('unknown-service', 'ListBuckets').allowed).toBe(false);
  });

  it('allows exactly the operations in the allowlist', () => {
    for (const entry of allAllowedOperations()) {
      const decision = evaluateReadOnly(entry.service, entry.operation);
      expect(decision.allowed, `${entry.service}:${entry.operation} should be allowed`).toBe(true);
    }
  });

  it('never allows an operation that starts with a mutating verb', () => {
    for (const entry of allAllowedOperations()) {
      const mutating = MUTATING_VERB_PREFIXES.find((prefix) => entry.operation.startsWith(prefix));
      expect(mutating, `${entry.operation} starts with mutating verb ${mutating}`).toBeUndefined();
    }
  });

  it('only allows operations that start with a read-only verb', () => {
    for (const entry of allAllowedOperations()) {
      const readVerb = READ_ONLY_VERB_PREFIXES.some((prefix) => entry.operation.startsWith(prefix));
      expect(readVerb, `${entry.operation} has no read-only verb prefix`).toBe(true);
    }
  });

  it('rejects malformed or empty operation names', () => {
    expect(evaluateReadOnly('s3', '').allowed).toBe(false);
    expect(evaluateReadOnly('s3', undefined as unknown as string).allowed).toBe(false);
    expect(evaluateReadOnly('s3', 'lowercaseoperation').allowed).toBe(false);
  });

  it('derives operation names from SDK command instances', () => {
    expect(operationNameOf(makeCommand('DescribeSecurityGroups'))).toBe('DescribeSecurityGroups');
    expect(operationNameOf({})).toBe('');
  });
});

describe('the allowlist cannot be widened at runtime', () => {
  it('is deeply frozen', () => {
    expect(Object.isFrozen(ALLOWLIST)).toBe(true);
    expect(Object.isFrozen(ALLOWLIST.s3)).toBe(true);
    expect(Object.isFrozen(ALLOWLIST.s3[0])).toBe(true);
  });

  it('ignores attempts to push new operations', () => {
    const before = ALLOWLIST.s3.length;
    try {
      (ALLOWLIST.s3 as unknown as Array<unknown>).push({
        operation: 'DeleteBucket',
        category: 's3',
        iamAction: 's3:DeleteBucket',
      });
    } catch {
      // Frozen arrays throw in strict mode; that is the desired outcome too.
    }
    expect(ALLOWLIST.s3.length).toBe(before);
    expect(evaluateReadOnly('s3', 'DeleteBucket').allowed).toBe(false);
  });

  it('ignores attempts to mutate an existing entry into a write operation', () => {
    try {
      (ALLOWLIST.s3[0] as { operation: string }).operation = 'DeleteBucket';
    } catch {
      // Expected under strict mode.
    }
    expect(ALLOWLIST.s3[0]?.operation).toBe('ListBuckets');
    expect(evaluateReadOnly('s3', 'DeleteBucket').allowed).toBe(false);
  });
});

describe('the access layer refuses mutations before touching the network', () => {
  it('throws without ever calling the SDK client', async () => {
    const client = new FakeClient();
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const guarded = layer.client('ec2', class {} as never, { profile: 'p', region: 'us-east-1' });

    await expect(
      guarded.send(makeCommand('AuthorizeSecurityGroupIngress'), { section: 'test' })
    ).rejects.toThrow(ReadOnlyViolationError);

    expect(client.calls).toHaveLength(0);
    // A refused call never reaches AWS, so it is not counted as one.
    expect(layer.tracker.totalCalls).toBe(0);
  });

  it('refuses an explicitly overridden operation name', async () => {
    const client = new FakeClient();
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const guarded = layer.client('s3', class {} as never, { profile: 'p', region: 'us-east-1' });

    await expect(
      guarded.send(makeCommand('ListBuckets'), { section: 'test', operation: 'DeleteBucket' })
    ).rejects.toThrow(ReadOnlyViolationError);
    expect(client.calls).toHaveLength(0);
  });

  it('cannot be bypassed by disabling categories in configuration', async () => {
    const client = new FakeClient({ ListBuckets: { Buckets: [] } });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const guarded = layer.client('s3', class {} as never, { profile: 'p', region: 'us-east-1' });

    // Configuration can only narrow: disabling a category blocks reads too.
    layer.setDisabledCategories(['s3']);
    await expect(guarded.send(makeCommand('ListBuckets'), { section: 'test' })).rejects.toThrow(
      ReadOnlyViolationError
    );

    // Re-enabling restores the read, but never unlocks a write.
    layer.setDisabledCategories([]);
    await expect(
      guarded.send(makeCommand('ListBuckets'), { section: 'test' })
    ).resolves.toBeDefined();
    await expect(guarded.send(makeCommand('DeleteBucket'), { section: 'test' })).rejects.toThrow(
      ReadOnlyViolationError
    );
  });
});
