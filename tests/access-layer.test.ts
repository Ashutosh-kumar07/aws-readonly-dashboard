/** API-call accounting, retries, error classification and profile isolation. */

import { describe, expect, it } from 'vitest';

import { AwsAccessLayer } from '../src/aws/access-layer.js';
import { ApiCallTracker } from '../src/aws/tracker.js';
import { classifyAwsError, extractMissingPermission } from '../src/util/errors.js';
import { FakeClient, awsError, makeCommand } from './helpers.js';

describe('API call accounting', () => {
  it('counts every AWS request that reaches the SDK', async () => {
    const client = new FakeClient({ ListBuckets: { Buckets: [] } });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const guarded = layer.client('s3', class {} as never, { profile: 'dev', region: 'us-east-1' });

    for (let index = 0; index < 5; index += 1) {
      await guarded.send(makeCommand('ListBuckets'), { section: 'security:s3' });
    }

    const snapshot = layer.tracker.snapshot();
    expect(snapshot.totalCalls).toBe(5);
    expect(snapshot.successfulCalls).toBe(5);
    expect(snapshot.categories[0]?.category).toBe('s3');
    expect(snapshot.categories[0]?.calls).toBe(5);
    expect(client.calls).toHaveLength(5);
  });

  it('records the profile, region, section and operation for each call', async () => {
    const client = new FakeClient({ GetCostAndUsage: {} });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const guarded = layer.client('cost-explorer', class {} as never, {
      profile: 'prd',
      region: 'global',
    });

    await guarded.send(makeCommand('GetCostAndUsage'), { section: 'billing' });

    const record = layer.tracker.snapshot().recentCalls[0];
    expect(record).toMatchObject({
      profile: 'prd',
      region: 'global',
      section: 'billing',
      operation: 'GetCostAndUsage',
      service: 'cost-explorer',
      category: 'billing',
      categoryLabel: 'Billing / Cost Explorer',
      status: 'success',
    });
  });

  it('counts failed calls separately and keeps the error code', async () => {
    const client = new FakeClient({ ListBuckets: awsError('AccessDenied', 'not allowed', 403) });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 0 });
    const guarded = layer.client('s3', class {} as never, { profile: 'dev', region: 'us-east-1' });

    await expect(
      guarded.send(makeCommand('ListBuckets'), { section: 'security:s3' })
    ).rejects.toThrow();

    const snapshot = layer.tracker.snapshot();
    expect(snapshot.totalCalls).toBe(1);
    expect(snapshot.failedCalls).toBe(1);
    expect(snapshot.recentCalls[0]?.errorCode).toBe('AccessDenied');
  });

  it('retries throttled calls and counts the attempt once it settles', async () => {
    let attempts = 0;
    const client = new FakeClient({
      ListBuckets: () => {
        attempts += 1;
        if (attempts < 3) throw awsError('ThrottlingException', 'slow down', 429);
        return { Buckets: [] };
      },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 3 });
    const guarded = layer.client('s3', class {} as never, { profile: 'dev', region: 'us-east-1' });

    await guarded.send(makeCommand('ListBuckets'), { section: 'security:s3' });

    expect(attempts).toBe(3);
    expect(layer.tracker.totalCalls).toBe(1);
  });

  it('does not retry an access-denied failure', async () => {
    let attempts = 0;
    const client = new FakeClient({
      ListBuckets: () => {
        attempts += 1;
        throw awsError('AccessDeniedException', 'nope', 403);
      },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 3 });
    const guarded = layer.client('s3', class {} as never, { profile: 'dev', region: 'us-east-1' });

    await expect(guarded.send(makeCommand('ListBuckets'), { section: 's3' })).rejects.toThrow();
    expect(attempts).toBe(1);
  });

  it('separates expected "not found" answers from real failures', async () => {
    const client = new FakeClient({
      GetPolicy: awsError('ResourceNotFoundException', 'no policy', 404),
      ListFunctions: awsError('AccessDeniedException', 'denied', 403),
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 0 });
    const guarded = layer.client('lambda', class {} as never, {
      profile: 'dev',
      region: 'us-east-1',
    });

    await expect(guarded.send(makeCommand('GetPolicy'), { section: 'security' })).rejects.toThrow();
    await expect(
      guarded.send(makeCommand('ListFunctions'), { section: 'security' })
    ).rejects.toThrow();

    const snapshot = layer.tracker.snapshot();
    expect(snapshot.failedCalls).toBe(2);
    // "This function has no resource policy" is an answer, not a problem.
    expect(snapshot.expectedNotFoundCalls).toBe(1);
    expect(snapshot.categories[0]?.expectedNotFound).toBe(1);
    expect(snapshot.recentCalls[0]?.errorKind).toBeDefined();
  });

  it('bounds the stored record list while keeping the running totals', () => {
    const tracker = new ApiCallTracker(10);
    for (let index = 0; index < 50; index += 1) {
      tracker.record({
        category: 's3',
        service: 's3',
        operation: 'ListBuckets',
        profile: 'dev',
        region: 'us-east-1',
        section: 'test',
        status: 'success',
        durationMs: 1,
      });
    }
    const snapshot = tracker.snapshot();
    expect(snapshot.totalCalls).toBe(50);
    expect(snapshot.recordedCalls).toBe(10);
    expect(snapshot.truncated).toBe(true);
  });

  it('resets cleanly for a new session', () => {
    const tracker = new ApiCallTracker();
    tracker.record({
      category: 'iam',
      service: 'iam',
      operation: 'ListUsers',
      profile: 'dev',
      region: 'global',
      section: 'test',
      status: 'success',
      durationMs: 1,
    });
    tracker.reset();
    expect(tracker.snapshot().totalCalls).toBe(0);
    expect(tracker.snapshot().categories).toHaveLength(0);
  });
});

describe('profile handling', () => {
  it('keeps clients and identities separate per profile', async () => {
    const clients = new Map<string, FakeClient>();
    const layer = new AwsAccessLayer({
      clientFactory: (() => {
        const client = new FakeClient({ ListBuckets: { Buckets: [] } });
        clients.set(String(clients.size), client);
        return client as never;
      }) as never,
    });

    const dev = layer.client('s3', class {} as never, { profile: 'dev', region: 'us-east-1' });
    const prd = layer.client('s3', class {} as never, { profile: 'prd', region: 'us-east-1' });

    await dev.send(makeCommand('ListBuckets'), { section: 's3' });
    await prd.send(makeCommand('ListBuckets'), { section: 's3' });

    // Two profiles must never share one SDK client instance.
    expect(clients.size).toBe(2);
    const profiles = layer.tracker.snapshot().recentCalls.map((call) => call.profile);
    expect(new Set(profiles)).toEqual(new Set(['dev', 'prd']));
  });

  it('reuses one client for the same profile, service and region', async () => {
    let created = 0;
    const client = new FakeClient({ ListBuckets: { Buckets: [] } });
    const layer = new AwsAccessLayer({
      clientFactory: (() => {
        created += 1;
        return client as never;
      }) as never,
    });

    layer.client('s3', class {} as never, { profile: 'dev', region: 'us-east-1' });
    layer.client('s3', class {} as never, { profile: 'dev', region: 'us-east-1' });
    expect(created).toBe(1);
  });

  it('reports a credential failure rather than throwing', async () => {
    const client = new FakeClient({
      GetCallerIdentity: awsError(
        'ExpiredToken',
        'The security token included in the request is expired'
      ),
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 0 });

    const identity = await layer.validateProfile('stale');
    expect(identity.status).toBe('error');
    expect(identity.error?.kind).toBe('authentication');
    expect(layer.accountIdFor('stale')).toBeUndefined();
  });

  it('caches a successful identity so it is validated once', async () => {
    const client = new FakeClient({
      GetCallerIdentity: { Account: '111122223333', Arn: 'arn:aws:iam::111122223333:user/dev' },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });

    const first = await layer.validateProfile('dev');
    const second = await layer.validateProfile('dev');

    expect(first.accountId).toBe('111122223333');
    expect(second.accountId).toBe('111122223333');
    expect(client.calls).toHaveLength(1);
    expect(layer.accountIdFor('dev')).toBe('111122223333');
  });

  it('attaches the account id to subsequent call records', async () => {
    const client = new FakeClient({
      GetCallerIdentity: { Account: '111122223333' },
      ListBuckets: { Buckets: [] },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });

    await layer.validateProfile('dev');
    const guarded = layer.client('s3', class {} as never, { profile: 'dev', region: 'us-east-1' });
    await guarded.send(makeCommand('ListBuckets'), { section: 's3' });

    const record = layer.tracker
      .snapshot()
      .recentCalls.find((call) => call.operation === 'ListBuckets');
    expect(record?.accountId).toBe('111122223333');
  });
});

describe('request deadlines', () => {
  /** A request that only ends when it is aborted, as a stalled socket does. */
  const hangingClient = (onSend?: () => void) => ({
    async send(_command: unknown, options?: { abortSignal?: AbortSignal }) {
      onSend?.();
      return new Promise((_resolve, reject) => {
        options?.abortSignal?.addEventListener('abort', () => {
          const error = new Error('aborted');
          error.name = 'AbortError';
          reject(error);
        });
      });
    },
    destroy() {},
  });

  it('aborts the underlying request when the deadline passes, instead of abandoning it', async () => {
    // A request that never settles on its own: only the abort can end it.
    let observed: AbortSignal | undefined;
    let releasedByAbort = false;
    const client = {
      async send(_command: unknown, options?: { abortSignal?: AbortSignal }) {
        observed = options?.abortSignal;
        return new Promise((_resolve, reject) => {
          options?.abortSignal?.addEventListener('abort', () => {
            releasedByAbort = true;
            const error = new Error('aborted');
            error.name = 'AbortError';
            reject(error);
          });
        });
      },
      destroy() {},
    };

    const layer = new AwsAccessLayer({
      clientFactory: (() => client) as never,
      requestTimeoutMs: 30,
      maxRetries: 0,
    });
    const guarded = layer.client('s3', class {} as never, { profile: 'dev', region: 'us-east-1' });

    await expect(
      guarded.send(makeCommand('ListBuckets'), { section: 'security:s3' })
    ).rejects.toThrow(/timed out/i);

    expect(observed).toBeInstanceOf(AbortSignal);
    // The socket is handed back rather than left checked out of the SDK's
    // connection pool, which is what turned one slow call into an outbreak.
    expect(releasedByAbort).toBe(true);
    expect(observed?.aborted).toBe(true);
  });

  it('does not describe its own deadline in a way that reads as an IAM action', async () => {
    const layer = new AwsAccessLayer({
      clientFactory: (() => hangingClient()) as never,
      requestTimeoutMs: 20,
      maxRetries: 0,
    });
    const guarded = layer.client('s3', class {} as never, { profile: 'dev', region: 'eu-west-1' });

    const error = await guarded
      .send(makeCommand('GetBucketLocation'), { section: 'security:s3' })
      .catch((caught: Error) => caught);

    expect((error as Error).message).toContain('GetBucketLocation');
    expect((error as Error).message).toContain('eu-west-1');
    // `s3:GetBucketLocation` in the text would be mined back out as a missing
    // permission, blaming IAM for a network problem.
    expect((error as Error).message).not.toContain('s3:GetBucketLocation');
    expect(classifyAwsError(error).missingPermission).toBeUndefined();
  });

  it('retries a timeout once, not once per configured retry', async () => {
    let attempts = 0;
    const client = hangingClient(() => {
      attempts += 1;
    });
    const layer = new AwsAccessLayer({
      clientFactory: (() => client) as never,
      requestTimeoutMs: 15,
      maxRetries: 3,
    });
    const guarded = layer.client('s3', class {} as never, { profile: 'dev', region: 'us-east-1' });

    await expect(
      guarded.send(makeCommand('ListBuckets'), { section: 'security:s3' })
    ).rejects.toThrow(/timed out/i);

    // One attempt plus a single retry: four 30-second waits for one call is
    // how a slow check starts looking like a broken one.
    expect(attempts).toBe(2);
  });
});

describe('AWS error classification', () => {
  const cases: Array<[Error, string]> = [
    [awsError('AccessDeniedException', 'User is not authorized'), 'access-denied'],
    [awsError('UnauthorizedOperation', 'not authorised'), 'access-denied'],
    [awsError('ExpiredTokenException', 'expired'), 'authentication'],
    [awsError('ThrottlingException', 'rate exceeded'), 'throttling'],
    [awsError('ResourceNotFoundException', 'missing'), 'not-found'],
    [awsError('InvalidAccessException', 'not subscribed'), 'not-subscribed'],
    [awsError('ServiceUnavailable', 'try later'), 'service-unavailable'],
    [awsError('TimeoutError', 'timed out'), 'timeout'],
  ];

  it.each(cases)('classifies %s', (error, expected) => {
    expect(classifyAwsError(error).kind).toBe(expected);
  });

  it('classifies by HTTP status when the code is unknown', () => {
    expect(classifyAwsError(awsError('WeirdError', 'boom', 403)).kind).toBe('access-denied');
    expect(classifyAwsError(awsError('WeirdError', 'boom', 500)).kind).toBe('service-unavailable');
  });

  it('extracts the missing IAM action from an AWS message', () => {
    expect(
      extractMissingPermission(
        'User: arn:aws:iam::111122223333:user/dev is not authorized to perform: ce:GetCostAndUsage'
      )
    ).toBe('ce:GetCostAndUsage');
    expect(extractMissingPermission('something unrelated')).toBeUndefined();
  });

  it('only reports a missing IAM action when the failure is about permissions', () => {
    // The message names an action, but a timeout is not evidence that the
    // action is missing — the permission may well be in place.
    const timedOut = new Error('AWS request timed out after 30000ms (s3:GetBucketLocation)');
    timedOut.name = 'TimeoutError';
    expect(classifyAwsError(timedOut).kind).toBe('timeout');
    expect(classifyAwsError(timedOut).missingPermission).toBeUndefined();

    const denied = awsError(
      'AccessDenied',
      'User: arn:aws:iam::111122223333:user/dev is not authorized to perform: s3:GetBucketLocation'
    );
    expect(classifyAwsError(denied).missingPermission).toBe('s3:GetBucketLocation');
  });

  it('classifies a cross-region S3 answer as a region mismatch, not a permission problem', () => {
    const redirect = awsError(
      'PermanentRedirect',
      'The bucket you are attempting to access must be addressed using the specified endpoint.',
      301
    );
    expect(classifyAwsError(redirect).kind).toBe('unsupported-region');
    expect(classifyAwsError(redirect).missingPermission).toBeUndefined();
  });

  it('marks throttling and service errors as retryable, permissions as not', () => {
    expect(classifyAwsError(awsError('ThrottlingException')).retryable).toBe(true);
    expect(classifyAwsError(awsError('AccessDeniedException')).retryable).toBe(false);
  });
});
