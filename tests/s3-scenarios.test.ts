/**
 * S3 against the real AWS SDK.
 *
 * Every other AWS test drives a hand-written fake client, which never builds a
 * real middleware stack — so a fault in how the dashboard uses the SDK (sending
 * a command instance twice, for one) cannot show up there. These tests use the
 * real `S3Client` and `S3ControlClient` with a stubbed transport: real commands,
 * real middleware, real response parsing, scripted HTTP answers.
 */

import { describe, expect, it } from 'vitest';
import { join } from 'node:path';

import { S3Client } from '@aws-sdk/client-s3';
import { S3ControlClient } from '@aws-sdk/client-s3-control';

import { AwsAccessLayer } from '../src/aws/access-layer.js';
import { GLOBAL_SCOPE } from '../src/aws/regions.js';
import {
  s3PublicAccessCheck,
  s3AccountPublicAccessBlockCheck,
} from '../src/services/security/checks/s3.js';
import { runSecurityAnalysis } from '../src/services/security/index.js';
import { FindingStore } from '../src/services/security/finding-store.js';
import { defaultConfig } from '../src/config/schema.js';
import { withTempDir } from './helpers.js';

interface StubRequest {
  /** The S3 operation, derived from the request the SDK actually built. */
  op: string;
  bucket?: string;
  method: string;
  hostname: string;
  path: string;
  query: Record<string, unknown>;
  region: string;
}

interface StubReply {
  status?: number;
  body?: string;
  headers?: Record<string, string>;
}

type Router = (request: StubRequest) => StubReply;

const xml = (body: string): string => `<?xml version="1.0" encoding="UTF-8"?>${body}`;

/** An S3 error document, as the service returns it. */
function s3Error(code: string, message = code, status = 400): StubReply {
  return { status, body: xml(`<Error><Code>${code}</Code><Message>${message}</Message></Error>`) };
}

function listBucketsBody(
  buckets: Array<{ name: string; region?: string }>,
  continuationToken?: string
): StubReply {
  const entries = buckets
    .map(
      (bucket) =>
        `<Bucket><Name>${bucket.name}</Name><CreationDate>2026-01-01T00:00:00.000Z</CreationDate>` +
        `${bucket.region ? `<BucketRegion>${bucket.region}</BucketRegion>` : ''}</Bucket>`
    )
    .join('');
  return {
    body: xml(
      `<ListAllMyBucketsResult><Owner><ID>owner</ID></Owner><Buckets>${entries}</Buckets>` +
        `${continuationToken ? `<ContinuationToken>${continuationToken}</ContinuationToken>` : ''}` +
        `</ListAllMyBucketsResult>`
    ),
  };
}

/** Sub-resource query keys, in the spelling the SDK puts on the wire. */
const SUB_RESOURCES: Record<string, string> = {
  location: 'GetBucketLocation',
  policyStatus: 'GetBucketPolicyStatus',
  publicAccessBlock: 'GetPublicAccessBlock',
  acl: 'GetBucketAcl',
  encryption: 'GetBucketEncryption',
};

/**
 * Identifies the request the SDK built.
 *
 * Path and hostname alone are ambiguous: a virtual-hosted bucket request has
 * path `/`, exactly like the account-wide listing, and a bucket whose name is
 * not DNS-compatible is addressed path-style instead. The operation is what the
 * tests actually care about, so it is derived once, here.
 */
function identify(request: {
  method: string;
  hostname: string;
  path: string;
  query: Record<string, unknown>;
}): { op: string; bucket?: string } {
  if (request.path.includes('/v20180820/configuration/publicAccessBlock')) {
    return { op: 'GetAccountPublicAccessBlock' };
  }

  const sub = Object.keys(SUB_RESOURCES).find((key) => key in (request.query ?? {}));
  const virtualHost = request.hostname.match(/^(.+?)\.s3[.-]/);
  const pathBucket = request.path.split('/').filter(Boolean)[0];
  const bucket = virtualHost ? virtualHost[1] : sub ? pathBucket : undefined;

  if (sub) return { op: SUB_RESOURCES[sub] as string, ...(bucket ? { bucket } : {}) };
  return { op: 'ListBuckets' };
}

function stubbedLayer(router: Router) {
  const requests: StubRequest[] = [];

  const handlerFor = (region: string) => ({
    async handle(request: {
      method: string;
      hostname: string;
      path: string;
      query: Record<string, unknown>;
    }) {
      const identified = identify(request);
      const captured: StubRequest = {
        ...identified,
        method: request.method,
        hostname: request.hostname,
        path: request.path,
        query: request.query ?? {},
        region,
      };
      requests.push(captured);
      const reply = router(captured);
      return {
        response: {
          statusCode: reply.status ?? 200,
          headers: reply.headers ?? {},
          body: Buffer.from(reply.body ?? ''),
        },
      };
    },
    updateHttpClientConfig() {},
    httpHandlerConfigs: () => ({}),
  });

  const layer = new AwsAccessLayer({
    maxRetries: 2,
    requestTimeoutMs: 5_000,
    clientFactory: ((ctor: unknown, config: { region: string }) => {
      const Client = ctor === S3ControlClient ? S3ControlClient : S3Client;
      return new Client({
        region: config.region,
        credentials: { accessKeyId: 'AKIAFAKEFAKEFAKE', secretAccessKey: 'fake-secret' },
        requestHandler: handlerFor(config.region) as never,
        maxAttempts: 1,
      }) as never;
    }) as never,
  });

  return { layer, requests };
}

function checkContext(layer: AwsAccessLayer, overrides: Record<string, unknown> = {}) {
  return {
    access: layer,
    profile: 'dev',
    accountId: '111122223333',
    region: GLOBAL_SCOPE,
    config: defaultConfig(),
    section: 'security:s3',
    ...overrides,
  } as never;
}

/** A bucket that answers every read cleanly and is fully protected. */
function healthyBucketReply(request: StubRequest): StubReply {
  switch (request.op) {
    case 'GetBucketLocation':
      return {
        body: xml(
          '<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>'
        ),
      };
    case 'GetBucketPolicyStatus':
      return { body: xml('<PolicyStatus><IsPublic>false</IsPublic></PolicyStatus>') };
    case 'GetPublicAccessBlock':
      return {
        body: xml(
          '<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls>' +
            '<IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy>' +
            '<RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>'
        ),
      };
    case 'GetBucketAcl':
      return {
        body: xml(
          '<AccessControlPolicy><AccessControlList></AccessControlList></AccessControlPolicy>'
        ),
      };
    case 'GetBucketEncryption':
      return {
        body: xml(
          '<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>' +
            '<SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule>' +
            '</ServerSideEncryptionConfiguration>'
        ),
      };
    default:
      return s3Error('NotImplemented', 'unexpected sub-resource', 501);
  }
}

describe('S3 account-level Block Public Access, against the real SDK', () => {
  it('recovers from a throttled request instead of failing on a reused command', async () => {
    // An SDK command may only be sent once: the retry used to fail inside the
    // SDK with "Duplicate middleware name 'parseOutpostArnablesMiddleaware'",
    // which surfaced as an unexplained error on a check that had simply been
    // throttled.
    let attempts = 0;
    const { layer } = stubbedLayer(() => {
      attempts += 1;
      if (attempts === 1) return s3Error('SlowDown', 'Rate exceeded', 503);
      return {
        body: xml(
          '<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls>' +
            '<IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy>' +
            '<RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>'
        ),
      };
    });

    const result = await s3AccountPublicAccessBlockCheck.run(checkContext(layer));

    expect(attempts).toBe(2);
    expect(result.evaluated).toBe(true);
    expect(result.issues).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
  });

  it('pins the SDK constraint behind that bug: a command instance is single-use', async () => {
    // Sending a command applies its plugins to its own middleware stack, and
    // the stack refuses them twice. If a future SDK changes this, the retry
    // machinery can be simplified — until then it must build a new command.
    const client = new S3ControlClient({
      region: 'us-east-1',
      credentials: { accessKeyId: 'AKIAFAKEFAKEFAKE', secretAccessKey: 'fake-secret' },
      maxAttempts: 1,
      requestHandler: {
        async handle() {
          throw Object.assign(new Error('Rate exceeded'), {
            name: 'ThrottlingException',
            $metadata: { httpStatusCode: 429 },
          });
        },
        updateHttpClientConfig() {},
        httpHandlerConfigs: () => ({}),
      } as never,
    });
    const { GetPublicAccessBlockCommand } = await import('@aws-sdk/client-s3-control');
    const command = new GetPublicAccessBlockCommand({ AccountId: '111122223333' });

    const first = await client.send(command).catch((error: Error) => error);
    expect((first as Error).message).toMatch(/Rate exceeded/);

    // The second send throws synchronously, while the command's middleware is
    // being resolved — before any request is attempted.
    let second: unknown;
    try {
      await client.send(command);
    } catch (error) {
      second = error;
    }
    expect((second as Error).message).toMatch(/Duplicate middleware name/);
  });

  it('reports a missing configuration as a finding, not as an error', async () => {
    const { layer } = stubbedLayer(() =>
      s3Error('NoSuchPublicAccessBlockConfiguration', 'not configured', 404)
    );

    const result = await s3AccountPublicAccessBlockCheck.run(checkContext(layer));

    expect(result.evaluated).toBe(true);
    expect(result.findings[0]?.title).toMatch(/No account-level/);
  });

  it('reports a denial as a permission problem', async () => {
    const { layer } = stubbedLayer(() => s3Error('AccessDenied', 'Access Denied', 403));

    const result = await s3AccountPublicAccessBlockCheck.run(checkContext(layer));

    expect(result.evaluated).toBe(false);
    expect(result.issues[0]?.kind).toBe('access-denied');
    expect(result.issues[0]?.missingPermission).toBeTruthy();
  });
});

describe('S3 bucket scanning, against the real SDK', () => {
  it('pages the listing and uses the region it reports', async () => {
    const page1 = Array.from({ length: 3 }, (_, i) => ({
      name: `bucket-${i}`,
      region: 'eu-west-1',
    }));
    const page2 = [{ name: 'bucket-3', region: 'eu-west-1' }];

    const { layer, requests } = stubbedLayer((request) => {
      if (request.op === 'ListBuckets') {
        if (!('continuation-token' in request.query)) return listBucketsBody(page1, 'next');
        return listBucketsBody(page2);
      }
      return healthyBucketReply(request);
    });

    const result = await s3PublicAccessCheck.run(checkContext(layer));

    const listings = requests.filter((request) => request.op === 'ListBuckets');
    expect(listings.length).toBeGreaterThanOrEqual(2);
    expect(listings[0]?.query['max-buckets']).toBeDefined();
    expect(listings[1]?.query['continuation-token']).toBe('next');
    // The listing carried each region, so no bucket needed a location lookup.
    expect(requests.some((request) => request.op === 'GetBucketLocation')).toBe(false);
    expect(result.resourcesEvaluated).toBe(4);
    expect(result.issues.filter((issue) => issue.kind === 'unknown')).toHaveLength(0);
  });

  it('falls back to GetBucketLocation, including the legacy EU value', async () => {
    const { layer, requests } = stubbedLayer((request) => {
      if (request.op === 'ListBuckets') return listBucketsBody([{ name: 'legacy-bucket' }]);
      if (request.op === 'GetBucketLocation') {
        // Real S3 sends the namespace, and the SDK needs it to read the value.
        return {
          body: xml(
            '<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">EU</LocationConstraint>'
          ),
        };
      }
      return healthyBucketReply(request);
    });

    const result = await s3PublicAccessCheck.run(checkContext(layer));

    expect(requests.some((request) => request.op === 'GetBucketLocation')).toBe(true);
    // Legacy "EU" is eu-west-1; a client built for "EU" would go nowhere.
    expect(requests.some((request) => request.region === 'eu-west-1')).toBe(true);
    expect(result.resourcesEvaluated).toBe(1);
  });

  it('treats a cross-region redirect as a routing problem, not a permission one', async () => {
    const { layer } = stubbedLayer((request) => {
      if (request.op === 'ListBuckets') {
        return listBucketsBody([{ name: 'moved-bucket', region: 'us-east-1' }]);
      }
      if (request.op === 'GetBucketPolicyStatus') {
        return s3Error(
          'PermanentRedirect',
          'The bucket you are attempting to access must be addressed using the specified endpoint.',
          301
        );
      }
      return healthyBucketReply(request);
    });

    const result = await s3PublicAccessCheck.run(checkContext(layer));

    const issue = result.issues.find((entry) => entry.check === 's3-public-access');
    expect(issue?.kind).toBe('unsupported-region');
    expect(issue?.missingPermission).toBeUndefined();
    // Nothing is asserted about a bucket whose policy could not be read.
    expect(result.findings).toHaveLength(0);
  });

  it('does not invent a finding when a read is denied', async () => {
    const { layer } = stubbedLayer((request) => {
      if (request.op === 'ListBuckets') {
        return listBucketsBody([{ name: 'guarded-bucket', region: 'us-east-1' }]);
      }
      if (request.op === 'GetPublicAccessBlock') {
        return s3Error('AccessDenied', 'Access Denied', 403);
      }
      return healthyBucketReply(request);
    });

    const result = await s3PublicAccessCheck.run(checkContext(layer));

    expect(
      result.findings.filter((finding) => finding.title.includes('Block Public Access'))
    ).toHaveLength(0);
    expect(result.issues.some((issue) => issue.label.startsWith('Partially evaluated'))).toBe(true);
    expect(result.resourcesEvaluated).toBe(0);
  });

  it('finds a genuinely public bucket', async () => {
    const { layer } = stubbedLayer((request) => {
      if (request.op === 'ListBuckets') {
        return listBucketsBody([{ name: 'open-data', region: 'us-east-1' }]);
      }
      if (request.op === 'GetBucketPolicyStatus') {
        return { body: xml('<PolicyStatus><IsPublic>true</IsPublic></PolicyStatus>') };
      }
      if (request.op === 'GetPublicAccessBlock') {
        return s3Error('NoSuchPublicAccessBlockConfiguration', 'none', 404);
      }
      return healthyBucketReply(request);
    });

    const result = await s3PublicAccessCheck.run(checkContext(layer));

    expect(result.findings.some((finding) => finding.severity === 'critical')).toBe(true);
    expect(result.findings[0]?.resourceId).toBe('open-data');
  });

  it('handles a bucket name with dots, which cannot use a virtual host', async () => {
    const { layer, requests } = stubbedLayer((request) => {
      if (request.op === 'ListBuckets') {
        return listBucketsBody([{ name: 'my.legacy.bucket', region: 'us-east-1' }]);
      }
      return healthyBucketReply(request);
    });

    const result = await s3PublicAccessCheck.run(checkContext(layer));

    // The SDK addresses it path-style; the scan must not care either way.
    expect(requests.some((request) => request.bucket === 'my.legacy.bucket')).toBe(true);
    expect(result.resourcesEvaluated).toBe(1);
    expect(result.issues.filter((issue) => issue.kind === 'unknown')).toHaveLength(0);
  });

  it('reports an operation a directory bucket does not support, without inventing anything', async () => {
    const { layer } = stubbedLayer((request) => {
      if (request.op === 'ListBuckets') {
        return listBucketsBody([{ name: 'analytics--use1-az4--x-s3', region: 'us-east-1' }]);
      }
      if (request.op === 'GetBucketPolicyStatus' || request.op === 'GetBucketAcl') {
        // Directory buckets do not implement every bucket sub-resource.
        return s3Error(
          'NotImplemented',
          'A header you provided implies functionality that is not implemented',
          501
        );
      }
      return healthyBucketReply(request);
    });

    const result = await s3PublicAccessCheck.run(checkContext(layer));

    expect(result.findings).toHaveLength(0);
    // Named failures, plus a partial-coverage note — and nothing "unexpected".
    expect(result.issues.map((issue) => issue.kind).sort()).toEqual([
      'partial',
      'service-unavailable',
      'service-unavailable',
    ]);
    expect(result.issues.some((issue) => issue.label.startsWith('Partially evaluated'))).toBe(true);
  });

  it('reports an empty account as evaluated with nothing to say', async () => {
    const { layer } = stubbedLayer(() => listBucketsBody([]));

    const result = await s3PublicAccessCheck.run(checkContext(layer));

    expect(result.evaluated).toBe(true);
    expect(result.resourcesEvaluated).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.issues).toHaveLength(0);
  });

  it('reports a denied listing as a permission problem and inspects nothing', async () => {
    const { layer } = stubbedLayer(() => s3Error('AccessDenied', 'Access Denied', 403));

    const result = await s3PublicAccessCheck.run(checkContext(layer));

    expect(result.evaluated).toBe(false);
    expect(result.issues[0]?.kind).toBe('access-denied');
  });

  it('recovers from a throttled listing', async () => {
    let attempts = 0;
    const { layer } = stubbedLayer((request) => {
      if (request.op === 'ListBuckets') {
        attempts += 1;
        if (attempts === 1) return s3Error('SlowDown', 'Rate exceeded', 503);
        return listBucketsBody([{ name: 'retried-bucket', region: 'us-east-1' }]);
      }
      return healthyBucketReply(request);
    });

    const result = await s3PublicAccessCheck.run(checkContext(layer));

    expect(attempts).toBe(2);
    expect(result.resourcesEvaluated).toBe(1);
    expect(result.issues.filter((issue) => issue.kind === 'unknown')).toHaveLength(0);
  });

  it('stops at the scan limit and offers to inspect the rest', async () => {
    const buckets = Array.from({ length: 12 }, (_, i) => ({
      name: `bucket-${i}`,
      region: 'us-east-1',
    }));
    const { layer } = stubbedLayer((request) => {
      if (request.op === 'ListBuckets') {
        const max = Number(request.query['max-buckets'] ?? 1000);
        return listBucketsBody(buckets.slice(0, max), 'more');
      }
      return healthyBucketReply(request);
    });
    const config = defaultConfig();
    config.security.maxBucketsPerScan = 5;

    const result = await s3PublicAccessCheck.run(checkContext(layer, { config }));

    expect(result.resourcesEvaluated).toBe(5);
    const partial = result.issues.find((issue) => issue.label.includes('more exist'));
    expect(partial?.suggestion).toEqual({
      setting: 'maxBucketsPerScan',
      value: 0,
      label: 'Inspect every bucket',
    });
  });
});

describe('the whole security scan, against the real S3 SDK', () => {
  it('never lets an S3 failure escape as an unexpected error', async () => {
    // Every S3 call fails, in a different way each time. None of them may
    // arrive as "unexpected error", and none may become a finding.
    const failures = [
      s3Error('SlowDown', 'Rate exceeded', 503),
      s3Error('AccessDenied', 'Access Denied', 403),
      s3Error('PermanentRedirect', 'wrong endpoint', 301),
      s3Error('InvalidAccessKeyId', 'bad key', 403),
    ];
    let index = 0;
    const { layer } = stubbedLayer(() => failures[index++ % failures.length]!);

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

      const s3Issues = result.issues.filter((issue) => issue.service === 'S3');
      expect(s3Issues.length).toBeGreaterThan(0);
      for (const issue of s3Issues) {
        expect(issue.kind).not.toBe('unknown');
        expect(issue.message).toBeTruthy();
      }
      expect(
        (result.data?.findings ?? []).filter((finding) => finding.checkId.startsWith('s3'))
      ).toHaveLength(0);
    });
  });
});
