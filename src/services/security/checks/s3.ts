/**
 * S3 bucket exposure.
 *
 * Buckets live in a global namespace, so this is a global check; each finding
 * still carries the bucket's real region so the dashboard never mislabels a
 * regional resource.
 */

import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  GetBucketPolicyStatusCommand,
  GetPublicAccessBlockCommand,
  GetBucketAclCommand,
  GetBucketEncryptionCommand,
  type ListBucketsCommandOutput,
  type GetBucketLocationCommandOutput,
  type GetBucketPolicyStatusCommandOutput,
  type GetPublicAccessBlockCommandOutput,
  type GetBucketAclCommandOutput,
  type GetBucketEncryptionCommandOutput,
} from '@aws-sdk/client-s3';
import {
  S3ControlClient,
  GetPublicAccessBlockCommand as GetAccountPublicAccessBlockCommand,
  type GetPublicAccessBlockCommandOutput as GetAccountPublicAccessBlockCommandOutput,
} from '@aws-sdk/client-s3-control';

import { classifyAwsError } from '../../../util/errors.js';
import { mapWithConcurrency } from '../../../util/async.js';
import { GLOBAL_SCOPE, regionFromLocationConstraint } from '../../../aws/regions.js';
import { buildFinding, type CheckContext, type CheckResult, type SecurityCheck } from '../types.js';
import { evaluated, issueFor, notEvaluated } from '../check-utils.js';
import type { EvaluationIssue } from '../../types.js';

const CHECK_ID = 's3-public-access';
const ACCOUNT_CHECK_ID = 's3-account-public-access-block';
/** Default bucket cap, overridden by `security.maxBucketsPerScan`. 0 means no cap. */
const DEFAULT_MAX_BUCKETS = 250;

/**
 * Buckets per `ListBuckets` request.
 *
 * Without `MaxBuckets`, S3 assembles the account's entire bucket inventory into
 * a single response, which on a large account takes longer than any sensible
 * request deadline — the listing then fails before a single bucket has been
 * examined. Asking for pages keeps each request small and lets the scan stop as
 * soon as it has the buckets it is allowed to inspect.
 */
const BUCKET_PAGE_SIZE = 1000;

const ALL_USERS_URI = 'http://acs.amazonaws.com/groups/global/AllUsers';
const AUTHENTICATED_USERS_URI = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers';

export const s3AccountPublicAccessBlockCheck: SecurityCheck = {
  id: ACCOUNT_CHECK_ID,
  title: 'Account-level S3 Block Public Access',
  service: 'S3',
  scope: 'global',
  description:
    'Verifies that the account-wide S3 Block Public Access configuration is fully enabled, which prevents any bucket from being made public.',
  requiredPermissions: ['s3:GetAccountPublicAccessBlock'],

  async run(context: CheckContext): Promise<CheckResult> {
    if (!context.accountId) {
      return notEvaluated([
        {
          profile: context.profile,
          region: GLOBAL_SCOPE,
          service: 'S3',
          check: ACCOUNT_CHECK_ID,
          kind: 'authentication',
          label: 'Unable to evaluate — account ID unknown',
          message:
            'The account ID could not be resolved for this profile, so the account-level Block Public Access setting cannot be read.',
        },
      ]);
    }

    const client = context.access.client('s3-control', S3ControlClient, {
      profile: context.profile,
      region: GLOBAL_SCOPE,
    });

    try {
      const output = await client.send<GetAccountPublicAccessBlockCommandOutput>(
        new GetAccountPublicAccessBlockCommand({ AccountId: context.accountId }),
        { section: context.section }
      );
      const config = output.PublicAccessBlockConfiguration ?? {};
      const disabled = Object.entries({
        BlockPublicAcls: config.BlockPublicAcls,
        IgnorePublicAcls: config.IgnorePublicAcls,
        BlockPublicPolicy: config.BlockPublicPolicy,
        RestrictPublicBuckets: config.RestrictPublicBuckets,
      })
        .filter(([, value]) => value !== true)
        .map(([key]) => key);

      if (disabled.length === 0) return evaluated({ resourcesEvaluated: 1 });

      return evaluated({
        resourcesEvaluated: 1,
        findings: [
          buildFinding({
            context,
            checkId: ACCOUNT_CHECK_ID,
            title: 'Account-level S3 Block Public Access is not fully enabled',
            severity: 'medium',
            resourceType: 'AWS::S3::AccountPublicAccessBlock',
            resourceId: context.accountId,
            region: GLOBAL_SCOPE,
            source: 'S3',
            evidence: { configuration: config, disabledSettings: disabled },
            why: 'Without all four account-level settings enabled, an individual bucket can still be made publicly readable or writable by an ACL or bucket policy.',
            recommendation:
              'In the S3 console, enable all four Block Public Access settings at the account level unless a documented workload requires public buckets.',
          }),
        ],
      });
    } catch (error) {
      const classified = classifyAwsError(error);
      if (classified.kind === 'not-found') {
        // No configuration at all means nothing is blocked.
        return evaluated({
          resourcesEvaluated: 1,
          findings: [
            buildFinding({
              context,
              checkId: ACCOUNT_CHECK_ID,
              title: 'No account-level S3 Block Public Access configuration exists',
              severity: 'medium',
              resourceType: 'AWS::S3::AccountPublicAccessBlock',
              resourceId: context.accountId,
              region: GLOBAL_SCOPE,
              source: 'S3',
              evidence: { configuration: null },
              why: 'The account has no Block Public Access configuration, so buckets may be made public by ACL or policy.',
              recommendation:
                'In the S3 console, enable all four Block Public Access settings at the account level.',
            }),
          ],
        });
      }
      return notEvaluated([
        issueFor(context, error, {
          service: 'S3',
          check: ACCOUNT_CHECK_ID,
          requiredPermission: 's3:GetAccountPublicAccessBlock',
        }),
      ]);
    }
  },
};

interface BucketAssessment {
  name: string;
  region: string;
  isPublicByPolicy?: boolean;
  publicAcl?: string[];
  publicAccessBlock?: {
    BlockPublicAcls?: boolean;
    IgnorePublicAcls?: boolean;
    BlockPublicPolicy?: boolean;
    RestrictPublicBuckets?: boolean;
  } | null;
  encryption?: 'enabled' | 'none';
}

/**
 * Which of a bucket's reads produced a definitive answer. A finding may only
 * be raised from reads that actually completed: "AWS did not answer" is not
 * evidence that a bucket is unprotected, and reporting it as though it were
 * manufactures a finding out of a failure.
 */
interface BucketReads {
  policyStatus: boolean;
  acl: boolean;
  publicAccessBlock: boolean;
  encryption: boolean;
}

export const s3PublicAccessCheck: SecurityCheck = {
  id: CHECK_ID,
  title: 'Publicly accessible S3 buckets',
  service: 'S3',
  scope: 'global',
  description:
    'Evaluates every bucket for a public bucket policy, public ACL grants, a missing Block Public Access configuration, and default encryption.',
  requiredPermissions: [
    's3:ListAllMyBuckets',
    's3:GetBucketLocation',
    's3:GetBucketPolicyStatus',
    's3:GetBucketPublicAccessBlock',
    's3:GetBucketAcl',
    's3:GetEncryptionConfiguration',
  ],

  async run(context: CheckContext): Promise<CheckResult> {
    const globalClient = context.access.client('s3', S3Client, {
      profile: context.profile,
      region: GLOBAL_SCOPE,
    });

    const scanLimit = context.config.security.maxBucketsPerScan ?? DEFAULT_MAX_BUCKETS;
    /** Listed buckets, with the region S3 reported for each where it did. */
    const listed: Array<{ name: string; region?: string }> = [];
    let continuationToken: string | undefined;
    let listingError: unknown;
    let page = 0;

    do {
      page += 1;
      const remaining = scanLimit === 0 ? BUCKET_PAGE_SIZE : scanLimit - listed.length;
      try {
        const output = await globalClient.send<ListBucketsCommandOutput>(
          new ListBucketsCommand({
            MaxBuckets: Math.max(1, Math.min(BUCKET_PAGE_SIZE, remaining)),
            ...(continuationToken ? { ContinuationToken: continuationToken } : {}),
          }),
          {
            section: context.section,
            // Named in a deadline message, so a timeout says how far it got.
            detail: `page ${page}, ${listed.length} buckets so far`,
          }
        );
        for (const bucket of output.Buckets ?? []) {
          if (!bucket.Name) continue;
          listed.push({
            name: bucket.Name,
            // S3 reports each bucket's region here, which saves one
            // GetBucketLocation call per bucket.
            ...(bucket.BucketRegion ? { region: bucket.BucketRegion } : {}),
          });
        }
        continuationToken = output.ContinuationToken;
      } catch (error) {
        listingError = error;
        break;
      }
    } while (continuationToken && (scanLimit === 0 || listed.length < scanLimit));

    // Nothing listed at all: there is no partial answer to give.
    if (listingError && listed.length === 0) {
      return notEvaluated([
        issueFor(context, listingError, {
          service: 'S3',
          check: CHECK_ID,
          requiredPermission: 's3:ListAllMyBuckets',
          detail: `listing buckets, page ${page}`,
        }),
      ]);
    }

    const inspected = scanLimit === 0 ? listed : listed.slice(0, scanLimit);
    const issues: EvaluationIssue[] = [];
    const findings: CheckResult['findings'] = [];
    const deniedPermissions = new Set<string>();
    /** Buckets whose evaluation is incomplete, and why. Never silently dropped. */
    const incomplete: Array<{ bucket: string; reason: string }> = [];

    const recordIssue = (
      error: unknown,
      permission: string,
      detail: string,
      bucket: string
    ): void => {
      const classified = classifyAwsError(error);
      if (classified.kind === 'not-found') return;
      // Report each distinct permission gap once rather than once per bucket.
      const key = `${permission}:${classified.kind}`;
      if (deniedPermissions.has(key)) return;
      deniedPermissions.add(key);
      issues.push(
        issueFor(context, error, {
          service: 'S3',
          check: CHECK_ID,
          requiredPermission: permission,
          detail: `${detail} (first seen on bucket ${bucket})`,
        })
      );
    };

    await mapWithConcurrency(inspected, 8, async (entry) => {
      const bucket = entry.name;
      let region: string;
      // The listing already reported the region for most buckets, which saves a
      // GetBucketLocation call for every one of them.
      const listedRegion = entry.region ? regionFromLocationConstraint(entry.region) : undefined;
      try {
        if (listedRegion) {
          region = listedRegion;
        } else {
          const location = await globalClient.send<GetBucketLocationCommandOutput>(
            new GetBucketLocationCommand({ Bucket: bucket }),
            { section: context.section }
          );
          const resolved = regionFromLocationConstraint(location.LocationConstraint);
          if (!resolved) {
            incomplete.push({
              bucket,
              reason: `AWS reported the location as "${String(location.LocationConstraint)}", which is not a region this tool recognises.`,
            });
            return;
          }
          region = resolved;
        }
      } catch (error) {
        recordIssue(error, 's3:GetBucketLocation', 'resolving bucket region', bucket);
        // Without the bucket's region there is nowhere correct to ask. Guessing
        // one sends four more requests to the wrong endpoint, each of which
        // fails for a reason that has nothing to do with the bucket's exposure
        // and reads like a separate permission problem.
        incomplete.push({ bucket, reason: classifyAwsError(error).message });
        return;
      }

      const regional = context.access.client('s3', S3Client, {
        profile: context.profile,
        region,
      });
      const assessment: BucketAssessment = { name: bucket, region };
      const reads: BucketReads = {
        policyStatus: false,
        acl: false,
        publicAccessBlock: false,
        encryption: false,
      };

      try {
        const status = await regional.send<GetBucketPolicyStatusCommandOutput>(
          new GetBucketPolicyStatusCommand({ Bucket: bucket }),
          { section: context.section }
        );
        assessment.isPublicByPolicy = status.PolicyStatus?.IsPublic === true;
        reads.policyStatus = true;
      } catch (error) {
        const classified = classifyAwsError(error);
        if (classified.kind !== 'not-found') {
          recordIssue(error, 's3:GetBucketPolicyStatus', 'reading bucket policy status', bucket);
          incomplete.push({ bucket, reason: `policy status: ${classified.message}` });
        } else {
          // No policy at all is a definitive answer: the bucket is not public
          // by policy.
          assessment.isPublicByPolicy = false;
          reads.policyStatus = true;
        }
      }

      try {
        const pab = await regional.send<GetPublicAccessBlockCommandOutput>(
          new GetPublicAccessBlockCommand({ Bucket: bucket }),
          { section: context.section }
        );
        assessment.publicAccessBlock = pab.PublicAccessBlockConfiguration ?? null;
        reads.publicAccessBlock = true;
      } catch (error) {
        const classified = classifyAwsError(error);
        if (classified.kind === 'not-found') {
          // No configuration is itself the answer: nothing is blocked.
          assessment.publicAccessBlock = null;
          reads.publicAccessBlock = true;
        } else {
          recordIssue(
            error,
            's3:GetBucketPublicAccessBlock',
            'reading Block Public Access',
            bucket
          );
          incomplete.push({ bucket, reason: `Block Public Access: ${classified.message}` });
        }
      }

      try {
        const acl = await regional.send<GetBucketAclCommandOutput>(
          new GetBucketAclCommand({ Bucket: bucket }),
          { section: context.section }
        );
        assessment.publicAcl = (acl.Grants ?? [])
          .filter(
            (grant) =>
              grant.Grantee?.URI === ALL_USERS_URI || grant.Grantee?.URI === AUTHENTICATED_USERS_URI
          )
          .map(
            (grant) =>
              `${grant.Grantee?.URI === ALL_USERS_URI ? 'AllUsers' : 'AuthenticatedUsers'}:${grant.Permission}`
          );
        reads.acl = true;
      } catch (error) {
        recordIssue(error, 's3:GetBucketAcl', 'reading bucket ACL', bucket);
        incomplete.push({ bucket, reason: `ACL: ${classifyAwsError(error).message}` });
      }

      try {
        await regional.send<GetBucketEncryptionCommandOutput>(
          new GetBucketEncryptionCommand({ Bucket: bucket }),
          { section: context.section }
        );
        assessment.encryption = 'enabled';
        reads.encryption = true;
      } catch (error) {
        const classified = classifyAwsError(error);
        if (classified.kind === 'not-found') {
          assessment.encryption = 'none';
          reads.encryption = true;
        } else {
          recordIssue(error, 's3:GetEncryptionConfiguration', 'reading default encryption', bucket);
          incomplete.push({ bucket, reason: `default encryption: ${classified.message}` });
        }
      }

      const pab = assessment.publicAccessBlock;
      const fullyBlocked =
        pab?.BlockPublicAcls === true &&
        pab?.IgnorePublicAcls === true &&
        pab?.BlockPublicPolicy === true &&
        pab?.RestrictPublicBuckets === true;

      if (reads.policyStatus && assessment.isPublicByPolicy) {
        findings.push(
          buildFinding({
            context,
            checkId: CHECK_ID,
            region: assessment.region,
            title: `S3 bucket ${bucket} is public through its bucket policy`,
            severity: 'critical',
            resourceType: 'AWS::S3::Bucket',
            resourceId: bucket,
            resourceArn: `arn:aws:s3:::${bucket}`,
            source: 'S3',
            discriminator: 'policy',
            evidence: {
              bucket,
              region: assessment.region,
              policyStatusIsPublic: true,
              publicAccessBlock: pab,
            },
            why: 'AWS reports this bucket policy as public, so its objects may be readable or writable by anyone on the internet.',
            recommendation:
              'Review the bucket policy in the S3 console, remove the public statements, and enable Block Public Access for the bucket unless public hosting is intentional.',
          })
        );
      }

      if (reads.acl && assessment.publicAcl && assessment.publicAcl.length > 0) {
        findings.push(
          buildFinding({
            context,
            checkId: CHECK_ID,
            region: assessment.region,
            title: `S3 bucket ${bucket} grants access through a public ACL`,
            severity: 'critical',
            resourceType: 'AWS::S3::Bucket',
            resourceId: bucket,
            resourceArn: `arn:aws:s3:::${bucket}`,
            source: 'S3',
            discriminator: 'acl',
            evidence: { bucket, region: assessment.region, grants: assessment.publicAcl },
            why: 'The bucket ACL grants permissions to the AllUsers or AuthenticatedUsers group, which is effectively public access.',
            recommendation:
              'Remove the public ACL grants in the S3 console and enable Block Public Access for the bucket.',
          })
        );
      }

      // "Not public today, but nothing stops it becoming public" is a claim
      // about all three controls at once, so it needs all three reads. With any
      // of them missing the bucket is reported as incomplete above instead.
      if (
        reads.publicAccessBlock &&
        reads.policyStatus &&
        reads.acl &&
        !fullyBlocked &&
        !assessment.isPublicByPolicy &&
        (assessment.publicAcl?.length ?? 0) === 0
      ) {
        findings.push(
          buildFinding({
            context,
            checkId: CHECK_ID,
            region: assessment.region,
            title: `S3 bucket ${bucket} does not have full Block Public Access`,
            severity: 'medium',
            resourceType: 'AWS::S3::Bucket',
            resourceId: bucket,
            resourceArn: `arn:aws:s3:::${bucket}`,
            source: 'S3',
            discriminator: 'block-public-access',
            evidence: { bucket, region: assessment.region, publicAccessBlock: pab },
            why: 'The bucket is not public today, but nothing prevents a future ACL or policy change from making it public.',
            recommendation:
              'Enable all four Block Public Access settings on the bucket in the S3 console.',
          })
        );
      }

      if (reads.encryption && assessment.encryption === 'none') {
        findings.push(
          buildFinding({
            context,
            checkId: CHECK_ID,
            region: assessment.region,
            title: `S3 bucket ${bucket} has no default encryption configuration`,
            severity: 'low',
            resourceType: 'AWS::S3::Bucket',
            resourceId: bucket,
            resourceArn: `arn:aws:s3:::${bucket}`,
            source: 'S3',
            discriminator: 'encryption',
            evidence: { bucket, region: assessment.region, defaultEncryption: null },
            why: 'No default encryption configuration is set on the bucket, so objects rely on per-request encryption settings.',
            recommendation:
              'Set default encryption (SSE-S3 or SSE-KMS) on the bucket in the S3 console.',
          })
        );
      }
    });

    // Buckets that could not be fully inspected are named, with the reason, so
    // an incomplete scan is visibly incomplete rather than quietly thinner.
    const incompleteBuckets = [...new Set(incomplete.map((entry) => entry.bucket))];
    if (incompleteBuckets.length > 0) {
      const first = incomplete[0];
      issues.push({
        profile: context.profile,
        ...(context.accountId ? { accountId: context.accountId } : {}),
        region: GLOBAL_SCOPE,
        service: 'S3',
        check: CHECK_ID,
        kind: 'partial',
        label: `Partially evaluated — ${incompleteBuckets.length} of ${inspected.length} buckets could not be fully inspected`,
        message:
          `These buckets were skipped or only partly read, so they are not reported as secure: ${incompleteBuckets
            .slice(0, 10)
            .join(', ')}${incompleteBuckets.length > 10 ? ', …' : ''}. ` +
          (first ? `First reason — ${first.bucket}: ${first.reason}` : ''),
      });
    }

    // The listing is paginated, so the account's full bucket count is only
    // known when the last page was reached: "more exist" is what can honestly
    // be said, and the counts never imply a total that was never counted.
    const moreBucketsExist = Boolean(continuationToken) || listed.length > inspected.length;
    const truncated = moreBucketsExist || Boolean(listingError) || incompleteBuckets.length > 0;

    if (listingError) {
      issues.push(
        issueFor(context, listingError, {
          service: 'S3',
          check: CHECK_ID,
          requiredPermission: 's3:ListAllMyBuckets',
          detail: `listing buckets, page ${page} — ${listed.length} listed before it failed`,
        })
      );
    }

    if (moreBucketsExist) {
      issues.push({
        profile: context.profile,
        ...(context.accountId ? { accountId: context.accountId } : {}),
        region: GLOBAL_SCOPE,
        service: 'S3',
        check: CHECK_ID,
        kind: 'partial',
        label: `Partially evaluated — ${inspected.length} buckets inspected, more exist`,
        message:
          `The account has more buckets than the scan limit of ${scanLimit}, so the rest were not examined. ` +
          'Inspecting them all costs up to five read calls per bucket; results appear as the scan runs.',
        suggestion: {
          setting: 'maxBucketsPerScan',
          value: 0,
          label: 'Inspect every bucket',
        },
      });
    }

    return {
      findings,
      issues,
      // The check ran; `resourcesEvaluated` counts only the buckets it could
      // actually answer for.
      evaluated: true,
      resourcesEvaluated: inspected.length - incompleteBuckets.length,
      truncated,
    };
  },
};
