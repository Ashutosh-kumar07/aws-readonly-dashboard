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
import { GLOBAL_ENDPOINT_REGION, GLOBAL_SCOPE } from '../../../aws/regions.js';
import { buildFinding, type CheckContext, type CheckResult, type SecurityCheck } from '../types.js';
import { evaluated, issueFor, notEvaluated } from '../check-utils.js';
import type { EvaluationIssue } from '../../types.js';

const CHECK_ID = 's3-public-access';
const ACCOUNT_CHECK_ID = 's3-account-public-access-block';
/** Default bucket cap, overridden by `security.maxBucketsPerScan`. */
const DEFAULT_MAX_BUCKETS = 250;

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

    let bucketNames: string[];
    try {
      const output = await globalClient.send<ListBucketsCommandOutput>(new ListBucketsCommand({}), {
        section: context.section,
      });
      bucketNames = (output.Buckets ?? [])
        .map((bucket) => bucket.Name)
        .filter((name): name is string => Boolean(name));
    } catch (error) {
      return notEvaluated([
        issueFor(context, error, {
          service: 'S3',
          check: CHECK_ID,
          requiredPermission: 's3:ListAllMyBuckets',
        }),
      ]);
    }

    const inspected = bucketNames.slice(
      0,
      context.config.security.maxBucketsPerScan ?? DEFAULT_MAX_BUCKETS
    );
    const issues: EvaluationIssue[] = [];
    const findings: CheckResult['findings'] = [];
    const deniedPermissions = new Set<string>();

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

    await mapWithConcurrency(inspected, 8, async (bucket) => {
      let region = GLOBAL_ENDPOINT_REGION;
      try {
        const location = await globalClient.send<GetBucketLocationCommandOutput>(
          new GetBucketLocationCommand({ Bucket: bucket }),
          { section: context.section }
        );
        region = location.LocationConstraint || GLOBAL_ENDPOINT_REGION;
      } catch (error) {
        recordIssue(error, 's3:GetBucketLocation', 'resolving bucket region', bucket);
      }

      const regional = context.access.client('s3', S3Client, {
        profile: context.profile,
        region,
      });
      const assessment: BucketAssessment = { name: bucket, region };

      try {
        const status = await regional.send<GetBucketPolicyStatusCommandOutput>(
          new GetBucketPolicyStatusCommand({ Bucket: bucket }),
          { section: context.section }
        );
        assessment.isPublicByPolicy = status.PolicyStatus?.IsPublic === true;
      } catch (error) {
        const classified = classifyAwsError(error);
        if (classified.kind !== 'not-found') {
          recordIssue(error, 's3:GetBucketPolicyStatus', 'reading bucket policy status', bucket);
        } else {
          assessment.isPublicByPolicy = false;
        }
      }

      try {
        const pab = await regional.send<GetPublicAccessBlockCommandOutput>(
          new GetPublicAccessBlockCommand({ Bucket: bucket }),
          { section: context.section }
        );
        assessment.publicAccessBlock = pab.PublicAccessBlockConfiguration ?? null;
      } catch (error) {
        const classified = classifyAwsError(error);
        if (classified.kind === 'not-found') assessment.publicAccessBlock = null;
        else
          recordIssue(
            error,
            's3:GetBucketPublicAccessBlock',
            'reading Block Public Access',
            bucket
          );
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
      } catch (error) {
        recordIssue(error, 's3:GetBucketAcl', 'reading bucket ACL', bucket);
      }

      try {
        await regional.send<GetBucketEncryptionCommandOutput>(
          new GetBucketEncryptionCommand({ Bucket: bucket }),
          { section: context.section }
        );
        assessment.encryption = 'enabled';
      } catch (error) {
        const classified = classifyAwsError(error);
        if (classified.kind === 'not-found') assessment.encryption = 'none';
        else
          recordIssue(error, 's3:GetEncryptionConfiguration', 'reading default encryption', bucket);
      }

      const pab = assessment.publicAccessBlock;
      const fullyBlocked =
        pab?.BlockPublicAcls === true &&
        pab?.IgnorePublicAcls === true &&
        pab?.BlockPublicPolicy === true &&
        pab?.RestrictPublicBuckets === true;

      if (assessment.isPublicByPolicy) {
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

      if (assessment.publicAcl && assessment.publicAcl.length > 0) {
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

      if (
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

      if (assessment.encryption === 'none') {
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

    const truncated = bucketNames.length > inspected.length;
    if (truncated) {
      issues.push({
        profile: context.profile,
        ...(context.accountId ? { accountId: context.accountId } : {}),
        region: GLOBAL_SCOPE,
        service: 'S3',
        check: CHECK_ID,
        kind: 'unknown',
        label: `Partially evaluated — ${inspected.length} of ${bucketNames.length} buckets inspected`,
        message:
          `${bucketNames.length - inspected.length} bucket(s) were not examined, because the scan limit was reached. ` +
          'Raise "S3 buckets per scan" in Settings to cover them, at the cost of more AWS API calls.',
      });
    }

    return {
      findings,
      issues,
      evaluated: true,
      resourcesEvaluated: inspected.length,
      truncated,
    };
  },
};
