/** CloudTrail configuration checks: coverage, delivery and log integrity. */

import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetTrailStatusCommand,
  type DescribeTrailsCommandOutput,
  type GetTrailStatusCommandOutput,
} from '@aws-sdk/client-cloudtrail';

import { buildFinding, type CheckContext, type CheckResult, type SecurityCheck } from '../types.js';
import { evaluated, issueFor, notEvaluated } from '../check-utils.js';
import type { EvaluationIssue } from '../../types.js';

const CHECK_ID = 'cloudtrail-configuration';

export const cloudTrailConfigurationCheck: SecurityCheck = {
  id: CHECK_ID,
  title: 'CloudTrail coverage and integrity',
  service: 'CloudTrail',
  scope: 'regional',
  description:
    'Verifies that the region is covered by a trail, that the trail is actively delivering, and that log file validation is enabled.',
  requiredPermissions: ['cloudtrail:DescribeTrails', 'cloudtrail:GetTrailStatus'],

  async run(context: CheckContext): Promise<CheckResult> {
    const client = context.access.client('cloudtrail', CloudTrailClient, {
      profile: context.profile,
      region: context.region,
    });

    let trails: DescribeTrailsCommandOutput['trailList'];
    try {
      const output = await client.send<DescribeTrailsCommandOutput>(
        new DescribeTrailsCommand({ includeShadowTrails: true }),
        { section: context.section }
      );
      trails = output.trailList ?? [];
    } catch (error) {
      return notEvaluated([
        issueFor(context, error, {
          service: 'CloudTrail',
          check: CHECK_ID,
          requiredPermission: 'cloudtrail:DescribeTrails',
        }),
      ]);
    }

    const findings: CheckResult['findings'] = [];
    const issues: EvaluationIssue[] = [];

    if (trails.length === 0) {
      return evaluated({
        findings: [
          buildFinding({
            context,
            checkId: CHECK_ID,
            title: 'No CloudTrail trail covers this region',
            severity: 'high',
            resourceType: 'AWS::CloudTrail::Trail',
            resourceId: `cloudtrail-${context.region}`,
            source: 'CloudTrail',
            discriminator: 'missing-trail',
            evidence: { region: context.region, trails: [] },
            why: 'Without a trail, management events in this region are not recorded beyond the 90-day CloudTrail event history, so incident investigation and the CloudTrail search in this dashboard are both limited.',
            recommendation:
              'Create a multi-region organisation trail in the CloudTrail console so every region is covered.',
          }),
        ],
        resourcesEvaluated: 0,
      });
    }

    const hasMultiRegion = trails.some((trail) => trail.IsMultiRegionTrail === true);
    if (!hasMultiRegion) {
      findings.push(
        buildFinding({
          context,
          checkId: CHECK_ID,
          title: 'No multi-region CloudTrail trail is present',
          severity: 'medium',
          resourceType: 'AWS::CloudTrail::Trail',
          resourceId: `cloudtrail-multi-region-${context.region}`,
          source: 'CloudTrail',
          discriminator: 'no-multi-region-trail',
          evidence: {
            trails: trails.map((trail) => ({ name: trail.Name, homeRegion: trail.HomeRegion })),
          },
          why: 'Single-region trails leave other regions unlogged, which is where unexpected activity often appears first.',
          recommendation:
            'Convert an existing trail to multi-region, or create a new multi-region trail.',
        })
      );
    }

    for (const trail of trails) {
      if (!trail.Name) continue;
      // Shadow trails belong to another region; their status lives at home.
      const isShadow = trail.HomeRegion !== undefined && trail.HomeRegion !== context.region;

      if (trail.LogFileValidationEnabled !== true && !isShadow) {
        findings.push(
          buildFinding({
            context,
            checkId: CHECK_ID,
            title: `CloudTrail trail ${trail.Name} does not have log file validation enabled`,
            severity: 'medium',
            resourceType: 'AWS::CloudTrail::Trail',
            resourceId: trail.Name,
            ...(trail.TrailARN ? { resourceArn: trail.TrailARN } : {}),
            source: 'CloudTrail',
            discriminator: 'log-file-validation',
            evidence: {
              name: trail.Name,
              logFileValidationEnabled: trail.LogFileValidationEnabled ?? false,
              s3BucketName: trail.S3BucketName,
              isMultiRegionTrail: trail.IsMultiRegionTrail,
            },
            why: 'Without log file validation you cannot prove that delivered CloudTrail logs were not modified or deleted.',
            recommendation: 'Enable log file validation on the trail in the CloudTrail console.',
          })
        );
      }

      if (isShadow) continue;

      try {
        const status = await client.send<GetTrailStatusCommandOutput>(
          new GetTrailStatusCommand({ Name: trail.TrailARN ?? trail.Name }),
          { section: context.section }
        );
        if (status.IsLogging !== true) {
          findings.push(
            buildFinding({
              context,
              checkId: CHECK_ID,
              title: `CloudTrail trail ${trail.Name} is not logging`,
              severity: 'high',
              resourceType: 'AWS::CloudTrail::Trail',
              resourceId: trail.Name,
              ...(trail.TrailARN ? { resourceArn: trail.TrailARN } : {}),
              source: 'CloudTrail',
              discriminator: 'not-logging',
              evidence: {
                name: trail.Name,
                isLogging: status.IsLogging ?? false,
                latestDeliveryTime: status.LatestDeliveryTime,
                latestDeliveryError: status.LatestDeliveryError,
              },
              why: 'The trail exists but is stopped, so no new events are being recorded.',
              recommendation: 'Start logging on the trail in the CloudTrail console.',
            })
          );
        } else if (status.LatestDeliveryError) {
          findings.push(
            buildFinding({
              context,
              checkId: CHECK_ID,
              title: `CloudTrail trail ${trail.Name} is failing to deliver logs`,
              severity: 'high',
              resourceType: 'AWS::CloudTrail::Trail',
              resourceId: trail.Name,
              ...(trail.TrailARN ? { resourceArn: trail.TrailARN } : {}),
              source: 'CloudTrail',
              discriminator: 'delivery-error',
              evidence: {
                name: trail.Name,
                latestDeliveryError: status.LatestDeliveryError,
                latestDeliveryTime: status.LatestDeliveryTime,
                s3BucketName: trail.S3BucketName,
              },
              why: 'CloudTrail cannot write to the destination bucket, so events are being lost.',
              recommendation:
                'Check the destination bucket policy and KMS key policy referenced by the delivery error in the CloudTrail console.',
            })
          );
        }
      } catch (error) {
        issues.push(
          issueFor(context, error, {
            service: 'CloudTrail',
            check: CHECK_ID,
            requiredPermission: 'cloudtrail:GetTrailStatus',
            detail: `reading status for trail ${trail.Name}`,
          })
        );
      }
    }

    return { findings, issues, evaluated: issues.length === 0, resourcesEvaluated: trails.length };
  },
};
