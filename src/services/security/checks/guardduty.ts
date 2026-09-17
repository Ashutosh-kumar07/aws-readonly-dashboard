/** Active GuardDuty findings. */

import {
  GuardDutyClient,
  ListDetectorsCommand,
  ListFindingsCommand,
  GetFindingsCommand,
  type ListDetectorsCommandOutput,
  type ListFindingsCommandOutput,
  type GetFindingsCommandOutput,
} from '@aws-sdk/client-guardduty';

import { buildFinding, type CheckContext, type CheckResult, type SecurityCheck } from '../types.js';
import {
  evaluated,
  issueFor,
  notEvaluated,
  numericSeverity,
  truncateText,
} from '../check-utils.js';

const CHECK_ID = 'guardduty-findings';
const MAX_FINDINGS = 50;

export const guardDutyCheck: SecurityCheck = {
  id: CHECK_ID,
  title: 'GuardDuty findings',
  service: 'GuardDuty',
  scope: 'regional',
  description:
    'Imports non-archived GuardDuty findings for the region, newest and most severe first.',
  requiredPermissions: [
    'guardduty:ListDetectors',
    'guardduty:ListFindings',
    'guardduty:GetFindings',
  ],

  async run(context: CheckContext): Promise<CheckResult> {
    const client = context.access.client('guardduty', GuardDutyClient, {
      profile: context.profile,
      region: context.region,
    });

    let detectorIds: string[];
    try {
      const output = await client.send<ListDetectorsCommandOutput>(new ListDetectorsCommand({}), {
        section: context.section,
      });
      detectorIds = output.DetectorIds ?? [];
    } catch (error) {
      return notEvaluated([
        issueFor(context, error, {
          service: 'GuardDuty',
          check: CHECK_ID,
          requiredPermission: 'guardduty:ListDetectors',
        }),
      ]);
    }

    if (detectorIds.length === 0) {
      return notEvaluated([
        {
          profile: context.profile,
          ...(context.accountId ? { accountId: context.accountId } : {}),
          region: context.region,
          service: 'GuardDuty',
          check: CHECK_ID,
          kind: 'not-subscribed',
          label: 'Unable to evaluate — GuardDuty is not enabled in this region',
          message:
            'No GuardDuty detector exists in this region, so no threat detection data is available. This is not evidence that the account is free of threats.',
        },
      ]);
    }

    const findings: CheckResult['findings'] = [];

    for (const detectorId of detectorIds) {
      let findingIds: string[];
      try {
        const listed = await client.send<ListFindingsCommandOutput>(
          new ListFindingsCommand({
            DetectorId: detectorId,
            FindingCriteria: { Criterion: { 'service.archived': { Eq: ['false'] } } },
            SortCriteria: { AttributeName: 'severity', OrderBy: 'DESC' },
            MaxResults: MAX_FINDINGS,
          }),
          { section: context.section }
        );
        findingIds = listed.FindingIds ?? [];
      } catch (error) {
        return notEvaluated(
          [
            issueFor(context, error, {
              service: 'GuardDuty',
              check: CHECK_ID,
              requiredPermission: 'guardduty:ListFindings',
            }),
          ],
          findings
        );
      }

      if (findingIds.length === 0) continue;

      try {
        const detail = await client.send<GetFindingsCommandOutput>(
          new GetFindingsCommand({ DetectorId: detectorId, FindingIds: findingIds }),
          { section: context.section }
        );

        for (const finding of detail.Findings ?? []) {
          const resourceType = finding.Resource?.ResourceType ?? 'AWS::GuardDuty::Finding';
          const resourceId =
            finding.Resource?.InstanceDetails?.InstanceId ??
            finding.Resource?.AccessKeyDetails?.UserName ??
            finding.Resource?.S3BucketDetails?.[0]?.Name ??
            finding.Id ??
            'unknown';
          findings.push(
            buildFinding({
              context,
              checkId: CHECK_ID,
              title: finding.Title ?? finding.Type ?? 'GuardDuty finding',
              severity: numericSeverity(finding.Severity),
              resourceType,
              resourceId,
              source: 'GuardDuty',
              discriminator: finding.Id ?? finding.Type ?? '',
              evidence: {
                findingId: finding.Id,
                type: finding.Type,
                severityScore: finding.Severity,
                count: finding.Service?.Count,
                firstSeenAt: finding.Service?.EventFirstSeen,
                lastSeenAt: finding.Service?.EventLastSeen,
                resourceType,
                description: truncateText(finding.Description),
              },
              why:
                truncateText(finding.Description) ||
                'GuardDuty detected suspicious activity for this resource.',
              recommendation:
                'Investigate this finding in the GuardDuty console, confirm whether the activity is expected, and follow the documented response for this finding type.',
            })
          );
        }
      } catch (error) {
        return notEvaluated(
          [
            issueFor(context, error, {
              service: 'GuardDuty',
              check: CHECK_ID,
              requiredPermission: 'guardduty:GetFindings',
            }),
          ],
          findings
        );
      }
    }

    return evaluated({ findings, resourcesEvaluated: findings.length });
  },
};
