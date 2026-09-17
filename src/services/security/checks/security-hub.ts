/** Active AWS Security Hub findings. */

import {
  SecurityHubClient,
  DescribeHubCommand,
  GetFindingsCommand,
  type DescribeHubCommandOutput,
  type GetFindingsCommandOutput,
} from '@aws-sdk/client-securityhub';

import { classifyAwsError } from '../../../util/errors.js';
import { buildFinding, type CheckContext, type CheckResult, type SecurityCheck } from '../types.js';
import { evaluated, issueFor, labelSeverity, notEvaluated, truncateText } from '../check-utils.js';

const CHECK_ID = 'security-hub-findings';
const MAX_PAGES = 5;
const PAGE_SIZE = 100;

export const securityHubCheck: SecurityCheck = {
  id: CHECK_ID,
  title: 'Security Hub findings',
  service: 'Security Hub',
  scope: 'regional',
  description: 'Imports active, non-archived Security Hub findings for the region.',
  requiredPermissions: ['securityhub:DescribeHub', 'securityhub:GetFindings'],

  async run(context: CheckContext): Promise<CheckResult> {
    const client = context.access.client('securityhub', SecurityHubClient, {
      profile: context.profile,
      region: context.region,
    });

    try {
      await client.send<DescribeHubCommandOutput>(new DescribeHubCommand({}), {
        section: context.section,
      });
    } catch (error) {
      const classified = classifyAwsError(error);
      // "Not subscribed" is a legitimate configuration, not a permission gap —
      // but it is still not evidence that the account is secure.
      return notEvaluated([
        issueFor(context, error, {
          service: 'Security Hub',
          check: CHECK_ID,
          requiredPermission: 'securityhub:DescribeHub',
          detail:
            classified.kind === 'not-subscribed' || classified.kind === 'invalid-request'
              ? 'Security Hub does not appear to be enabled in this region'
              : 'checking whether Security Hub is enabled',
        }),
      ]);
    }

    const findings: CheckResult['findings'] = [];
    let token: string | undefined;
    let pages = 0;

    try {
      do {
        const output = await client.send<GetFindingsCommandOutput>(
          new GetFindingsCommand({
            Filters: {
              RecordState: [{ Value: 'ACTIVE', Comparison: 'EQUALS' }],
              WorkflowStatus: [
                { Value: 'NEW', Comparison: 'EQUALS' },
                { Value: 'NOTIFIED', Comparison: 'EQUALS' },
              ],
              SeverityLabel: [
                { Value: 'CRITICAL', Comparison: 'EQUALS' },
                { Value: 'HIGH', Comparison: 'EQUALS' },
                { Value: 'MEDIUM', Comparison: 'EQUALS' },
              ],
            },
            MaxResults: PAGE_SIZE,
            ...(token ? { NextToken: token } : {}),
          }),
          { section: context.section }
        );

        for (const finding of output.Findings ?? []) {
          const resource = finding.Resources?.[0];
          findings.push(
            buildFinding({
              context,
              checkId: CHECK_ID,
              title: finding.Title ?? 'Security Hub finding',
              severity: labelSeverity(finding.Severity?.Label),
              resourceType: resource?.Type ?? 'AWS::SecurityHub::Finding',
              resourceId: resource?.Id ?? finding.Id ?? 'unknown',
              ...(resource?.Id?.startsWith('arn:') ? { resourceArn: resource.Id } : {}),
              source: `Security Hub (${finding.ProductName ?? 'AWS'})`,
              discriminator: finding.GeneratorId ?? finding.Id ?? '',
              evidence: {
                findingId: finding.Id,
                generatorId: finding.GeneratorId,
                productName: finding.ProductName,
                complianceStatus: finding.Compliance?.Status,
                description: truncateText(finding.Description),
                resources: (finding.Resources ?? []).map((item) => ({
                  id: item.Id,
                  type: item.Type,
                })),
                firstObservedAt: finding.FirstObservedAt,
                updatedAt: finding.UpdatedAt,
              },
              why:
                truncateText(finding.Description) ||
                'Security Hub reported this control or detection as failing.',
              recommendation:
                truncateText(finding.Remediation?.Recommendation?.Text) ||
                'Open this finding in the Security Hub console and follow the remediation guidance shown there.',
            })
          );
        }

        token = output.NextToken;
        pages += 1;
      } while (token && pages < MAX_PAGES);
    } catch (error) {
      return notEvaluated(
        [
          issueFor(context, error, {
            service: 'Security Hub',
            check: CHECK_ID,
            requiredPermission: 'securityhub:GetFindings',
          }),
        ],
        findings
      );
    }

    return evaluated({ findings, resourcesEvaluated: findings.length, truncated: Boolean(token) });
  },
};
