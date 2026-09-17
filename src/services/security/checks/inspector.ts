/** Amazon Inspector (v2) findings. */

import {
  Inspector2Client,
  BatchGetAccountStatusCommand,
  ListFindingsCommand,
  type BatchGetAccountStatusCommandOutput,
  type ListFindingsCommandOutput,
} from '@aws-sdk/client-inspector2';

import { buildFinding, type CheckContext, type CheckResult, type SecurityCheck } from '../types.js';
import { evaluated, issueFor, labelSeverity, notEvaluated, truncateText } from '../check-utils.js';

const CHECK_ID = 'inspector-findings';
const MAX_FINDINGS = 100;

export const inspectorCheck: SecurityCheck = {
  id: CHECK_ID,
  title: 'Inspector findings',
  service: 'Inspector',
  scope: 'regional',
  description:
    'Imports active Amazon Inspector findings (software vulnerabilities and network reachability).',
  requiredPermissions: ['inspector2:BatchGetAccountStatus', 'inspector2:ListFindings'],

  async run(context: CheckContext): Promise<CheckResult> {
    const client = context.access.client('inspector2', Inspector2Client, {
      profile: context.profile,
      region: context.region,
    });

    try {
      const status = await client.send<BatchGetAccountStatusCommandOutput>(
        new BatchGetAccountStatusCommand({}),
        { section: context.section }
      );
      const enabled = (status.accounts ?? []).some(
        (account) => account.state?.status === 'ENABLED' || account.state?.status === 'ENABLING'
      );
      if (!enabled) {
        return notEvaluated([
          {
            profile: context.profile,
            ...(context.accountId ? { accountId: context.accountId } : {}),
            region: context.region,
            service: 'Inspector',
            check: CHECK_ID,
            kind: 'not-subscribed',
            label: 'Unable to evaluate — Inspector is not enabled in this region',
            message:
              'Amazon Inspector is not enabled for this account and region, so no vulnerability data is available.',
          },
        ]);
      }
    } catch (error) {
      return notEvaluated([
        issueFor(context, error, {
          service: 'Inspector',
          check: CHECK_ID,
          requiredPermission: 'inspector2:BatchGetAccountStatus',
        }),
      ]);
    }

    try {
      const output = await client.send<ListFindingsCommandOutput>(
        new ListFindingsCommand({
          filterCriteria: {
            findingStatus: [{ comparison: 'EQUALS', value: 'ACTIVE' }],
            severity: [
              { comparison: 'EQUALS', value: 'CRITICAL' },
              { comparison: 'EQUALS', value: 'HIGH' },
              { comparison: 'EQUALS', value: 'MEDIUM' },
            ],
          },
          maxResults: MAX_FINDINGS,
        }),
        { section: context.section }
      );

      const findings = (output.findings ?? []).map((finding) => {
        const resource = finding.resources?.[0];
        return buildFinding({
          context,
          checkId: CHECK_ID,
          title: finding.title ?? 'Inspector finding',
          severity: labelSeverity(finding.severity),
          resourceType: resource?.type ?? 'AWS::Inspector::Finding',
          resourceId: resource?.id ?? finding.findingArn ?? 'unknown',
          ...(finding.findingArn ? { resourceArn: finding.findingArn } : {}),
          source: 'Inspector',
          discriminator: finding.findingArn ?? '',
          evidence: {
            findingArn: finding.findingArn,
            type: finding.type,
            inspectorScore: finding.inspectorScore,
            firstObservedAt: finding.firstObservedAt,
            lastObservedAt: finding.lastObservedAt,
            packageVulnerability: finding.packageVulnerabilityDetails?.vulnerabilityId,
            resources: (finding.resources ?? []).map((item) => ({ id: item.id, type: item.type })),
            description: truncateText(finding.description),
          },
          why:
            truncateText(finding.description) ||
            'Inspector reported this vulnerability or exposure.',
          recommendation:
            truncateText(finding.remediation?.recommendation?.text) ||
            'Review the finding in the Inspector console and patch or reconfigure the affected resource.',
        });
      });

      return evaluated({
        findings,
        resourcesEvaluated: findings.length,
        truncated: Boolean(output.nextToken),
      });
    } catch (error) {
      return notEvaluated([
        issueFor(context, error, {
          service: 'Inspector',
          check: CHECK_ID,
          requiredPermission: 'inspector2:ListFindings',
        }),
      ]);
    }
  },
};
