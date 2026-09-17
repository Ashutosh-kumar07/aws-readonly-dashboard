/**
 * Trusted Advisor security checks.
 *
 * The Support API requires a Business, Enterprise On-Ramp or Enterprise support
 * plan. When it is unavailable the dashboard reports that the check could not be
 * evaluated — never that the account is clean.
 */

import {
  SupportClient,
  DescribeTrustedAdvisorChecksCommand,
  DescribeTrustedAdvisorCheckSummariesCommand,
  type DescribeTrustedAdvisorChecksCommandOutput,
  type DescribeTrustedAdvisorCheckSummariesCommandOutput,
} from '@aws-sdk/client-support';

import { GLOBAL_SCOPE } from '../../../aws/regions.js';
import {
  buildFinding,
  type CheckContext,
  type CheckResult,
  type SecurityCheck,
  type Severity,
} from '../types.js';
import { evaluated, issueFor, notEvaluated, truncateText } from '../check-utils.js';

const CHECK_ID = 'trusted-advisor-security';
const RELEVANT_CATEGORIES = new Set(['security', 'fault_tolerance']);

function severityForStatus(status: string | undefined): Severity {
  switch (status) {
    case 'error':
      return 'high';
    case 'warning':
      return 'medium';
    default:
      return 'low';
  }
}

export const trustedAdvisorCheck: SecurityCheck = {
  id: CHECK_ID,
  title: 'Trusted Advisor security recommendations',
  service: 'Trusted Advisor',
  scope: 'global',
  description:
    'Surfaces Trusted Advisor checks in the security and fault-tolerance categories that are currently in a warning or error state.',
  requiredPermissions: [
    'support:DescribeTrustedAdvisorChecks',
    'support:DescribeTrustedAdvisorCheckSummaries',
  ],

  async run(context: CheckContext): Promise<CheckResult> {
    const client = context.access.client('support', SupportClient, {
      profile: context.profile,
      region: GLOBAL_SCOPE,
    });

    let checks: Array<{ id?: string; name?: string; category?: string; description?: string }>;
    try {
      const output = await client.send<DescribeTrustedAdvisorChecksCommandOutput>(
        new DescribeTrustedAdvisorChecksCommand({ language: 'en' }),
        { section: context.section }
      );
      checks = (output.checks ?? []).filter((check) =>
        RELEVANT_CATEGORIES.has((check.category ?? '').toLowerCase())
      );
    } catch (error) {
      return notEvaluated([
        issueFor(context, error, {
          service: 'Trusted Advisor',
          check: CHECK_ID,
          requiredPermission: 'support:DescribeTrustedAdvisorChecks',
          detail: 'the Support API requires a Business or Enterprise support plan',
        }),
      ]);
    }

    const checkIds = checks.map((check) => check.id).filter((id): id is string => Boolean(id));
    if (checkIds.length === 0) return evaluated({ resourcesEvaluated: 0 });

    const findings: CheckResult['findings'] = [];
    const byId = new Map(checks.map((check) => [check.id, check]));

    // The Support API accepts a bounded number of check IDs per request.
    for (let index = 0; index < checkIds.length; index += 100) {
      const batch = checkIds.slice(index, index + 100);
      try {
        const output = await client.send<DescribeTrustedAdvisorCheckSummariesCommandOutput>(
          new DescribeTrustedAdvisorCheckSummariesCommand({ checkIds: batch }),
          { section: context.section }
        );

        for (const summary of output.summaries ?? []) {
          if (summary.status !== 'warning' && summary.status !== 'error') continue;
          const definition = byId.get(summary.checkId);
          findings.push(
            buildFinding({
              context,
              checkId: CHECK_ID,
              region: GLOBAL_SCOPE,
              title: `Trusted Advisor: ${definition?.name ?? summary.checkId}`,
              severity: severityForStatus(summary.status),
              resourceType: 'AWS::TrustedAdvisor::Check',
              resourceId: summary.checkId ?? 'unknown',
              source: 'Trusted Advisor',
              evidence: {
                checkId: summary.checkId,
                status: summary.status,
                category: definition?.category,
                resourcesFlagged: summary.resourcesSummary?.resourcesFlagged,
                resourcesProcessed: summary.resourcesSummary?.resourcesProcessed,
                estimatedMonthlySavings:
                  summary.categorySpecificSummary?.costOptimizing?.estimatedMonthlySavings,
              },
              why:
                truncateText(definition?.description, 600) ||
                'Trusted Advisor flagged resources for this check.',
              recommendation:
                'Open Trusted Advisor in the AWS console to see the flagged resources and apply the recommended change manually.',
            })
          );
        }
      } catch (error) {
        return notEvaluated(
          [
            issueFor(context, error, {
              service: 'Trusted Advisor',
              check: CHECK_ID,
              requiredPermission: 'support:DescribeTrustedAdvisorCheckSummaries',
            }),
          ],
          findings
        );
      }
    }

    return evaluated({ findings, resourcesEvaluated: checkIds.length });
  },
};
