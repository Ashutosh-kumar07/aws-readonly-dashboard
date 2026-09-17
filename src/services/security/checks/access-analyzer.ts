/** IAM Access Analyzer external-access findings. */

import {
  AccessAnalyzerClient,
  ListAnalyzersCommand,
  ListFindingsCommand,
  type ListAnalyzersCommandOutput,
  type ListFindingsCommandOutput,
} from '@aws-sdk/client-accessanalyzer';

import { buildFinding, type CheckContext, type CheckResult, type SecurityCheck } from '../types.js';
import { evaluated, issueFor, notEvaluated } from '../check-utils.js';

const CHECK_ID = 'access-analyzer-findings';
const MAX_FINDINGS = 100;

export const accessAnalyzerCheck: SecurityCheck = {
  id: CHECK_ID,
  title: 'IAM Access Analyzer findings',
  service: 'IAM Access Analyzer',
  scope: 'regional',
  description:
    'Reports resources that Access Analyzer has determined are shared with an external principal.',
  requiredPermissions: ['access-analyzer:ListAnalyzers', 'access-analyzer:ListFindings'],

  async run(context: CheckContext): Promise<CheckResult> {
    const client = context.access.client('accessanalyzer', AccessAnalyzerClient, {
      profile: context.profile,
      region: context.region,
    });

    let analyzerArns: string[];
    try {
      const output = await client.send<ListAnalyzersCommandOutput>(
        new ListAnalyzersCommand({ type: 'ACCOUNT' }),
        { section: context.section }
      );
      analyzerArns = (output.analyzers ?? [])
        .filter((analyzer) => analyzer.status === 'ACTIVE')
        .map((analyzer) => analyzer.arn)
        .filter((arn): arn is string => Boolean(arn));
    } catch (error) {
      return notEvaluated([
        issueFor(context, error, {
          service: 'IAM Access Analyzer',
          check: CHECK_ID,
          requiredPermission: 'access-analyzer:ListAnalyzers',
        }),
      ]);
    }

    if (analyzerArns.length === 0) {
      return notEvaluated([
        {
          profile: context.profile,
          ...(context.accountId ? { accountId: context.accountId } : {}),
          region: context.region,
          service: 'IAM Access Analyzer',
          check: CHECK_ID,
          kind: 'not-subscribed',
          label: 'Unable to evaluate — no active Access Analyzer in this region',
          message:
            'No active account-level analyzer exists in this region, so external access cannot be evaluated here.',
        },
      ]);
    }

    const findings: CheckResult['findings'] = [];

    for (const analyzerArn of analyzerArns) {
      try {
        const output = await client.send<ListFindingsCommandOutput>(
          new ListFindingsCommand({
            analyzerArn,
            filter: { status: { eq: ['ACTIVE'] } },
            maxResults: MAX_FINDINGS,
          }),
          { section: context.section }
        );

        for (const finding of output.findings ?? []) {
          const isPublic = finding.isPublic === true;
          findings.push(
            buildFinding({
              context,
              checkId: CHECK_ID,
              title:
                `${finding.resourceType ?? 'Resource'} ${finding.resource ?? ''} is shared externally${
                  isPublic ? ' and is public' : ''
                }`.trim(),
              severity: isPublic ? 'high' : 'medium',
              resourceType: finding.resourceType ?? 'AWS::AccessAnalyzer::Finding',
              resourceId: finding.resource ?? finding.id ?? 'unknown',
              ...(finding.resource?.startsWith('arn:') ? { resourceArn: finding.resource } : {}),
              source: 'IAM Access Analyzer',
              discriminator: finding.id ?? '',
              evidence: {
                findingId: finding.id,
                resource: finding.resource,
                resourceType: finding.resourceType,
                isPublic,
                principal: finding.principal,
                action: finding.action,
                condition: finding.condition,
                analyzedAt: finding.analyzedAt,
              },
              why: isPublic
                ? 'Access Analyzer determined that this resource grants access to anyone on the internet.'
                : 'Access Analyzer determined that this resource grants access to a principal outside your account or organization.',
              recommendation:
                'Review the resource policy in the AWS console and remove or scope down the external grant if it is not intentional. ' +
                'Intentional sharing can be archived in Access Analyzer.',
            })
          );
        }
      } catch (error) {
        return notEvaluated(
          [
            issueFor(context, error, {
              service: 'IAM Access Analyzer',
              check: CHECK_ID,
              requiredPermission: 'access-analyzer:ListFindings',
            }),
          ],
          findings
        );
      }
    }

    return evaluated({ findings, resourcesEvaluated: findings.length });
  },
};
