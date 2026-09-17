/** AWS Config recorder coverage and non-compliant rules. */

import {
  ConfigServiceClient,
  DescribeConfigurationRecordersCommand,
  DescribeConfigurationRecorderStatusCommand,
  DescribeComplianceByConfigRuleCommand,
  type DescribeConfigurationRecordersCommandOutput,
  type DescribeConfigurationRecorderStatusCommandOutput,
  type DescribeComplianceByConfigRuleCommandOutput,
} from '@aws-sdk/client-config-service';

import { buildFinding, type CheckContext, type CheckResult, type SecurityCheck } from '../types.js';
import { evaluated, issueFor } from '../check-utils.js';
import type { EvaluationIssue } from '../../types.js';

const CHECK_ID = 'aws-config-coverage';

export const awsConfigCheck: SecurityCheck = {
  id: CHECK_ID,
  title: 'AWS Config recorder and rule compliance',
  service: 'AWS Config',
  scope: 'regional',
  description:
    'Checks that a configuration recorder exists and is recording, and reports Config rules that are currently non-compliant.',
  requiredPermissions: [
    'config:DescribeConfigurationRecorders',
    'config:DescribeConfigurationRecorderStatus',
    'config:DescribeComplianceByConfigRule',
  ],

  async run(context: CheckContext): Promise<CheckResult> {
    const client = context.access.client('config-service', ConfigServiceClient, {
      profile: context.profile,
      region: context.region,
    });
    const findings: CheckResult['findings'] = [];
    const issues: EvaluationIssue[] = [];

    try {
      const recorders = await client.send<DescribeConfigurationRecordersCommandOutput>(
        new DescribeConfigurationRecordersCommand({}),
        { section: context.section }
      );
      const list = recorders.ConfigurationRecorders ?? [];

      if (list.length === 0) {
        findings.push(
          buildFinding({
            context,
            checkId: CHECK_ID,
            title: 'AWS Config has no configuration recorder in this region',
            severity: 'medium',
            resourceType: 'AWS::Config::ConfigurationRecorder',
            resourceId: `config-recorder-${context.region}`,
            source: 'AWS Config',
            discriminator: 'missing-recorder',
            evidence: { recorders: [] },
            why: 'Without a configuration recorder there is no configuration history for this region, which limits both security investigations and compliance evidence.',
            recommendation:
              'Enable AWS Config with a configuration recorder and delivery channel for this region.',
          })
        );
      } else {
        const status = await client.send<DescribeConfigurationRecorderStatusCommandOutput>(
          new DescribeConfigurationRecorderStatusCommand({}),
          { section: context.section }
        );
        for (const recorder of status.ConfigurationRecordersStatus ?? []) {
          if (recorder.recording === true && recorder.lastStatus !== 'Failure') continue;
          findings.push(
            buildFinding({
              context,
              checkId: CHECK_ID,
              title: `AWS Config recorder ${recorder.name ?? ''} is not recording correctly`.trim(),
              severity: 'medium',
              resourceType: 'AWS::Config::ConfigurationRecorder',
              resourceId: recorder.name ?? `config-recorder-${context.region}`,
              source: 'AWS Config',
              discriminator: 'recorder-status',
              evidence: {
                name: recorder.name,
                recording: recorder.recording,
                lastStatus: recorder.lastStatus,
                lastErrorCode: recorder.lastErrorCode,
                lastErrorMessage: recorder.lastErrorMessage,
              },
              why: 'Configuration history stops being captured when the recorder is stopped or failing.',
              recommendation:
                'Start the recorder in the AWS Config console and fix the delivery channel error it reports.',
            })
          );
        }
      }
    } catch (error) {
      issues.push(
        issueFor(context, error, {
          service: 'AWS Config',
          check: CHECK_ID,
          requiredPermission: 'config:DescribeConfigurationRecorders',
          detail: 'reading configuration recorder state',
        })
      );
    }

    try {
      let token: string | undefined;
      let pages = 0;
      do {
        const output = await client.send<DescribeComplianceByConfigRuleCommandOutput>(
          new DescribeComplianceByConfigRuleCommand({
            ComplianceTypes: ['NON_COMPLIANT'],
            ...(token ? { NextToken: token } : {}),
          }),
          { section: context.section }
        );
        for (const rule of output.ComplianceByConfigRules ?? []) {
          if (rule.Compliance?.ComplianceType !== 'NON_COMPLIANT') continue;
          findings.push(
            buildFinding({
              context,
              checkId: CHECK_ID,
              title: `AWS Config rule ${rule.ConfigRuleName} is non-compliant`,
              severity: 'medium',
              resourceType: 'AWS::Config::ConfigRule',
              resourceId: rule.ConfigRuleName ?? 'unknown',
              source: 'AWS Config',
              discriminator: 'non-compliant-rule',
              evidence: {
                ruleName: rule.ConfigRuleName,
                complianceType: rule.Compliance.ComplianceType,
                nonCompliantResourceCount: rule.Compliance.ComplianceContributorCount?.CappedCount,
                capExceeded: rule.Compliance.ComplianceContributorCount?.CapExceeded,
              },
              why: 'One or more resources violate a Config rule that this account has chosen to enforce.',
              recommendation:
                'Open the rule in the AWS Config console to list the non-compliant resources and remediate them manually.',
            })
          );
        }
        token = output.NextToken;
        pages += 1;
      } while (token && pages < 10);
    } catch (error) {
      issues.push(
        issueFor(context, error, {
          service: 'AWS Config',
          check: CHECK_ID,
          requiredPermission: 'config:DescribeComplianceByConfigRule',
          detail: 'reading Config rule compliance',
        })
      );
    }

    return issues.length > 0
      ? { findings, issues, evaluated: false }
      : evaluated({ findings, resourcesEvaluated: findings.length });
  },
};
