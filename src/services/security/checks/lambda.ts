/** Lambda posture: functions outside a VPC and functions exposed to everyone. */

import {
  LambdaClient,
  ListFunctionsCommand,
  GetPolicyCommand,
  type ListFunctionsCommandOutput,
  type FunctionConfiguration,
  type GetPolicyCommandOutput,
} from '@aws-sdk/client-lambda';

import { classifyAwsError } from '../../../util/errors.js';
import { mapWithConcurrency } from '../../../util/async.js';
import { buildFinding, type CheckContext, type CheckResult, type SecurityCheck } from '../types.js';
import { evaluated, issueFor, notEvaluated } from '../check-utils.js';
import type { EvaluationIssue } from '../../types.js';

const VPC_CHECK_ID = 'lambda-outside-vpc';
const POLICY_CHECK_ID = 'lambda-public-resource-policy';

/** Upper bound on per-function policy lookups so a large account is not hammered. */
const MAX_POLICY_LOOKUPS = 100;

async function listFunctions(context: CheckContext): Promise<FunctionConfiguration[]> {
  const client = context.access.client('lambda', LambdaClient, {
    profile: context.profile,
    region: context.region,
  });
  const functions: FunctionConfiguration[] = [];
  let marker: string | undefined;
  do {
    const output = await client.send<ListFunctionsCommandOutput>(
      new ListFunctionsCommand({ MaxItems: 50, ...(marker ? { Marker: marker } : {}) }),
      { section: context.section }
    );
    functions.push(...(output.Functions ?? []));
    marker = output.NextMarker;
  } while (marker && functions.length < 5000);
  return functions;
}

export const lambdaVpcCheck: SecurityCheck = {
  id: VPC_CHECK_ID,
  title: 'Lambda functions running outside a VPC',
  service: 'Lambda',
  scope: 'regional',
  description:
    'Lists Lambda functions with no VPC configuration. Such functions cannot reach private subnets and their egress is not governed by VPC controls.',
  requiredPermissions: ['lambda:ListFunctions'],

  async run(context: CheckContext): Promise<CheckResult> {
    let functions: FunctionConfiguration[];
    try {
      functions = await listFunctions(context);
    } catch (error) {
      return notEvaluated([
        issueFor(context, error, {
          service: 'Lambda',
          check: VPC_CHECK_ID,
          requiredPermission: 'lambda:ListFunctions',
        }),
      ]);
    }

    const findings = functions
      .filter((fn) => !fn.VpcConfig?.SubnetIds || fn.VpcConfig.SubnetIds.length === 0)
      .map((fn) =>
        buildFinding({
          context,
          checkId: VPC_CHECK_ID,
          title: `Lambda function ${fn.FunctionName} is not attached to a VPC`,
          severity: 'low',
          resourceType: 'AWS::Lambda::Function',
          resourceId: fn.FunctionName ?? 'unknown',
          ...(fn.FunctionArn ? { resourceArn: fn.FunctionArn } : {}),
          source: 'Lambda',
          evidence: {
            functionName: fn.FunctionName,
            runtime: fn.Runtime,
            lastModified: fn.LastModified,
            vpcConfig: fn.VpcConfig ?? null,
            role: fn.Role,
          },
          why:
            'The function runs in the Lambda service network rather than in your VPC. Its outbound traffic is not subject to VPC routing, ' +
            'security groups, or VPC endpoint policies, and it cannot reach resources that only accept private connectivity.',
          recommendation:
            'If the function needs private connectivity or VPC-level egress control, attach it to private subnets with an appropriate security group in the Lambda console. ' +
            'Functions that only call public AWS APIs are frequently fine outside a VPC — treat this as context, not an automatic defect.',
        })
      );

    return evaluated({ findings, resourcesEvaluated: functions.length });
  },
};

export const lambdaPublicPolicyCheck: SecurityCheck = {
  id: POLICY_CHECK_ID,
  title: 'Lambda functions with a public resource policy',
  service: 'Lambda',
  scope: 'regional',
  description:
    'Inspects Lambda resource policies for statements that grant invoke permission to any principal without a condition.',
  requiredPermissions: ['lambda:ListFunctions', 'lambda:GetPolicy'],

  async run(context: CheckContext): Promise<CheckResult> {
    let functions: FunctionConfiguration[];
    try {
      functions = await listFunctions(context);
    } catch (error) {
      return notEvaluated([
        issueFor(context, error, {
          service: 'Lambda',
          check: POLICY_CHECK_ID,
          requiredPermission: 'lambda:ListFunctions',
        }),
      ]);
    }

    const client = context.access.client('lambda', LambdaClient, {
      profile: context.profile,
      region: context.region,
    });
    const inspected = functions.slice(0, MAX_POLICY_LOOKUPS);
    const issues: EvaluationIssue[] = [];
    const findings: CheckResult['findings'] = [];
    let permissionDenied = false;

    await mapWithConcurrency(inspected, 6, async (fn) => {
      if (!fn.FunctionName) return;
      try {
        const output = await client.send<GetPolicyCommandOutput>(
          new GetPolicyCommand({ FunctionName: fn.FunctionName }),
          { section: context.section }
        );
        if (!output.Policy) return;
        const policy = JSON.parse(output.Policy) as {
          Statement?: Array<{
            Effect?: string;
            Principal?: unknown;
            Condition?: unknown;
            Action?: unknown;
            Sid?: string;
          }>;
        };
        for (const statement of policy.Statement ?? []) {
          const principal = statement.Principal;
          const isWildcard =
            principal === '*' ||
            (typeof principal === 'object' &&
              principal !== null &&
              (principal as Record<string, unknown>).AWS === '*');
          if (statement.Effect !== 'Allow' || !isWildcard) continue;
          if (statement.Condition && Object.keys(statement.Condition as object).length > 0)
            continue;
          findings.push(
            buildFinding({
              context,
              checkId: POLICY_CHECK_ID,
              title: `Lambda function ${fn.FunctionName} can be invoked by any principal`,
              severity: 'high',
              resourceType: 'AWS::Lambda::Function',
              resourceId: fn.FunctionName,
              ...(fn.FunctionArn ? { resourceArn: fn.FunctionArn } : {}),
              source: 'Lambda',
              discriminator: statement.Sid ?? 'wildcard-principal',
              evidence: {
                functionName: fn.FunctionName,
                statementSid: statement.Sid,
                action: statement.Action,
                principal: statement.Principal,
              },
              why: 'The resource policy allows a wildcard principal with no condition, so anyone with the function ARN may be able to invoke it.',
              recommendation:
                'Review the function policy and scope the principal to the specific account, service or source ARN that needs to invoke it. ' +
                'This dashboard never edits Lambda policies.',
            })
          );
        }
      } catch (error) {
        const classified = classifyAwsError(error);
        // "No policy" is the normal case, not a failure to evaluate.
        if (classified.kind === 'not-found') return;
        if (classified.kind === 'access-denied' && permissionDenied) return;
        if (classified.kind === 'access-denied') permissionDenied = true;
        issues.push(
          issueFor(context, error, {
            service: 'Lambda',
            check: POLICY_CHECK_ID,
            requiredPermission: 'lambda:GetPolicy',
            detail: 'reading function resource policies',
          })
        );
      }
    });

    return {
      findings,
      issues,
      evaluated: !permissionDenied,
      resourcesEvaluated: inspected.length,
      truncated: functions.length > inspected.length,
    };
  },
};
