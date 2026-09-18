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

/**
 * Default upper bound on per-function policy lookups, used when configuration
 * does not say otherwise. Each lookup is one `lambda:GetPolicy` call, so the
 * limit is a cost control rather than a technical one, and it is configurable
 * in Settings.
 */
const DEFAULT_POLICY_LOOKUPS = 100;

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

    const outsideVpc = functions.filter(
      (fn) => !fn.VpcConfig?.SubnetIds || fn.VpcConfig.SubnetIds.length === 0
    );

    if (outsideVpc.length === 0) {
      return evaluated({ resourcesEvaluated: functions.length });
    }

    // One aggregated finding per region rather than one per function: in an
    // account with hundreds of functions, a per-function finding would bury the
    // genuine issues and dominate the severity counts. The functions themselves
    // are listed in the evidence.
    const MAX_LISTED = 100;
    const findings = [
      buildFinding({
        context,
        checkId: VPC_CHECK_ID,
        title: `${outsideVpc.length} of ${functions.length} Lambda function${
          functions.length === 1 ? '' : 's'
        } run outside a VPC`,
        severity: 'low',
        resourceType: 'AWS::Lambda::Function',
        resourceId: `lambda-outside-vpc-${context.region}`,
        source: 'Lambda',
        evidence: {
          region: context.region,
          functionsOutsideVpc: outsideVpc.length,
          functionsTotal: functions.length,
          functions: outsideVpc.slice(0, MAX_LISTED).map((fn) => ({
            name: fn.FunctionName,
            runtime: fn.Runtime,
            lastModified: fn.LastModified,
          })),
          ...(outsideVpc.length > MAX_LISTED
            ? { note: `Only the first ${MAX_LISTED} functions are listed here.` }
            : {}),
        },
        why:
          'These functions run in the Lambda service network rather than in your VPC. Their outbound traffic is not subject to VPC routing, ' +
          'security groups or VPC endpoint policies, and they cannot reach resources that only accept private connectivity.',
        recommendation:
          'Attach the functions that need private connectivity or VPC-level egress control to private subnets with an appropriate security group, in the Lambda console. ' +
          'Functions that only call public AWS APIs are frequently fine outside a VPC — treat this as context, not an automatic defect.',
      }),
    ];

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

    const limit = context.config.security.maxLambdaPolicyLookupsPerRegion ?? DEFAULT_POLICY_LOOKUPS;

    const client = context.access.client('lambda', LambdaClient, {
      profile: context.profile,
      region: context.region,
    });
    // Newest functions first: a recently deployed function is the likelier
    // source of an unnoticed public policy.
    const ordered = [...functions].sort((a, b) =>
      String(b.LastModified ?? '').localeCompare(String(a.LastModified ?? ''))
    );
    // 0 means no limit: inspect every function. Results stream in as each
    // check finishes, so a long scan shows its findings while it runs.
    const inspected = limit === 0 ? ordered : ordered.slice(0, limit);
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

    const truncated = functions.length > inspected.length;
    if (truncated) {
      // Partial coverage is stated explicitly: the functions that were not
      // inspected have an unknown policy, not a clean one.
      issues.push({
        profile: context.profile,
        ...(context.accountId ? { accountId: context.accountId } : {}),
        region: context.region,
        service: 'Lambda',
        check: POLICY_CHECK_ID,
        kind: 'partial',
        label: `Partially evaluated — ${inspected.length} of ${functions.length} functions inspected`,
        message:
          `The resource policies of ${functions.length - inspected.length} function(s) in this region were not read, because the per-region ` +
          'lookup limit was reached. Inspecting them all costs one lambda:GetPolicy call per function; results appear as the scan runs.',
        suggestion: {
          setting: 'maxLambdaPolicyLookupsPerRegion',
          value: 0,
          label: `Inspect every function (${functions.length} in this region)`,
        },
      });
    }

    return {
      findings,
      issues,
      evaluated: !permissionDenied,
      resourcesEvaluated: inspected.length,
      truncated,
    };
  },
};
