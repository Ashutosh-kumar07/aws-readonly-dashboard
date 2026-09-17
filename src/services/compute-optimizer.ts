/**
 * AWS Compute Optimizer.
 *
 * Every number shown comes from Compute Optimizer itself. When AWS does not
 * provide an estimate (for example, when the recommendation preference for
 * savings estimation is not enabled) the dashboard shows "not provided by AWS"
 * rather than inventing a figure.
 */

import {
  ComputeOptimizerClient,
  GetEnrollmentStatusCommand,
  GetEC2InstanceRecommendationsCommand,
  GetAutoScalingGroupRecommendationsCommand,
  GetEBSVolumeRecommendationsCommand,
  GetLambdaFunctionRecommendationsCommand,
  GetECSServiceRecommendationsCommand,
  GetRDSDatabaseRecommendationsCommand,
  GetIdleRecommendationsCommand,
  type GetEnrollmentStatusCommandOutput,
  type GetEC2InstanceRecommendationsCommandOutput,
  type GetAutoScalingGroupRecommendationsCommandOutput,
  type GetEBSVolumeRecommendationsCommandOutput,
  type GetLambdaFunctionRecommendationsCommandOutput,
  type GetECSServiceRecommendationsCommandOutput,
  type GetRDSDatabaseRecommendationsCommandOutput,
  type GetIdleRecommendationsCommandOutput,
  type SavingsOpportunity,
} from '@aws-sdk/client-compute-optimizer';

import type { AwsAccessLayer } from '../aws/access-layer.js';
import { classifyAwsError, ERROR_KIND_LABEL } from '../util/errors.js';
import { mapWithConcurrency } from '../util/async.js';
import { issueFromError, type EvaluationIssue, type ProfileScoped } from './types.js';

export interface OptimizerRecommendation {
  resourceType: string;
  resourceId: string;
  resourceArn?: string;
  region: string;
  /** Compute Optimizer finding, e.g. `OVER_PROVISIONED`. */
  finding: string;
  findingReasons: string[];
  currentConfiguration: Record<string, unknown>;
  recommendedConfiguration: Record<string, unknown> | null;
  /** `null` when AWS did not return a performance risk. */
  performanceRisk: number | null;
  estimatedMonthlyCost: number | null;
  estimatedMonthlySavings: number | null;
  savingsPercentage: number | null;
  currency: string | null;
  reason: string;
}

export interface ComputeOptimizerData {
  enrollment: { status: string; statusReason?: string; memberAccountsEnrolled?: boolean } | null;
  recommendations: OptimizerRecommendation[];
  totals: {
    count: number;
    /** Sum of AWS-provided savings estimates only. */
    estimatedMonthlySavings: number;
    withoutSavingsEstimate: number;
  };
  byResourceType: Array<{ resourceType: string; count: number; estimatedMonthlySavings: number }>;
}

function savings(opportunity: SavingsOpportunity | undefined): {
  estimatedMonthlySavings: number | null;
  savingsPercentage: number | null;
  currency: string | null;
} {
  const value = opportunity?.estimatedMonthlySavings?.value;
  return {
    estimatedMonthlySavings: typeof value === 'number' ? Math.round(value * 100) / 100 : null,
    savingsPercentage:
      typeof opportunity?.savingsOpportunityPercentage === 'number'
        ? Math.round(opportunity.savingsOpportunityPercentage * 100) / 100
        : null,
    currency: opportunity?.estimatedMonthlySavings?.currency ?? null,
  };
}

function idFromArn(arn: string | undefined, fallback: string): string {
  if (!arn) return fallback;
  const tail = arn.split(':').pop() ?? arn;
  return tail.split('/').pop() ?? tail;
}

const FINDING_REASONS: Record<string, string> = {
  Overprovisioned: 'Compute Optimizer observed utilisation well below the provisioned capacity.',
  Underprovisioned: 'Compute Optimizer observed utilisation at or above the provisioned capacity.',
  Optimized: 'Compute Optimizer considers the current configuration appropriate.',
  NotOptimized: 'Compute Optimizer identified a better configuration for this resource.',
  Idle: 'Compute Optimizer observed no meaningful utilisation over the analysis period.',
};

function reasonFor(finding: string | undefined, reasons: string[]): string {
  const base =
    FINDING_REASONS[finding ?? ''] ??
    'Compute Optimizer returned a recommendation for this resource.';
  return reasons.length > 0 ? `${base} Reasons reported by AWS: ${reasons.join(', ')}.` : base;
}

export interface ComputeOptimizerFetchOptions {
  profile: string;
  accountId?: string;
  regions: string[];
  section?: string;
}

/** Fetches Compute Optimizer recommendations for one profile across regions. */
export async function fetchComputeOptimizer(
  access: AwsAccessLayer,
  options: ComputeOptimizerFetchOptions
): Promise<ProfileScoped<ComputeOptimizerData>> {
  const section = options.section ?? 'compute-optimizer';
  const issues: EvaluationIssue[] = [];
  const recommendations: OptimizerRecommendation[] = [];
  let enrollment: ComputeOptimizerData['enrollment'] = null;

  const scope = {
    profile: options.profile,
    ...(options.accountId ? { accountId: options.accountId } : {}),
  };

  await mapWithConcurrency(options.regions, 3, async (region) => {
    const client = access.client('compute-optimizer', ComputeOptimizerClient, {
      profile: options.profile,
      region,
    });

    try {
      const status = await client.send<GetEnrollmentStatusCommandOutput>(
        new GetEnrollmentStatusCommand({}),
        { section }
      );
      if (!enrollment) {
        enrollment = {
          status: status.status ?? 'Unknown',
          ...(status.statusReason ? { statusReason: status.statusReason } : {}),
          ...(status.memberAccountsEnrolled !== undefined
            ? { memberAccountsEnrolled: status.memberAccountsEnrolled }
            : {}),
        };
      }
      if (status.status !== 'Active') {
        issues.push({
          ...scope,
          region,
          service: 'Compute Optimizer',
          kind: 'not-subscribed',
          label: 'Unable to evaluate — Compute Optimizer is not enrolled',
          message: `Compute Optimizer enrollment status is "${status.status ?? 'Unknown'}"${
            status.statusReason ? `: ${status.statusReason}` : ''
          }. Recommendations are unavailable until the account opts in.`,
        });
        return;
      }
    } catch (error) {
      const classified = classifyAwsError(error);
      issues.push(
        issueFromError(
          classified,
          {
            ...scope,
            region,
            service: 'Compute Optimizer',
            requiredPermission: 'compute-optimizer:GetEnrollmentStatus',
          },
          `${ERROR_KIND_LABEL[classified.kind]} (enrollment status)`
        )
      );
      return;
    }

    const collectors: Array<{
      resourceType: string;
      permission: string;
      run: () => Promise<OptimizerRecommendation[]>;
    }> = [
      {
        resourceType: 'EC2 instance',
        permission: 'compute-optimizer:GetEC2InstanceRecommendations',
        run: async () => {
          const output = await client.send<GetEC2InstanceRecommendationsCommandOutput>(
            new GetEC2InstanceRecommendationsCommand({ maxResults: 100 }),
            { section }
          );
          return (output.instanceRecommendations ?? [])
            .filter((item) => item.finding !== 'Optimized')
            .map((item) => {
              const best = item.recommendationOptions?.[0];
              return {
                resourceType: 'EC2 instance',
                resourceId: item.instanceName ?? idFromArn(item.instanceArn, 'unknown'),
                ...(item.instanceArn ? { resourceArn: item.instanceArn } : {}),
                region,
                finding: item.finding ?? 'UNKNOWN',
                findingReasons: (item.findingReasonCodes ?? []).map(String),
                currentConfiguration: {
                  instanceType: item.currentInstanceType,
                  utilizationMetrics: item.utilizationMetrics,
                  currentPerformanceRisk: item.currentPerformanceRisk,
                },
                recommendedConfiguration: best
                  ? { instanceType: best.instanceType, rank: best.rank }
                  : null,
                performanceRisk:
                  typeof best?.performanceRisk === 'number' ? best.performanceRisk : null,
                estimatedMonthlyCost: null,
                ...savings(best?.savingsOpportunity),
                reason: reasonFor(item.finding, (item.findingReasonCodes ?? []).map(String)),
              } satisfies OptimizerRecommendation;
            });
        },
      },
      {
        resourceType: 'Auto Scaling group',
        permission: 'compute-optimizer:GetAutoScalingGroupRecommendations',
        run: async () => {
          const output = await client.send<GetAutoScalingGroupRecommendationsCommandOutput>(
            new GetAutoScalingGroupRecommendationsCommand({ maxResults: 100 }),
            { section }
          );
          return (output.autoScalingGroupRecommendations ?? [])
            .filter((item) => item.finding !== 'Optimized')
            .map((item) => {
              const best = item.recommendationOptions?.[0];
              return {
                resourceType: 'Auto Scaling group',
                resourceId:
                  item.autoScalingGroupName ?? idFromArn(item.autoScalingGroupArn, 'unknown'),
                ...(item.autoScalingGroupArn ? { resourceArn: item.autoScalingGroupArn } : {}),
                region,
                finding: item.finding ?? 'UNKNOWN',
                findingReasons: [],
                currentConfiguration: {
                  configuration: item.currentConfiguration,
                  utilizationMetrics: item.utilizationMetrics,
                },
                recommendedConfiguration: best
                  ? { configuration: best.configuration, rank: best.rank }
                  : null,
                performanceRisk:
                  typeof best?.performanceRisk === 'number' ? best.performanceRisk : null,
                estimatedMonthlyCost: null,
                ...savings(best?.savingsOpportunity),
                reason: reasonFor(item.finding, []),
              } satisfies OptimizerRecommendation;
            });
        },
      },
      {
        resourceType: 'EBS volume',
        permission: 'compute-optimizer:GetEBSVolumeRecommendations',
        run: async () => {
          const output = await client.send<GetEBSVolumeRecommendationsCommandOutput>(
            new GetEBSVolumeRecommendationsCommand({ maxResults: 100 }),
            { section }
          );
          return (output.volumeRecommendations ?? [])
            .filter((item) => item.finding !== 'Optimized')
            .map((item) => {
              const best = item.volumeRecommendationOptions?.[0];
              return {
                resourceType: 'EBS volume',
                resourceId: idFromArn(item.volumeArn, 'unknown'),
                ...(item.volumeArn ? { resourceArn: item.volumeArn } : {}),
                region,
                finding: item.finding ?? 'UNKNOWN',
                findingReasons: [],
                currentConfiguration: {
                  configuration: item.currentConfiguration,
                  utilizationMetrics: item.utilizationMetrics,
                },
                recommendedConfiguration: best
                  ? { configuration: best.configuration, rank: best.rank }
                  : null,
                performanceRisk:
                  typeof best?.performanceRisk === 'number' ? best.performanceRisk : null,
                estimatedMonthlyCost: null,
                ...savings(best?.savingsOpportunity),
                reason: reasonFor(item.finding, []),
              } satisfies OptimizerRecommendation;
            });
        },
      },
      {
        resourceType: 'Lambda function',
        permission: 'compute-optimizer:GetLambdaFunctionRecommendations',
        run: async () => {
          const output = await client.send<GetLambdaFunctionRecommendationsCommandOutput>(
            new GetLambdaFunctionRecommendationsCommand({ maxResults: 100 }),
            { section }
          );
          return (output.lambdaFunctionRecommendations ?? [])
            .filter((item) => item.finding !== 'Optimized')
            .map((item) => {
              const best = item.memorySizeRecommendationOptions?.[0];
              return {
                resourceType: 'Lambda function',
                resourceId: item.functionArn ? idFromArn(item.functionArn, 'unknown') : 'unknown',
                ...(item.functionArn ? { resourceArn: item.functionArn } : {}),
                region,
                finding: item.finding ?? 'UNKNOWN',
                findingReasons: (item.findingReasonCodes ?? []).map(String),
                currentConfiguration: {
                  memorySize: item.currentMemorySize,
                  numberOfInvocations: item.numberOfInvocations,
                  utilizationMetrics: item.utilizationMetrics,
                },
                recommendedConfiguration: best
                  ? { memorySize: best.memorySize, rank: best.rank }
                  : null,
                performanceRisk: null,
                estimatedMonthlyCost: null,
                ...savings(best?.savingsOpportunity),
                reason: reasonFor(item.finding, (item.findingReasonCodes ?? []).map(String)),
              } satisfies OptimizerRecommendation;
            });
        },
      },
      {
        resourceType: 'ECS service',
        permission: 'compute-optimizer:GetECSServiceRecommendations',
        run: async () => {
          const output = await client.send<GetECSServiceRecommendationsCommandOutput>(
            new GetECSServiceRecommendationsCommand({ maxResults: 100 }),
            { section }
          );
          return (output.ecsServiceRecommendations ?? [])
            .filter((item) => item.finding !== 'Optimized')
            .map((item) => {
              const best = item.serviceRecommendationOptions?.[0];
              return {
                resourceType: 'ECS service',
                resourceId: idFromArn(item.serviceArn, 'unknown'),
                ...(item.serviceArn ? { resourceArn: item.serviceArn } : {}),
                region,
                finding: item.finding ?? 'UNKNOWN',
                findingReasons: (item.findingReasonCodes ?? []).map(String),
                currentConfiguration: {
                  configuration: item.currentServiceConfiguration,
                  utilizationMetrics: item.utilizationMetrics,
                },
                recommendedConfiguration: best
                  ? {
                      cpu: best.cpu,
                      memory: best.memory,
                      containerRecommendations: best.containerRecommendations,
                    }
                  : null,
                performanceRisk: null,
                estimatedMonthlyCost: null,
                ...savings(best?.savingsOpportunity),
                reason: reasonFor(item.finding, (item.findingReasonCodes ?? []).map(String)),
              } satisfies OptimizerRecommendation;
            });
        },
      },
      {
        resourceType: 'RDS database',
        permission: 'compute-optimizer:GetRDSDatabaseRecommendations',
        run: async () => {
          const output = await client.send<GetRDSDatabaseRecommendationsCommandOutput>(
            new GetRDSDatabaseRecommendationsCommand({ maxResults: 100 }),
            { section }
          );
          return (output.rdsDBRecommendations ?? [])
            .filter(
              (item) => item.instanceFinding !== 'Optimized' || item.storageFinding !== 'Optimized'
            )
            .map((item) => {
              const best = item.instanceRecommendationOptions?.[0];
              return {
                resourceType: 'RDS database',
                resourceId: item.resourceArn ? idFromArn(item.resourceArn, 'unknown') : 'unknown',
                ...(item.resourceArn ? { resourceArn: item.resourceArn } : {}),
                region,
                finding: item.instanceFinding ?? item.storageFinding ?? 'UNKNOWN',
                findingReasons: [
                  ...(item.instanceFindingReasonCodes ?? []).map(String),
                  ...(item.storageFindingReasonCodes ?? []).map(String),
                ],
                currentConfiguration: {
                  instanceClass: item.currentDBInstanceClass,
                  storageConfiguration: item.currentStorageConfiguration,
                  engine: item.engine,
                },
                recommendedConfiguration: best
                  ? { instanceClass: best.dbInstanceClass, rank: best.rank }
                  : null,
                performanceRisk:
                  typeof best?.performanceRisk === 'number' ? best.performanceRisk : null,
                estimatedMonthlyCost: null,
                ...savings(best?.savingsOpportunity),
                reason: reasonFor(item.instanceFinding, [
                  ...(item.instanceFindingReasonCodes ?? []).map(String),
                ]),
              } satisfies OptimizerRecommendation;
            });
        },
      },
      {
        resourceType: 'Idle resource',
        permission: 'compute-optimizer:GetIdleRecommendations',
        run: async () => {
          const output = await client.send<GetIdleRecommendationsCommandOutput>(
            new GetIdleRecommendationsCommand({ maxResults: 100 }),
            { section }
          );
          return (output.idleRecommendations ?? []).map((item) => ({
            resourceType: `Idle ${item.resourceType ?? 'resource'}`,
            resourceId: item.resourceId ?? idFromArn(item.resourceArn, 'unknown'),
            ...(item.resourceArn ? { resourceArn: item.resourceArn } : {}),
            region,
            finding: item.finding ?? 'IDLE',
            findingReasons: (item.findingDescription ? [item.findingDescription] : []).map(String),
            currentConfiguration: { utilizationMetrics: item.utilizationMetrics },
            recommendedConfiguration: null,
            performanceRisk: null,
            estimatedMonthlyCost: null,
            ...savings(item.savingsOpportunity),
            reason:
              item.findingDescription ??
              'Compute Optimizer classified this resource as idle over the analysis period.',
          }));
        },
      },
    ];

    await mapWithConcurrency(collectors, 3, async (collector) => {
      try {
        recommendations.push(...(await collector.run()));
      } catch (error) {
        const classified = classifyAwsError(error);
        issues.push(
          issueFromError(
            classified,
            {
              ...scope,
              region,
              service: `Compute Optimizer (${collector.resourceType})`,
              requiredPermission: collector.permission,
            },
            `${ERROR_KIND_LABEL[classified.kind]} (${collector.resourceType} recommendations)`
          )
        );
      }
    });
  });

  const byType = new Map<string, { count: number; estimatedMonthlySavings: number }>();
  let totalSavings = 0;
  let withoutEstimate = 0;
  for (const recommendation of recommendations) {
    const bucket = byType.get(recommendation.resourceType) ?? {
      count: 0,
      estimatedMonthlySavings: 0,
    };
    bucket.count += 1;
    if (recommendation.estimatedMonthlySavings === null) withoutEstimate += 1;
    else {
      bucket.estimatedMonthlySavings += recommendation.estimatedMonthlySavings;
      totalSavings += recommendation.estimatedMonthlySavings;
    }
    byType.set(recommendation.resourceType, bucket);
  }

  recommendations.sort(
    (a, b) => (b.estimatedMonthlySavings ?? 0) - (a.estimatedMonthlySavings ?? 0)
  );

  const data: ComputeOptimizerData = {
    enrollment,
    recommendations,
    totals: {
      count: recommendations.length,
      estimatedMonthlySavings: Math.round(totalSavings * 100) / 100,
      withoutSavingsEstimate: withoutEstimate,
    },
    byResourceType: [...byType.entries()]
      .map(([resourceType, bucket]) => ({
        resourceType,
        count: bucket.count,
        estimatedMonthlySavings: Math.round(bucket.estimatedMonthlySavings * 100) / 100,
      }))
      .sort((a, b) => b.estimatedMonthlySavings - a.estimatedMonthlySavings),
  };

  return {
    profile: options.profile,
    ...(options.accountId ? { accountId: options.accountId } : {}),
    status: issues.length === 0 ? 'ok' : recommendations.length > 0 ? 'partial' : 'partial',
    data,
    issues,
  };
}
