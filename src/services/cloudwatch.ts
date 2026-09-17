/**
 * CloudWatch Logs analysis.
 *
 * Growth is measured from the `IncomingBytes` metric over a configurable window
 * rather than by persisting size snapshots, so the dashboard stays true to its
 * "no persisted AWS data" rule and still reports real growth.
 *
 * Per the product requirements, no CloudWatch cost estimates are produced.
 */

import {
  CloudWatchLogsClient,
  DescribeLogGroupsCommand,
  type DescribeLogGroupsCommandOutput,
  type LogGroup,
} from '@aws-sdk/client-cloudwatch-logs';
import {
  CloudWatchClient,
  GetMetricDataCommand,
  type GetMetricDataCommandOutput,
} from '@aws-sdk/client-cloudwatch';

import type { AwsAccessLayer } from '../aws/access-layer.js';
import { classifyAwsError, ERROR_KIND_LABEL } from '../util/errors.js';
import { mapWithConcurrency } from '../util/async.js';
import type { CloudWatchConfig } from '../config/schema.js';
import { issueFromError, type EvaluationIssue, type ProfileScoped } from './types.js';

export interface LogGroupInsight {
  name: string;
  arn?: string;
  region: string;
  storedBytes: number;
  retentionInDays: number | null;
  /** Bytes ingested during the growth window, from the IncomingBytes metric. */
  growthBytes: number | null;
  /** Growth as a percentage of the size at the start of the window. */
  growthPercent: number | null;
  createdAt?: string;
  flags: {
    rapidGrowth: boolean;
    noRetention: boolean;
    longRetention: boolean;
    largest: boolean;
  };
}

export interface CloudWatchData {
  windowDays: number;
  thresholds: {
    growthPercent: number;
    growthBytes: number;
    longRetentionDays: number;
  };
  logGroups: LogGroupInsight[];
  largest: LogGroupInsight[];
  rapidlyGrowing: LogGroupInsight[];
  noRetention: LogGroupInsight[];
  longRetention: LogGroupInsight[];
  totals: {
    logGroups: number;
    storedBytes: number;
    inspected: number;
    metricsUnavailable: number;
  };
}

/** Pure classification of a log group against the configured thresholds. */
export function classifyLogGroup(
  group: { storedBytes: number; retentionInDays: number | null; growthBytes: number | null },
  config: Pick<
    CloudWatchConfig,
    'growthPercentThreshold' | 'growthBytesThreshold' | 'longRetentionDays'
  >
): { growthPercent: number | null; flags: Omit<LogGroupInsight['flags'], 'largest'> } {
  const growthBytes = group.growthBytes;
  const previousSize = growthBytes === null ? null : Math.max(group.storedBytes - growthBytes, 0);
  const growthPercent =
    growthBytes === null
      ? null
      : previousSize && previousSize > 0
        ? Math.round((growthBytes / previousSize) * 10000) / 100
        : growthBytes > 0
          ? 100
          : 0;

  const rapidGrowth =
    growthBytes !== null &&
    growthBytes > 0 &&
    ((growthPercent !== null && growthPercent >= config.growthPercentThreshold) ||
      growthBytes >= config.growthBytesThreshold);

  return {
    growthPercent,
    flags: {
      rapidGrowth,
      noRetention: group.retentionInDays === null,
      longRetention:
        group.retentionInDays !== null && group.retentionInDays >= config.longRetentionDays,
    },
  };
}

export interface CloudWatchFetchOptions {
  profile: string;
  accountId?: string;
  regions: string[];
  config: CloudWatchConfig;
  section?: string;
  now?: Date;
}

const METRIC_BATCH_SIZE = 100;

export async function fetchCloudWatchInsights(
  access: AwsAccessLayer,
  options: CloudWatchFetchOptions
): Promise<ProfileScoped<CloudWatchData>> {
  const section = options.section ?? 'cloudwatch';
  const config = options.config;
  const issues: EvaluationIssue[] = [];
  const insights: LogGroupInsight[] = [];
  let totalGroups = 0;
  let metricsUnavailable = 0;

  const scope = {
    profile: options.profile,
    ...(options.accountId ? { accountId: options.accountId } : {}),
  };
  const now = options.now ?? new Date();
  const windowStart = new Date(now.getTime() - config.growthWindowDays * 24 * 60 * 60 * 1000);

  await mapWithConcurrency(options.regions, 3, async (region) => {
    const logsClient = access.client('cloudwatch-logs', CloudWatchLogsClient, {
      profile: options.profile,
      region,
    });

    const groups: LogGroup[] = [];
    try {
      let token: string | undefined;
      do {
        const output = await logsClient.send<DescribeLogGroupsCommandOutput>(
          new DescribeLogGroupsCommand({ limit: 50, ...(token ? { nextToken: token } : {}) }),
          { section }
        );
        groups.push(...(output.logGroups ?? []));
        token = output.nextToken;
      } while (token && groups.length < config.maxLogGroupsPerRegion * 2);
    } catch (error) {
      const classified = classifyAwsError(error);
      issues.push(
        issueFromError(
          classified,
          {
            ...scope,
            region,
            service: 'CloudWatch Logs',
            requiredPermission: 'logs:DescribeLogGroups',
          },
          `${ERROR_KIND_LABEL[classified.kind]} (listing log groups)`
        )
      );
      return;
    }

    totalGroups += groups.length;
    const inspected = [...groups]
      .sort((a, b) => (b.storedBytes ?? 0) - (a.storedBytes ?? 0))
      .slice(0, config.maxLogGroupsPerRegion);

    // One GetMetricData call covers up to 100 log groups, keeping the API-call
    // count proportional to the inventory rather than to every log group.
    const growth = new Map<string, number>();
    const metricsClient = access.client('cloudwatch', CloudWatchClient, {
      profile: options.profile,
      region,
    });

    for (let index = 0; index < inspected.length; index += METRIC_BATCH_SIZE) {
      const batch = inspected.slice(index, index + METRIC_BATCH_SIZE);
      const queries = batch.map((group, position) => ({
        Id: `m${index + position}`,
        MetricStat: {
          Metric: {
            Namespace: 'AWS/Logs',
            MetricName: 'IncomingBytes',
            Dimensions: [{ Name: 'LogGroupName', Value: group.logGroupName ?? '' }],
          },
          Period: Math.max(86400, config.growthWindowDays * 86400),
          Stat: 'Sum',
        },
        ReturnData: true,
      }));

      try {
        const output = await metricsClient.send<GetMetricDataCommandOutput>(
          new GetMetricDataCommand({
            StartTime: windowStart,
            EndTime: now,
            MetricDataQueries: queries,
            ScanBy: 'TimestampDescending',
          }),
          { section }
        );
        for (const result of output.MetricDataResults ?? []) {
          const position = Number(String(result.Id ?? '').replace('m', ''));
          const group = inspected[position];
          if (!group?.logGroupName) continue;
          const sum = (result.Values ?? []).reduce((total, value) => total + value, 0);
          growth.set(group.logGroupName, sum);
        }
      } catch (error) {
        metricsUnavailable += batch.length;
        const classified = classifyAwsError(error);
        issues.push(
          issueFromError(
            classified,
            {
              ...scope,
              region,
              service: 'CloudWatch Metrics',
              requiredPermission: 'cloudwatch:GetMetricData',
            },
            `${ERROR_KIND_LABEL[classified.kind]} (log group growth metrics)`
          )
        );
        break;
      }
    }

    for (const group of inspected) {
      if (!group.logGroupName) continue;
      const storedBytes = group.storedBytes ?? 0;
      const retentionInDays = group.retentionInDays ?? null;
      const growthBytes = growth.has(group.logGroupName)
        ? Math.round(growth.get(group.logGroupName) ?? 0)
        : null;
      const classified = classifyLogGroup({ storedBytes, retentionInDays, growthBytes }, config);

      insights.push({
        name: group.logGroupName,
        ...(group.arn ? { arn: group.arn } : {}),
        region,
        storedBytes,
        retentionInDays,
        growthBytes,
        growthPercent: classified.growthPercent,
        ...(group.creationTime ? { createdAt: new Date(group.creationTime).toISOString() } : {}),
        flags: { ...classified.flags, largest: false },
      });
    }
  });

  const bySize = [...insights].sort((a, b) => b.storedBytes - a.storedBytes);
  for (const insight of bySize.slice(0, 20)) insight.flags.largest = true;

  const data: CloudWatchData = {
    windowDays: config.growthWindowDays,
    thresholds: {
      growthPercent: config.growthPercentThreshold,
      growthBytes: config.growthBytesThreshold,
      longRetentionDays: config.longRetentionDays,
    },
    logGroups: bySize,
    largest: bySize.slice(0, 20),
    rapidlyGrowing: insights
      .filter((insight) => insight.flags.rapidGrowth)
      .sort((a, b) => (b.growthBytes ?? 0) - (a.growthBytes ?? 0)),
    noRetention: insights
      .filter((insight) => insight.flags.noRetention)
      .sort((a, b) => b.storedBytes - a.storedBytes),
    longRetention: insights
      .filter((insight) => insight.flags.longRetention)
      .sort((a, b) => (b.retentionInDays ?? 0) - (a.retentionInDays ?? 0)),
    totals: {
      logGroups: totalGroups,
      storedBytes: insights.reduce((sum, insight) => sum + insight.storedBytes, 0),
      inspected: insights.length,
      metricsUnavailable,
    },
  };

  return {
    profile: options.profile,
    ...(options.accountId ? { accountId: options.accountId } : {}),
    status: issues.length === 0 ? 'ok' : 'partial',
    data,
    issues,
  };
}
