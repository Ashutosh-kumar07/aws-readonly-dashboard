/**
 * AI payload construction (data minimization).
 *
 * Raw AWS responses are never sent to a provider. Each section is first reduced
 * to a compact analytical representation: rounded numbers, top-N slices, and
 * counts instead of inventories. This lowers token usage and latency, reduces
 * privacy exposure, and gives the model a better signal-to-noise ratio.
 */

import type { BillingData } from '../services/billing.js';
import type { CloudWatchData } from '../services/cloudwatch.js';
import type { ComputeOptimizerData } from '../services/compute-optimizer.js';
import type { SecurityData } from '../services/security/index.js';
import type { NormalisedEvent } from '../services/cloudtrail.js';
import type { EvaluationIssue, SectionId } from '../services/types.js';

export interface CompactSectionPayload {
  section: SectionId;
  profile: string;
  accountId?: string;
  regions: string[];
  data: unknown;
  /** Permission or availability gaps, so the model never assumes "all clear". */
  notEvaluated: Array<{
    service: string;
    region: string;
    reason: string;
    missingPermission?: string;
  }>;
}

const MAX_ROWS = 15;

function round(value: number | null | undefined, digits = 2): number | null {
  if (value === null || value === undefined || !Number.isFinite(value)) return null;
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function compactIssues(issues: readonly EvaluationIssue[]): CompactSectionPayload['notEvaluated'] {
  return issues.slice(0, 40).map((issue) => ({
    service: issue.service,
    region: issue.region,
    reason: issue.label,
    ...(issue.missingPermission ? { missingPermission: issue.missingPermission } : {}),
  }));
}

export function compactBilling(data: BillingData): unknown {
  const row = (change: BillingData['byService'][number]) => ({
    key: change.key,
    current: round(change.currentCost),
    previous: round(change.previousCost),
    delta: round(change.delta),
    percent: change.percentChange === null ? null : round(change.percentChange, 1),
    kind: change.kind,
  });

  return {
    currency: data.currency,
    metric: data.metric,
    comparison: {
      windowDays: data.comparisonDays,
      current: {
        start: data.currentPeriod.start,
        end: data.currentPeriod.end,
        total: round(data.currentPeriod.total),
      },
      previous: {
        start: data.previousPeriod.start,
        end: data.previousPeriod.end,
        total: round(data.previousPeriod.total),
      },
      delta: round(data.totalDelta),
      percent: data.totalPercentChange === null ? null : round(data.totalPercentChange, 1),
    },
    thresholds: data.thresholds,
    topIncreases: data.topIncreases.slice(0, MAX_ROWS).map(row),
    topDecreases: data.topDecreases.slice(0, MAX_ROWS).map(row),
    newCosts: data.newCosts.slice(0, MAX_ROWS).map(row),
    removedCosts: data.removedCosts.slice(0, MAX_ROWS).map(row),
    byRegion: data.byRegion.slice(0, MAX_ROWS).map(row),
    // A short daily tail is enough to spot a step change without shipping 90 rows.
    dailyTail: data.dailySeries
      .slice(-14)
      .map((point) => ({ d: point.date, v: round(point.amount) })),
    monthly: data.monthlySeries
      .slice(-6)
      .map((point) => ({ m: point.date, v: round(point.amount) })),
    estimatesIncluded: data.containsEstimates,
  };
}

export function compactSecurity(data: SecurityData): unknown {
  return {
    summary: data.summary,
    findings: data.findings
      .filter((finding) => finding.status !== 'ignored')
      .slice(0, 60)
      .map((finding) => ({
        id: finding.id,
        check: finding.checkId,
        title: finding.title,
        severity: finding.severity,
        status: finding.status,
        region: finding.region,
        resourceType: finding.resourceType,
        resource: finding.resourceId,
        source: finding.source,
        why: finding.why,
        evidence: finding.evidence,
      })),
    checksNotEvaluated: data.checks
      .filter((check) => check.state === 'not-evaluated')
      .slice(0, 40)
      .map((check) => ({
        check: check.checkId,
        service: check.service,
        region: check.region,
        reasons: check.issues.map((issue) => issue.label).slice(0, 3),
      })),
  };
}

export function compactCloudWatch(data: CloudWatchData): unknown {
  const row = (insight: CloudWatchData['logGroups'][number]) => ({
    name: insight.name,
    region: insight.region,
    storedMB: round(insight.storedBytes / 1_048_576, 1),
    growthMB: insight.growthBytes === null ? null : round(insight.growthBytes / 1_048_576, 1),
    growthPercent: insight.growthPercent === null ? null : round(insight.growthPercent, 1),
    retentionDays: insight.retentionInDays,
  });

  return {
    windowDays: data.windowDays,
    thresholds: {
      growthPercent: data.thresholds.growthPercent,
      growthMB: round(data.thresholds.growthBytes / 1_048_576, 0),
      longRetentionDays: data.thresholds.longRetentionDays,
    },
    totals: {
      logGroups: data.totals.logGroups,
      inspected: data.totals.inspected,
      storedGB: round(data.totals.storedBytes / 1_073_741_824, 2),
      metricsUnavailable: data.totals.metricsUnavailable,
    },
    largest: data.largest.slice(0, MAX_ROWS).map(row),
    rapidlyGrowing: data.rapidlyGrowing.slice(0, MAX_ROWS).map(row),
    noRetention: data.noRetention.slice(0, MAX_ROWS).map(row),
    longRetention: data.longRetention.slice(0, MAX_ROWS).map(row),
  };
}

export function compactComputeOptimizer(data: ComputeOptimizerData): unknown {
  return {
    enrollment: data.enrollment,
    totals: data.totals,
    byResourceType: data.byResourceType,
    recommendations: data.recommendations.slice(0, 30).map((recommendation) => ({
      type: recommendation.resourceType,
      resource: recommendation.resourceId,
      region: recommendation.region,
      finding: recommendation.finding,
      reasons: recommendation.findingReasons.slice(0, 5),
      current: recommendation.currentConfiguration,
      recommended: recommendation.recommendedConfiguration,
      performanceRisk: recommendation.performanceRisk,
      estimatedMonthlySavings: recommendation.estimatedMonthlySavings,
      savingsPercent: recommendation.savingsPercentage,
    })),
  };
}

export interface CloudTrailPayloadInput {
  aggregates: unknown;
  total: number;
  truncated: boolean;
  events: NormalisedEvent[];
  /** True when the user explicitly picked the events to analyse. */
  userSelected: boolean;
}

export function compactCloudTrail(input: CloudTrailPayloadInput): unknown {
  const limit = input.userSelected ? 100 : 40;
  return {
    matchedEvents: input.total,
    truncated: input.truncated,
    selection: input.userSelected ? 'user-selected events' : 'most recent matching events',
    aggregates: input.aggregates,
    events: input.events.slice(0, limit).map((event) => ({
      time: event.eventTime,
      name: event.eventName,
      source: event.eventSource,
      region: event.awsRegion,
      user: event.username,
      principalType: event.principalType,
      sourceIp: event.sourceIp,
      readOnly: event.readOnly,
      error: event.errorCode,
      resources: event.resources.slice(0, 5),
    })),
  };
}

export interface AiPayload {
  /** Prompt template version, so behaviour changes are traceable. */
  promptVersion: string;
  generatedAt: string;
  analysis: {
    kind: 'section' | 'cross-section';
    sections: SectionId[];
    profiles: string[];
    regions: string[];
  };
  sections: CompactSectionPayload[];
  /** Sanitized summaries of prior analyses, when AI history is enabled. */
  history?: Array<{ analysedAt: string; sections: string[]; summary: string }>;
  userQuestion?: string;
}

export function buildSectionPayload(input: {
  section: SectionId;
  profile: string;
  accountId?: string;
  regions: string[];
  data: unknown;
  issues: readonly EvaluationIssue[];
}): CompactSectionPayload {
  return {
    section: input.section,
    profile: input.profile,
    ...(input.accountId ? { accountId: input.accountId } : {}),
    regions: input.regions,
    data: input.data,
    notEvaluated: compactIssues(input.issues),
  };
}
