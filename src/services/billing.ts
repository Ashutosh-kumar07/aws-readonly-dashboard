/**
 * Billing / cost analysis via AWS Cost Explorer.
 *
 * Cost Explorer is a global (us-east-1) API and its granularity is the
 * granularity AWS actually offers: cost is attributed to services, regions and
 * days. The dashboard deliberately does not pretend that every charge maps to
 * an individual resource, because Cost Explorer cannot reliably provide that.
 */

import {
  CostExplorerClient,
  GetCostAndUsageCommand,
  type GetCostAndUsageCommandOutput,
  type Expression,
} from '@aws-sdk/client-cost-explorer';

import type { AwsAccessLayer } from '../aws/access-layer.js';
import { GLOBAL_SCOPE } from '../aws/regions.js';
import { classifyAwsError } from '../util/errors.js';
import { ERROR_KIND_LABEL } from '../util/errors.js';
import { mapWithConcurrency } from '../util/async.js';
import type { BillingConfig } from '../config/schema.js';
import { issueFromError, type EvaluationIssue, type ProfileScoped } from './types.js';

export type CostChangeKind = 'increase' | 'decrease' | 'new' | 'removed' | 'unchanged';

export interface CostChange {
  key: string;
  currentCost: number;
  previousCost: number;
  /** Absolute dollar change, current minus previous. */
  delta: number;
  /** Percentage change; `null` when the previous period was zero. */
  percentChange: number | null;
  kind: CostChangeKind;
  /** True when the dollar or percentage threshold is met. */
  exceedsThreshold: boolean;
}

export interface CostPoint {
  date: string;
  amount: number;
}

export interface WeeklyPoint {
  weekStart: string;
  weekEnd: string;
  amount: number;
}

export interface BillingPeriod {
  start: string;
  /** Exclusive end date, matching Cost Explorer semantics. */
  end: string;
  total: number;
}

export interface BillingData {
  currency: string;
  metric: string;
  comparisonDays: number;
  thresholds: { dollar: number; percent: number };
  currentPeriod: BillingPeriod;
  previousPeriod: BillingPeriod;
  totalDelta: number;
  totalPercentChange: number | null;
  byService: CostChange[];
  byRegion: CostChange[];
  topIncreases: CostChange[];
  topDecreases: CostChange[];
  newCosts: CostChange[];
  removedCosts: CostChange[];
  dailySeries: CostPoint[];
  weeklySeries: WeeklyPoint[];
  monthlySeries: CostPoint[];
  /** True when AWS returned estimated (not yet finalised) amounts. */
  containsEstimates: boolean;
}

const ISO_DAY = 24 * 60 * 60 * 1000;

export function formatDate(date: Date): string {
  return date.toISOString().slice(0, 10);
}

export function addDays(date: Date, days: number): Date {
  return new Date(date.getTime() + days * ISO_DAY);
}

/** Start of the UTC day; Cost Explorer works in whole days. */
export function startOfUtcDay(date: Date): Date {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

export interface RollingPeriods {
  current: { start: string; end: string };
  previous: { start: string; end: string };
  chartStart: string;
}

/**
 * Rolling comparison windows. The current period ends today (exclusive), so the
 * last complete day is yesterday; the previous period is the equally long window
 * immediately before it. Calendar weeks are deliberately not used.
 */
export function computeRollingPeriods(
  comparisonDays: number,
  now: Date = new Date(),
  chartMinimumDays = 30
): RollingPeriods {
  const today = startOfUtcDay(now);
  const currentEnd = today;
  const currentStart = addDays(currentEnd, -comparisonDays);
  const previousEnd = currentStart;
  const previousStart = addDays(previousEnd, -comparisonDays);
  const chartDays = Math.min(92, Math.max(chartMinimumDays, comparisonDays * 2));

  return {
    current: { start: formatDate(currentStart), end: formatDate(currentEnd) },
    previous: { start: formatDate(previousStart), end: formatDate(previousEnd) },
    chartStart: formatDate(addDays(currentEnd, -chartDays)),
  };
}

export function classifyChange(
  previousCost: number,
  currentCost: number,
  thresholds: { dollar: number; percent: number }
): Pick<CostChange, 'delta' | 'percentChange' | 'kind' | 'exceedsThreshold'> {
  const delta = round(currentCost - previousCost);
  const percentChange = previousCost === 0 ? null : round((delta / previousCost) * 100);

  let kind: CostChangeKind;
  if (previousCost === 0 && currentCost > 0) kind = 'new';
  else if (previousCost > 0 && currentCost === 0) kind = 'removed';
  else if (delta > 0) kind = 'increase';
  else if (delta < 0) kind = 'decrease';
  else kind = 'unchanged';

  const exceedsThreshold =
    kind === 'new'
      ? currentCost > 0
      : Math.abs(delta) >= thresholds.dollar ||
        (percentChange !== null && Math.abs(percentChange) >= thresholds.percent);

  return { delta, percentChange, kind, exceedsThreshold };
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}

interface DayGroup {
  date: string;
  groups: Map<string, number>;
  total: number;
  estimated: boolean;
}

function parseResults(
  outputs: GetCostAndUsageCommandOutput[],
  metric: string
): {
  days: DayGroup[];
  currency: string;
  estimated: boolean;
} {
  const days = new Map<string, DayGroup>();
  let currency = 'USD';
  let estimated = false;

  for (const output of outputs) {
    for (const period of output.ResultsByTime ?? []) {
      const date = period.TimePeriod?.Start ?? '';
      if (!date) continue;
      const day = days.get(date) ?? {
        date,
        groups: new Map<string, number>(),
        total: 0,
        estimated: false,
      };
      if (period.Estimated) {
        day.estimated = true;
        estimated = true;
      }

      const groups = period.Groups ?? [];
      if (groups.length === 0) {
        const total = period.Total?.[metric];
        if (total?.Amount !== undefined) {
          const amount = Number(total.Amount);
          if (Number.isFinite(amount)) day.total += amount;
          if (total.Unit) currency = total.Unit;
        }
      } else {
        for (const group of groups) {
          const key = group.Keys?.[0] ?? 'Unknown';
          const measure = group.Metrics?.[metric];
          const amount = Number(measure?.Amount ?? 0);
          if (measure?.Unit) currency = measure.Unit;
          if (!Number.isFinite(amount)) continue;
          day.groups.set(key, (day.groups.get(key) ?? 0) + amount);
          day.total += amount;
        }
      }
      days.set(date, day);
    }
  }

  return {
    days: [...days.values()].sort((a, b) => a.date.localeCompare(b.date)),
    currency,
    estimated,
  };
}

function sumBetween(days: DayGroup[], start: string, end: string): Map<string, number> {
  const totals = new Map<string, number>();
  for (const day of days) {
    if (day.date < start || day.date >= end) continue;
    for (const [key, amount] of day.groups) {
      totals.set(key, (totals.get(key) ?? 0) + amount);
    }
  }
  return totals;
}

function buildChanges(
  previous: Map<string, number>,
  current: Map<string, number>,
  thresholds: { dollar: number; percent: number }
): CostChange[] {
  const keys = new Set([...previous.keys(), ...current.keys()]);
  const changes: CostChange[] = [];
  for (const key of keys) {
    const previousCost = round(previous.get(key) ?? 0);
    const currentCost = round(current.get(key) ?? 0);
    if (previousCost === 0 && currentCost === 0) continue;
    changes.push({
      key,
      previousCost,
      currentCost,
      ...classifyChange(previousCost, currentCost, thresholds),
    });
  }
  return changes.sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));
}

export function buildWeeklySeries(daily: CostPoint[]): WeeklyPoint[] {
  if (daily.length === 0) return [];
  const weeks: WeeklyPoint[] = [];
  // Buckets are built backwards from the most recent day, so the newest bucket
  // is always a complete rolling week rather than a partial calendar week.
  for (let end = daily.length; end > 0; end -= 7) {
    const start = Math.max(0, end - 7);
    const slice = daily.slice(start, end);
    if (slice.length === 0) continue;
    weeks.unshift({
      weekStart: slice[0]!.date,
      weekEnd: slice[slice.length - 1]!.date,
      amount: round(slice.reduce((sum, point) => sum + point.amount, 0)),
    });
  }
  return weeks;
}

function costFilter(includeCredits: boolean): Expression | undefined {
  if (includeCredits) return undefined;
  return {
    Not: {
      Dimensions: { Key: 'RECORD_TYPE', Values: ['Credit', 'Refund'] },
    },
  };
}

export interface BillingFetchOptions {
  profile: string;
  accountId?: string;
  config: BillingConfig;
  now?: Date;
  section?: string;
}

/** Fetches and analyses Cost Explorer data for one profile. */
export async function fetchBillingForProfile(
  access: AwsAccessLayer,
  options: BillingFetchOptions
): Promise<ProfileScoped<BillingData>> {
  const { profile, config } = options;
  const section = options.section ?? 'billing';
  const issues: EvaluationIssue[] = [];
  const periods = computeRollingPeriods(config.comparisonDays, options.now ?? new Date());
  const thresholds = { dollar: config.dollarThreshold, percent: config.percentThreshold };
  const client = access.client('cost-explorer', CostExplorerClient, {
    profile,
    region: GLOBAL_SCOPE,
  });
  const filter = costFilter(config.includeCredits);

  const collect = async (
    input: ConstructorParameters<typeof GetCostAndUsageCommand>[0]
  ): Promise<GetCostAndUsageCommandOutput[]> => {
    const outputs: GetCostAndUsageCommandOutput[] = [];
    let token: string | undefined;
    let pages = 0;
    do {
      const output = await client.send<GetCostAndUsageCommandOutput>(
        new GetCostAndUsageCommand({ ...input, ...(token ? { NextPageToken: token } : {}) }),
        { section }
      );
      outputs.push(output);
      token = output.NextPageToken;
      pages += 1;
    } while (token && pages < 20);
    return outputs;
  };

  const monthsBack = 12;
  const monthStart = new Date(
    Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth() - monthsBack + 1, 1)
  );

  const fetches: Array<{
    name: string;
    permission: string;
    run: () => Promise<GetCostAndUsageCommandOutput[]>;
  }> = [
    {
      name: 'daily cost by service',
      permission: 'ce:GetCostAndUsage',
      run: () =>
        collect({
          TimePeriod: { Start: periods.chartStart, End: periods.current.end },
          Granularity: 'DAILY',
          Metrics: [config.metric],
          GroupBy: [{ Type: 'DIMENSION', Key: 'SERVICE' }],
          ...(filter ? { Filter: filter } : {}),
        }),
    },
    {
      name: 'daily cost by region',
      permission: 'ce:GetCostAndUsage',
      run: () =>
        collect({
          TimePeriod: { Start: periods.previous.start, End: periods.current.end },
          Granularity: 'DAILY',
          Metrics: [config.metric],
          GroupBy: [{ Type: 'DIMENSION', Key: 'REGION' }],
          ...(filter ? { Filter: filter } : {}),
        }),
    },
    {
      name: 'monthly cost totals',
      permission: 'ce:GetCostAndUsage',
      run: () =>
        collect({
          TimePeriod: { Start: formatDate(monthStart), End: periods.current.end },
          Granularity: 'MONTHLY',
          Metrics: [config.metric],
          ...(filter ? { Filter: filter } : {}),
        }),
    },
  ];

  const results = await mapWithConcurrency(fetches, 2, async (fetch) => {
    try {
      return { ok: true as const, name: fetch.name, outputs: await fetch.run() };
    } catch (error) {
      const classified = classifyAwsError(error);
      issues.push(
        issueFromError(
          classified,
          {
            profile,
            ...(options.accountId ? { accountId: options.accountId } : {}),
            region: GLOBAL_SCOPE,
            service: 'Cost Explorer',
            requiredPermission: fetch.permission,
          },
          `${ERROR_KIND_LABEL[classified.kind]} (${fetch.name})`
        )
      );
      return {
        ok: false as const,
        name: fetch.name,
        outputs: [] as GetCostAndUsageCommandOutput[],
      };
    }
  });

  const [serviceResult, regionResult, monthlyResult] = results;

  if (!serviceResult?.ok) {
    return {
      profile,
      ...(options.accountId ? { accountId: options.accountId } : {}),
      status: 'failed',
      issues,
    };
  }

  const serviceParsed = parseResults(serviceResult.outputs, config.metric);
  const regionParsed = regionResult?.ok
    ? parseResults(regionResult.outputs, config.metric)
    : { days: [], currency: serviceParsed.currency, estimated: false };
  const monthlyParsed = monthlyResult?.ok
    ? parseResults(monthlyResult.outputs, config.metric)
    : { days: [], currency: serviceParsed.currency, estimated: false };

  const byService = buildChanges(
    sumBetween(serviceParsed.days, periods.previous.start, periods.previous.end),
    sumBetween(serviceParsed.days, periods.current.start, periods.current.end),
    thresholds
  );
  const byRegion = buildChanges(
    sumBetween(regionParsed.days, periods.previous.start, periods.previous.end),
    sumBetween(regionParsed.days, periods.current.start, periods.current.end),
    thresholds
  );

  const currentTotal = round(
    serviceParsed.days
      .filter((day) => day.date >= periods.current.start && day.date < periods.current.end)
      .reduce((sum, day) => sum + day.total, 0)
  );
  const previousTotal = round(
    serviceParsed.days
      .filter((day) => day.date >= periods.previous.start && day.date < periods.previous.end)
      .reduce((sum, day) => sum + day.total, 0)
  );

  const dailySeries: CostPoint[] = serviceParsed.days.map((day) => ({
    date: day.date,
    amount: round(day.total),
  }));

  const monthlySeries: CostPoint[] = monthlyParsed.days.map((day) => ({
    date: day.date.slice(0, 7),
    amount: round(day.total),
  }));

  const data: BillingData = {
    currency: serviceParsed.currency,
    metric: config.metric,
    comparisonDays: config.comparisonDays,
    thresholds,
    currentPeriod: { ...periods.current, total: currentTotal },
    previousPeriod: { ...periods.previous, total: previousTotal },
    totalDelta: round(currentTotal - previousTotal),
    totalPercentChange:
      previousTotal === 0 ? null : round(((currentTotal - previousTotal) / previousTotal) * 100),
    byService,
    byRegion,
    topIncreases: byService.filter((change) => change.kind === 'increase').slice(0, 20),
    topDecreases: byService.filter((change) => change.kind === 'decrease').slice(0, 20),
    newCosts: byService.filter((change) => change.kind === 'new'),
    removedCosts: byService.filter((change) => change.kind === 'removed'),
    dailySeries,
    weeklySeries: buildWeeklySeries(dailySeries),
    monthlySeries,
    containsEstimates: serviceParsed.estimated || monthlyParsed.estimated,
  };

  return {
    profile,
    ...(options.accountId ? { accountId: options.accountId } : {}),
    status: issues.length ? 'partial' : 'ok',
    data,
    issues,
  };
}
