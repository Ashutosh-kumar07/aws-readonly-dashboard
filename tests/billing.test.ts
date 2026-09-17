/** Rolling cost comparisons, thresholds and change classification. */

import { describe, expect, it } from 'vitest';

import {
  classifyChange,
  computeRollingPeriods,
  buildWeeklySeries,
  fetchBillingForProfile,
  formatDate,
} from '../src/services/billing.js';
import { AwsAccessLayer } from '../src/aws/access-layer.js';
import { defaultConfig } from '../src/config/schema.js';
import { FakeClient, awsError } from './helpers.js';

const NOW = new Date('2026-03-15T09:30:00Z');

describe('rolling comparison periods', () => {
  it('uses a rolling window ending today, not a calendar week', () => {
    const periods = computeRollingPeriods(7, NOW);
    expect(periods.current).toEqual({ start: '2026-03-08', end: '2026-03-15' });
    expect(periods.previous).toEqual({ start: '2026-03-01', end: '2026-03-08' });
  });

  it.each([1, 7, 14, 30, 60, 90])('supports a %s-day comparison', (days) => {
    const periods = computeRollingPeriods(days, NOW);
    const currentStart = Date.parse(`${periods.current.start}T00:00:00Z`);
    const currentEnd = Date.parse(`${periods.current.end}T00:00:00Z`);
    const previousStart = Date.parse(`${periods.previous.start}T00:00:00Z`);

    expect((currentEnd - currentStart) / 86_400_000).toBe(days);
    expect((currentStart - previousStart) / 86_400_000).toBe(days);
    expect(periods.previous.end).toBe(periods.current.start);
  });

  it('extends the chart window for short comparisons', () => {
    expect(computeRollingPeriods(1, NOW).chartStart).toBe('2026-02-13');
    expect(computeRollingPeriods(90, NOW).chartStart).toBe(
      formatDate(new Date('2025-12-13T00:00:00Z'))
    );
  });
});

describe('cost change classification', () => {
  const thresholds = { dollar: 20, percent: 10 };

  it('flags a new cost when the previous period was zero', () => {
    const change = classifyChange(0, 5, thresholds);
    expect(change.kind).toBe('new');
    expect(change.percentChange).toBeNull();
    // A new cost always qualifies, regardless of the thresholds.
    expect(change.exceedsThreshold).toBe(true);
  });

  it('flags a removed cost when the current period is zero', () => {
    const change = classifyChange(120, 0, thresholds);
    expect(change.kind).toBe('removed');
    expect(change.delta).toBe(-120);
    expect(change.exceedsThreshold).toBe(true);
  });

  it('qualifies on the dollar threshold alone', () => {
    const change = classifyChange(1000, 1025, thresholds);
    expect(change.kind).toBe('increase');
    expect(change.delta).toBe(25);
    expect(change.percentChange).toBe(2.5);
    expect(change.exceedsThreshold).toBe(true);
  });

  it('qualifies on the percentage threshold alone', () => {
    const change = classifyChange(10, 12, thresholds);
    expect(change.delta).toBe(2);
    expect(change.percentChange).toBe(20);
    expect(change.exceedsThreshold).toBe(true);
  });

  it('does not qualify when neither threshold is met', () => {
    const change = classifyChange(100, 105, thresholds);
    expect(change.percentChange).toBe(5);
    expect(change.exceedsThreshold).toBe(false);
  });

  it('reports decreases as well as increases', () => {
    const decrease = classifyChange(500, 400, thresholds);
    expect(decrease.kind).toBe('decrease');
    expect(decrease.delta).toBe(-100);
    expect(decrease.percentChange).toBe(-20);
    expect(decrease.exceedsThreshold).toBe(true);
  });

  it('treats an unchanged cost as unchanged', () => {
    expect(classifyChange(50, 50, thresholds).kind).toBe('unchanged');
    expect(classifyChange(50, 50, thresholds).exceedsThreshold).toBe(false);
  });

  it('honours custom thresholds', () => {
    const strict = { dollar: 1000, percent: 90 };
    expect(classifyChange(100, 150, strict).exceedsThreshold).toBe(false);
    expect(classifyChange(100, 200, strict).exceedsThreshold).toBe(true);
  });
});

describe('weekly bucketing', () => {
  it('builds rolling 7-day buckets anchored on the most recent day', () => {
    const daily = Array.from({ length: 14 }, (_, index) => ({
      date: `2026-03-${String(index + 1).padStart(2, '0')}`,
      amount: index + 1,
    }));
    const weekly = buildWeeklySeries(daily);
    expect(weekly).toHaveLength(2);
    expect(weekly[1]).toMatchObject({ weekStart: '2026-03-08', weekEnd: '2026-03-14' });
    expect(weekly[1]?.amount).toBe(8 + 9 + 10 + 11 + 12 + 13 + 14);
  });

  it('handles an empty series', () => {
    expect(buildWeeklySeries([])).toEqual([]);
  });
});

function costResponse(days: Array<{ date: string; groups: Array<[string, number]> }>) {
  return {
    ResultsByTime: days.map((day) => ({
      TimePeriod: { Start: day.date, End: day.date },
      Groups: day.groups.map(([key, amount]) => ({
        Keys: [key],
        Metrics: { UnblendedCost: { Amount: String(amount), Unit: 'USD' } },
      })),
      Estimated: false,
    })),
  };
}

describe('billing fetch', () => {
  it('computes the comparison from Cost Explorer results', async () => {
    const previousDays = Array.from({ length: 7 }, (_, index) => ({
      date: `2026-03-0${index + 1}`,
      groups: [
        ['Amazon EC2', 10],
        ['Amazon S3', 2],
      ] as Array<[string, number]>,
    }));
    const currentDays = Array.from({ length: 7 }, (_, index) => ({
      date: `2026-03-${String(index + 8).padStart(2, '0')}`,
      groups: [
        ['Amazon EC2', 20],
        ['AWS Lambda', 1],
      ] as Array<[string, number]>,
    }));

    const client = new FakeClient({
      GetCostAndUsage: costResponse([...previousDays, ...currentDays]),
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });

    const result = await fetchBillingForProfile(layer, {
      profile: 'dev',
      accountId: '111122223333',
      config: defaultConfig().billing,
      now: NOW,
    });

    expect(result.status).toBe('ok');
    const data = result.data!;
    expect(data.currentPeriod.total).toBe(147); // 7 × (20 + 1)
    expect(data.previousPeriod.total).toBe(84); // 7 × (10 + 2)
    expect(data.totalDelta).toBe(63);

    const ec2 = data.byService.find((change) => change.key === 'Amazon EC2');
    expect(ec2).toMatchObject({ currentCost: 140, previousCost: 70, kind: 'increase' });

    expect(data.newCosts.map((change) => change.key)).toContain('AWS Lambda');
    expect(data.removedCosts.map((change) => change.key)).toContain('Amazon S3');
  });

  it('reports a permission failure instead of pretending there is no cost', async () => {
    const client = new FakeClient({
      GetCostAndUsage: awsError(
        'AccessDeniedException',
        'not authorized to perform: ce:GetCostAndUsage',
        403
      ),
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 0 });

    const result = await fetchBillingForProfile(layer, {
      profile: 'dev',
      config: defaultConfig().billing,
      now: NOW,
    });

    expect(result.status).toBe('failed');
    expect(result.data).toBeUndefined();
    expect(result.issues[0]?.kind).toBe('access-denied');
    expect(result.issues[0]?.missingPermission).toBe('ce:GetCostAndUsage');
  });

  it('excludes credits and refunds unless the user opts in', async () => {
    const client = new FakeClient({ GetCostAndUsage: costResponse([]) });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });

    await fetchBillingForProfile(layer, {
      profile: 'dev',
      config: defaultConfig().billing,
      now: NOW,
    });

    const input = client.calls[0]?.input as {
      Filter?: { Not?: { Dimensions?: { Values?: string[] } } };
    };
    expect(input.Filter?.Not?.Dimensions?.Values).toEqual(['Credit', 'Refund']);
  });

  it('follows Cost Explorer pagination', async () => {
    let page = 0;
    const client = new FakeClient({
      GetCostAndUsage: () => {
        page += 1;
        return page === 1
          ? {
              ...costResponse([{ date: '2026-03-10', groups: [['Amazon EC2', 5]] }]),
              NextPageToken: 'more',
            }
          : costResponse([{ date: '2026-03-11', groups: [['Amazon EC2', 5]] }]);
      },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });

    const result = await fetchBillingForProfile(layer, {
      profile: 'dev',
      config: defaultConfig().billing,
      now: NOW,
    });

    expect(result.data?.currentPeriod.total).toBe(10);
    expect(client.calls.length).toBeGreaterThan(3);
  });
});
