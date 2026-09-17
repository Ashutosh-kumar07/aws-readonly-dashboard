/** CloudWatch growth/retention thresholds and CloudTrail search behaviour. */

import { describe, expect, it } from 'vitest';

import { classifyLogGroup, fetchCloudWatchInsights } from '../src/services/cloudwatch.js';
import {
  matchesFilters,
  selectLookupAttribute,
  searchCloudTrail,
  type NormalisedEvent,
} from '../src/services/cloudtrail.js';
import { compactCloudTrail } from '../src/ai/payload.js';
import { AwsAccessLayer } from '../src/aws/access-layer.js';
import { defaultConfig } from '../src/config/schema.js';
import { FakeClient, awsError } from './helpers.js';

const GB = 1024 * 1024 * 1024;
const thresholds = {
  growthPercentThreshold: 5,
  growthBytesThreshold: 2 * GB,
  longRetentionDays: 90,
};

describe('CloudWatch log-group classification', () => {
  it('flags growth above the percentage threshold', () => {
    const result = classifyLogGroup(
      { storedBytes: 110, retentionInDays: 30, growthBytes: 10 },
      thresholds
    );
    expect(result.growthPercent).toBe(10);
    expect(result.flags.rapidGrowth).toBe(true);
  });

  it('flags growth above the absolute threshold even at a low percentage', () => {
    const result = classifyLogGroup(
      { storedBytes: 1000 * GB, retentionInDays: 30, growthBytes: 3 * GB },
      thresholds
    );
    expect(result.growthPercent).toBeLessThan(5);
    expect(result.flags.rapidGrowth).toBe(true);
  });

  it('does not flag growth below both thresholds', () => {
    const result = classifyLogGroup(
      { storedBytes: 1000 * GB, retentionInDays: 30, growthBytes: 1 * GB },
      thresholds
    );
    expect(result.flags.rapidGrowth).toBe(false);
  });

  it('flags a log group with no retention policy', () => {
    const result = classifyLogGroup(
      { storedBytes: 100, retentionInDays: null, growthBytes: 0 },
      thresholds
    );
    expect(result.flags.noRetention).toBe(true);
    expect(result.flags.longRetention).toBe(false);
  });

  it('flags long retention at or above the configured threshold', () => {
    expect(
      classifyLogGroup({ storedBytes: 1, retentionInDays: 90, growthBytes: 0 }, thresholds).flags
        .longRetention
    ).toBe(true);
    expect(
      classifyLogGroup({ storedBytes: 1, retentionInDays: 30, growthBytes: 0 }, thresholds).flags
        .longRetention
    ).toBe(false);
  });

  it('respects a custom long-retention threshold', () => {
    const custom = { ...thresholds, longRetentionDays: 7 };
    expect(
      classifyLogGroup({ storedBytes: 1, retentionInDays: 14, growthBytes: 0 }, custom).flags
        .longRetention
    ).toBe(true);
  });

  it('does not invent a growth figure when the metric is unavailable', () => {
    const result = classifyLogGroup(
      { storedBytes: 100, retentionInDays: 30, growthBytes: null },
      thresholds
    );
    expect(result.growthPercent).toBeNull();
    expect(result.flags.rapidGrowth).toBe(false);
  });
});

describe('CloudWatch fetch', () => {
  it('builds insights from log groups and the IncomingBytes metric', async () => {
    const client = new FakeClient({
      DescribeLogGroups: {
        logGroups: [
          { logGroupName: '/aws/lambda/big', storedBytes: 50 * GB, retentionInDays: null },
          { logGroupName: '/aws/lambda/small', storedBytes: 1024, retentionInDays: 7 },
        ],
      },
      GetMetricData: {
        MetricDataResults: [
          { Id: 'm0', Values: [10 * GB] },
          { Id: 'm1', Values: [0] },
        ],
      },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });

    const result = await fetchCloudWatchInsights(layer, {
      profile: 'dev',
      regions: ['us-east-1'],
      config: defaultConfig().cloudwatch,
    });

    const data = result.data!;
    expect(data.totals.inspected).toBe(2);
    expect(data.largest[0]?.name).toBe('/aws/lambda/big');
    expect(data.noRetention.map((group) => group.name)).toEqual(['/aws/lambda/big']);
    expect(data.rapidlyGrowing[0]?.growthBytes).toBe(10 * GB);
  });

  it('reports a metrics permission failure without losing the log-group inventory', async () => {
    const client = new FakeClient({
      DescribeLogGroups: {
        logGroups: [{ logGroupName: '/a', storedBytes: 10, retentionInDays: null }],
      },
      GetMetricData: awsError('AccessDeniedException', 'denied', 403),
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 0 });

    const result = await fetchCloudWatchInsights(layer, {
      profile: 'dev',
      regions: ['us-east-1'],
      config: defaultConfig().cloudwatch,
    });

    expect(result.status).toBe('partial');
    expect(result.data?.logGroups).toHaveLength(1);
    expect(result.data?.logGroups[0]?.growthBytes).toBeNull();
    expect(result.issues[0]?.kind).toBe('access-denied');
  });
});

function event(overrides: Partial<NormalisedEvent> = {}): NormalisedEvent {
  return {
    id: 'e1',
    eventName: 'RunInstances',
    eventSource: 'ec2.amazonaws.com',
    eventTime: '2026-03-15T10:00:00.000Z',
    awsRegion: 'us-east-1',
    profile: 'dev',
    username: 'deployer',
    sourceIp: '203.0.113.10',
    readOnly: false,
    resources: [{ type: 'AWS::EC2::Instance', name: 'i-1234567890abcdef0' }],
    ...overrides,
  };
}

describe('CloudTrail filters', () => {
  it('pushes the most selective filter down to AWS', () => {
    expect(selectLookupAttribute({ eventName: 'RunInstances' })).toEqual({
      AttributeKey: 'EventName',
      AttributeValue: 'RunInstances',
    });
    expect(selectLookupAttribute({ username: 'deployer' })?.AttributeKey).toBe('Username');
    expect(selectLookupAttribute({ eventSource: 'ec2.amazonaws.com' })?.AttributeKey).toBe(
      'EventSource'
    );
    expect(selectLookupAttribute({})).toBeUndefined();
  });

  it('applies the remaining filters locally', () => {
    const sample = event();
    expect(matchesFilters(sample, { sourceIp: '203.0.113.10' })).toBe(true);
    expect(matchesFilters(sample, { sourceIp: '198.51.100.1' })).toBe(false);
    expect(matchesFilters(sample, { readOnly: 'write' })).toBe(true);
    expect(matchesFilters(sample, { readOnly: 'read' })).toBe(false);
    expect(matchesFilters(sample, { outcome: 'success' })).toBe(true);
    expect(matchesFilters(event({ errorCode: 'AccessDenied' }), { outcome: 'failure' })).toBe(true);
    expect(matchesFilters(sample, { resourceType: 'AWS::EC2::Instance' })).toBe(true);
    expect(matchesFilters(sample, { resourceType: 'AWS::S3::Bucket' })).toBe(false);
  });

  it('supports free-text search across the event record', () => {
    expect(matchesFilters(event(), { text: 'i-1234567890abcdef0' })).toBe(true);
    expect(matchesFilters(event(), { text: 'nothing-like-this' })).toBe(false);
  });

  it('combines filters conjunctively', () => {
    const sample = event();
    expect(matchesFilters(sample, { eventName: 'RunInstances', readOnly: 'write' })).toBe(true);
    expect(matchesFilters(sample, { eventName: 'RunInstances', readOnly: 'read' })).toBe(false);
  });
});

describe('CloudTrail search', () => {
  function lookupResponse(count: number, token?: string) {
    return {
      Events: Array.from({ length: count }, (_, index) => ({
        EventId: `event-${token ?? 'first'}-${index}`,
        EventName: index % 2 === 0 ? 'RunInstances' : 'GetObject',
        EventSource: 'ec2.amazonaws.com',
        EventTime: new Date(Date.UTC(2026, 2, 15, 10, index)),
        Username: 'deployer',
        Resources: [],
        CloudTrailEvent: JSON.stringify({
          awsRegion: 'us-east-1',
          sourceIPAddress: '203.0.113.10',
          readOnly: index % 2 !== 0,
          userIdentity: { type: 'IAMUser', userName: 'deployer' },
        }),
      })),
      NextToken: token,
    };
  }

  it('returns every matching event and lets the caller paginate', async () => {
    const client = new FakeClient({ LookupEvents: lookupResponse(60) });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });

    const result = await searchCloudTrail(layer, {
      profiles: [{ profile: 'dev', accountId: '111122223333' }],
      regions: ['us-east-1'],
      filters: {},
      config: defaultConfig().cloudtrail,
    });

    expect(result.total).toBe(60);
    expect(result.events).toHaveLength(60);
    // Newest first.
    expect(result.events[0]!.eventTime > result.events[59]!.eventTime).toBe(true);
  });

  it('follows pagination until the per-search cap', async () => {
    let page = 0;
    const client = new FakeClient({
      LookupEvents: () => {
        page += 1;
        return page < 5 ? lookupResponse(50, `page-${page}`) : lookupResponse(50);
      },
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });
    const config = { ...defaultConfig().cloudtrail, maxEventsPerSearch: 120 };

    const result = await searchCloudTrail(layer, {
      profiles: [{ profile: 'dev' }],
      regions: ['us-east-1'],
      filters: {},
      config,
    });

    expect(result.total).toBeGreaterThanOrEqual(120);
    expect(result.truncated).toBe(true);
  });

  it('applies local filters while paging', async () => {
    const client = new FakeClient({ LookupEvents: lookupResponse(20) });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });

    const result = await searchCloudTrail(layer, {
      profiles: [{ profile: 'dev' }],
      regions: ['us-east-1'],
      filters: { readOnly: 'write' },
      config: defaultConfig().cloudtrail,
    });

    expect(result.total).toBe(10);
    expect(result.events.every((item) => item.readOnly === false)).toBe(true);
  });

  it('searches every selected profile and region and keeps the context', async () => {
    const client = new FakeClient({ LookupEvents: lookupResponse(2) });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });

    const result = await searchCloudTrail(layer, {
      profiles: [{ profile: 'dev' }, { profile: 'prd' }],
      regions: ['us-east-1', 'eu-west-1'],
      filters: {},
      config: defaultConfig().cloudtrail,
    });

    expect(new Set(result.events.map((item) => item.profile))).toEqual(new Set(['dev', 'prd']));
    expect(result.total).toBe(8); // 2 profiles × 2 regions × 2 events
  });

  it('reports a permission failure per profile and region', async () => {
    const client = new FakeClient({
      LookupEvents: awsError('AccessDeniedException', 'denied', 403),
    });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never, maxRetries: 0 });

    const result = await searchCloudTrail(layer, {
      profiles: [{ profile: 'dev' }],
      regions: ['us-east-1'],
      filters: {},
      config: defaultConfig().cloudtrail,
    });

    expect(result.events).toHaveLength(0);
    expect(result.issues[0]?.kind).toBe('access-denied');
  });

  it('builds aggregates for the whole result set', async () => {
    const client = new FakeClient({ LookupEvents: lookupResponse(10) });
    const layer = new AwsAccessLayer({ clientFactory: () => client as never });

    const result = await searchCloudTrail(layer, {
      profiles: [{ profile: 'dev' }],
      regions: ['us-east-1'],
      filters: {},
      config: defaultConfig().cloudtrail,
    });

    expect(result.aggregates.byEventName.map((entry) => entry.key).sort()).toEqual([
      'GetObject',
      'RunInstances',
    ]);
    expect(result.aggregates.byUser[0]).toEqual({ key: 'deployer', count: 10 });
  });
});

describe('CloudTrail AI payload reduction', () => {
  it('caps the events sent for an unselected search', () => {
    const events = Array.from({ length: 500 }, (_, index) => event({ id: `e${index}` }));
    const payload = compactCloudTrail({
      aggregates: {},
      total: events.length,
      truncated: false,
      events,
      userSelected: false,
    }) as { events: unknown[]; selection: string };

    expect(payload.events.length).toBeLessThanOrEqual(40);
    expect(payload.selection).toBe('most recent matching events');
  });

  it('sends more events when the user picked them explicitly', () => {
    const events = Array.from({ length: 500 }, (_, index) => event({ id: `e${index}` }));
    const payload = compactCloudTrail({
      aggregates: {},
      total: events.length,
      truncated: false,
      events,
      userSelected: true,
    }) as { events: unknown[]; selection: string };

    expect(payload.events.length).toBe(100);
    expect(payload.selection).toBe('user-selected events');
  });

  it('drops the raw CloudTrail record from the payload', () => {
    const payload = compactCloudTrail({
      aggregates: {},
      total: 1,
      truncated: false,
      events: [event({ raw: { secret: 'do-not-send' } })],
      userSelected: true,
    }) as { events: Array<Record<string, unknown>> };

    expect(payload.events[0]).not.toHaveProperty('raw');
    expect(JSON.stringify(payload)).not.toContain('do-not-send');
  });
});
