/**
 * CloudTrail event search.
 *
 * AWS `LookupEvents` supports exactly one lookup attribute per request, so the
 * strategy is: push the most selective filter AWS can evaluate down to the API,
 * then apply the remaining filters locally while paging. Results are paginated
 * for the UI and never loaded wholesale into an AI request.
 */

import {
  CloudTrailClient,
  LookupEventsCommand,
  type LookupEventsCommandOutput,
  type Event as CloudTrailEvent,
  type LookupAttributeKey,
} from '@aws-sdk/client-cloudtrail';

import type { AwsAccessLayer } from '../aws/access-layer.js';
import { classifyAwsError, ERROR_KIND_LABEL } from '../util/errors.js';
import { mapWithConcurrency } from '../util/async.js';
import type { CloudTrailConfig } from '../config/schema.js';
import { issueFromError, type EvaluationIssue } from './types.js';

export interface CloudTrailSearchFilters {
  startTime?: string;
  endTime?: string;
  eventName?: string;
  eventSource?: string;
  username?: string;
  resourceType?: string;
  resourceName?: string;
  sourceIp?: string;
  readOnly?: 'read' | 'write' | 'all';
  outcome?: 'success' | 'failure' | 'all';
  /** Free-text match applied locally across the event record. */
  text?: string;
}

export interface NormalisedEvent {
  id: string;
  eventName: string;
  eventSource: string;
  eventTime: string;
  awsRegion: string;
  profile: string;
  accountId?: string;
  username?: string;
  principalType?: string;
  sourceIp?: string;
  userAgent?: string;
  readOnly: boolean | null;
  errorCode?: string;
  errorMessage?: string;
  resources: Array<{ type?: string; name?: string }>;
  requestParameters?: unknown;
  /** Full CloudTrail record, retained in memory only. */
  raw?: unknown;
}

export interface CloudTrailSearchResult {
  /** Every matching event, bounded by `maxEventsPerSearch`. Paginated by the caller. */
  events: NormalisedEvent[];
  total: number;
  truncated: boolean;
  issues: EvaluationIssue[];
  aggregates: {
    byEventName: Array<{ key: string; count: number }>;
    byEventSource: Array<{ key: string; count: number }>;
    byUser: Array<{ key: string; count: number }>;
    bySourceIp: Array<{ key: string; count: number }>;
    byOutcome: Array<{ key: string; count: number }>;
    byRegion: Array<{ key: string; count: number }>;
  };
}

function parseRecord(event: CloudTrailEvent, profile: string, accountId?: string): NormalisedEvent {
  let record: Record<string, any> = {};
  try {
    record = event.CloudTrailEvent ? JSON.parse(event.CloudTrailEvent) : {};
  } catch {
    record = {};
  }

  return {
    id: event.EventId ?? `${event.EventName}-${event.EventTime?.toISOString() ?? ''}`,
    eventName: event.EventName ?? record.eventName ?? 'unknown',
    eventSource: event.EventSource ?? record.eventSource ?? 'unknown',
    eventTime: (
      event.EventTime ?? (record.eventTime ? new Date(record.eventTime) : new Date())
    ).toISOString(),
    awsRegion: record.awsRegion ?? 'unknown',
    profile,
    ...(accountId ? { accountId } : {}),
    ...(event.Username || record.userIdentity?.userName
      ? { username: event.Username ?? record.userIdentity?.userName }
      : {}),
    ...(record.userIdentity?.type ? { principalType: record.userIdentity.type } : {}),
    ...(record.sourceIPAddress ? { sourceIp: record.sourceIPAddress } : {}),
    ...(record.userAgent ? { userAgent: record.userAgent } : {}),
    readOnly: typeof record.readOnly === 'boolean' ? record.readOnly : null,
    ...(record.errorCode ? { errorCode: record.errorCode } : {}),
    ...(record.errorMessage ? { errorMessage: String(record.errorMessage).slice(0, 500) } : {}),
    resources: (event.Resources ?? []).map((resource) => ({
      ...(resource.ResourceType ? { type: resource.ResourceType } : {}),
      ...(resource.ResourceName ? { name: resource.ResourceName } : {}),
    })),
    ...(record.requestParameters ? { requestParameters: record.requestParameters } : {}),
    raw: record,
  };
}

/** Chooses the single lookup attribute AWS will evaluate server-side. */
export function selectLookupAttribute(
  filters: CloudTrailSearchFilters
): { AttributeKey: LookupAttributeKey; AttributeValue: string } | undefined {
  if (filters.eventName) {
    return { AttributeKey: 'EventName' as LookupAttributeKey, AttributeValue: filters.eventName };
  }
  if (filters.resourceName) {
    return {
      AttributeKey: 'ResourceName' as LookupAttributeKey,
      AttributeValue: filters.resourceName,
    };
  }
  if (filters.username) {
    return { AttributeKey: 'Username' as LookupAttributeKey, AttributeValue: filters.username };
  }
  if (filters.eventSource) {
    return {
      AttributeKey: 'EventSource' as LookupAttributeKey,
      AttributeValue: filters.eventSource,
    };
  }
  if (filters.resourceType) {
    return {
      AttributeKey: 'ResourceType' as LookupAttributeKey,
      AttributeValue: filters.resourceType,
    };
  }
  return undefined;
}

/** Local filtering for everything AWS cannot express in a lookup attribute. */
export function matchesFilters(event: NormalisedEvent, filters: CloudTrailSearchFilters): boolean {
  if (filters.eventName && event.eventName !== filters.eventName) return false;
  if (filters.eventSource && event.eventSource !== filters.eventSource) return false;
  if (filters.username && event.username !== filters.username) return false;
  if (filters.sourceIp && event.sourceIp !== filters.sourceIp) return false;
  if (
    filters.resourceType &&
    !event.resources.some((resource) => resource.type === filters.resourceType)
  ) {
    return false;
  }
  if (
    filters.resourceName &&
    !event.resources.some((resource) => resource.name === filters.resourceName)
  ) {
    return false;
  }
  if (filters.readOnly === 'read' && event.readOnly !== true) return false;
  if (filters.readOnly === 'write' && event.readOnly !== false) return false;
  if (filters.outcome === 'failure' && !event.errorCode) return false;
  if (filters.outcome === 'success' && event.errorCode) return false;
  if (filters.text) {
    const needle = filters.text.toLowerCase();
    const haystack = JSON.stringify({
      eventName: event.eventName,
      eventSource: event.eventSource,
      username: event.username,
      sourceIp: event.sourceIp,
      userAgent: event.userAgent,
      errorCode: event.errorCode,
      errorMessage: event.errorMessage,
      resources: event.resources,
      requestParameters: event.requestParameters,
    }).toLowerCase();
    if (!haystack.includes(needle)) return false;
  }
  return true;
}

function topCounts(
  values: Array<string | undefined>,
  limit = 10
): Array<{ key: string; count: number }> {
  const counts = new Map<string, number>();
  for (const value of values) {
    const key = value ?? 'unknown';
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

export interface CloudTrailSearchOptions {
  profiles: Array<{ profile: string; accountId?: string }>;
  regions: string[];
  filters: CloudTrailSearchFilters;
  config: CloudTrailConfig;
  section?: string;
  now?: Date;
}

export async function searchCloudTrail(
  access: AwsAccessLayer,
  options: CloudTrailSearchOptions
): Promise<CloudTrailSearchResult> {
  const section = options.section ?? 'cloudtrail';
  const filters = options.filters;
  const now = options.now ?? new Date();
  const endTime = filters.endTime ? new Date(filters.endTime) : now;
  const startTime = filters.startTime
    ? new Date(filters.startTime)
    : new Date(endTime.getTime() - options.config.defaultLookbackHours * 60 * 60 * 1000);

  const lookupAttribute = selectLookupAttribute(filters);
  const issues: EvaluationIssue[] = [];
  const collected: NormalisedEvent[] = [];
  let truncated = false;

  const units = options.profiles.flatMap((profile) =>
    options.regions.map((region) => ({ ...profile, region }))
  );

  await mapWithConcurrency(units, 4, async (unit) => {
    const client = access.client('cloudtrail', CloudTrailClient, {
      profile: unit.profile,
      region: unit.region,
    });
    let token: string | undefined;
    let fetched = 0;

    try {
      do {
        const output = await client.send<LookupEventsCommandOutput>(
          new LookupEventsCommand({
            StartTime: startTime,
            EndTime: endTime,
            MaxResults: 50,
            ...(lookupAttribute ? { LookupAttributes: [lookupAttribute] } : {}),
            ...(token ? { NextToken: token } : {}),
          }),
          { section }
        );

        for (const event of output.Events ?? []) {
          const normalised = parseRecord(event, unit.profile, unit.accountId);
          fetched += 1;
          if (matchesFilters(normalised, filters)) collected.push(normalised);
        }

        token = output.NextToken;
        if (fetched >= options.config.maxEventsPerSearch) {
          truncated = Boolean(token);
          break;
        }
      } while (token);
    } catch (error) {
      const classified = classifyAwsError(error);
      issues.push(
        issueFromError(
          classified,
          {
            profile: unit.profile,
            ...(unit.accountId ? { accountId: unit.accountId } : {}),
            region: unit.region,
            service: 'CloudTrail',
            requiredPermission: 'cloudtrail:LookupEvents',
          },
          `${ERROR_KIND_LABEL[classified.kind]} (CloudTrail search)`
        )
      );
    }
  });

  collected.sort((a, b) => b.eventTime.localeCompare(a.eventTime));

  return {
    events: collected,
    total: collected.length,
    truncated,
    issues,
    aggregates: {
      byEventName: topCounts(collected.map((event) => event.eventName)),
      byEventSource: topCounts(collected.map((event) => event.eventSource)),
      byUser: topCounts(collected.map((event) => event.username)),
      bySourceIp: topCounts(collected.map((event) => event.sourceIp)),
      byOutcome: topCounts(collected.map((event) => (event.errorCode ? 'failure' : 'success'))),
      byRegion: topCounts(collected.map((event) => event.awsRegion)),
    },
  };
}
