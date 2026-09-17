/**
 * AWS API call accounting.
 *
 * Every AWS SDK invocation made through the access layer is recorded here — and
 * only AWS SDK invocations. AI provider calls are tracked separately and are
 * deliberately excluded from the AWS counter.
 *
 * Statistics are session scoped: they live in memory and reset when the local
 * server restarts, which matches the "no persistent AWS data" rule.
 */

import { API_CATEGORY_LABELS, type ApiCategory } from './allowlist.js';

export interface ApiCallRecord {
  id: number;
  timestamp: string;
  category: ApiCategory;
  categoryLabel: string;
  service: string;
  operation: string;
  profile: string;
  accountId?: string;
  /** AWS region, or `global` for global endpoints. */
  region: string;
  /** Dashboard section/action that caused this call. */
  section: string;
  status: 'success' | 'error';
  durationMs: number;
  errorCode?: string;
}

export interface CategoryUsage {
  category: ApiCategory;
  label: string;
  calls: number;
  successes: number;
  errors: number;
  operations: Array<{ operation: string; service: string; calls: number; errors: number }>;
}

export interface ApiUsageSnapshot {
  totalCalls: number;
  successfulCalls: number;
  failedCalls: number;
  sessionStartedAt: string;
  categories: CategoryUsage[];
  /** Most recent calls, newest first. Bounded by `maxRecords`. */
  recentCalls: ApiCallRecord[];
  recordedCalls: number;
  truncated: boolean;
}

interface OperationCounter {
  operation: string;
  service: string;
  calls: number;
  errors: number;
}

export class ApiCallTracker {
  private nextId = 1;
  private total = 0;
  private successes = 0;
  private failures = 0;
  private readonly startedAt = new Date().toISOString();
  private readonly records: ApiCallRecord[] = [];
  private readonly byCategory = new Map<
    ApiCategory,
    { calls: number; successes: number; errors: number; operations: Map<string, OperationCounter> }
  >();

  constructor(private readonly maxRecords = 5000) {}

  record(entry: Omit<ApiCallRecord, 'id' | 'timestamp' | 'categoryLabel'>): ApiCallRecord {
    const record: ApiCallRecord = {
      ...entry,
      id: this.nextId++,
      timestamp: new Date().toISOString(),
      categoryLabel: API_CATEGORY_LABELS[entry.category] ?? entry.category,
    };

    this.total += 1;
    if (record.status === 'success') this.successes += 1;
    else this.failures += 1;

    let bucket = this.byCategory.get(record.category);
    if (!bucket) {
      bucket = { calls: 0, successes: 0, errors: 0, operations: new Map() };
      this.byCategory.set(record.category, bucket);
    }
    bucket.calls += 1;
    if (record.status === 'success') bucket.successes += 1;
    else bucket.errors += 1;

    const opKey = `${record.service}:${record.operation}`;
    const counter = bucket.operations.get(opKey) ?? {
      operation: record.operation,
      service: record.service,
      calls: 0,
      errors: 0,
    };
    counter.calls += 1;
    if (record.status === 'error') counter.errors += 1;
    bucket.operations.set(opKey, counter);

    this.records.push(record);
    if (this.records.length > this.maxRecords) this.records.shift();

    return record;
  }

  get totalCalls(): number {
    return this.total;
  }

  snapshot(recentLimit = 500): ApiUsageSnapshot {
    const categories: CategoryUsage[] = [...this.byCategory.entries()]
      .map(([category, bucket]) => ({
        category,
        label: API_CATEGORY_LABELS[category] ?? category,
        calls: bucket.calls,
        successes: bucket.successes,
        errors: bucket.errors,
        operations: [...bucket.operations.values()].sort((a, b) => b.calls - a.calls),
      }))
      .sort((a, b) => b.calls - a.calls);

    return {
      totalCalls: this.total,
      successfulCalls: this.successes,
      failedCalls: this.failures,
      sessionStartedAt: this.startedAt,
      categories,
      recentCalls: this.records.slice(-recentLimit).reverse(),
      recordedCalls: this.records.length,
      truncated: this.total > this.records.length,
    };
  }

  /** Session-scoped reset; used by tests and by an explicit user action. */
  reset(): void {
    this.total = 0;
    this.successes = 0;
    this.failures = 0;
    this.records.length = 0;
    this.byCategory.clear();
    this.nextId = 1;
  }
}
