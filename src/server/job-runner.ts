/**
 * Background jobs with partial results.
 *
 * A security scan across several profiles and regions runs dozens of AWS checks
 * and can take well past the ten seconds that is generally treated as the limit
 * for holding someone's attention (Nielsen's response-time limits). Making the
 * user stare at a spinner until the slowest check returns wastes the results
 * that are already in hand.
 *
 * A job therefore publishes results as they arrive: the caller starts it, then
 * polls for a snapshot containing everything completed so far plus a progress
 * count. The dashboard renders each snapshot, so findings appear within a second
 * or two and fill in while the rest of the scan runs.
 *
 * Jobs are in-memory and session scoped, like all AWS data in this application.
 */

import { randomUUID } from 'node:crypto';

import { logger } from '../util/logger.js';
import type { SectionId } from '../services/types.js';

export interface JobProgress {
  completed: number;
  total: number;
  /** What finished most recently, e.g. "S3 public access (us-east-1)". */
  label?: string;
}

export interface JobSnapshot<T> {
  id: string;
  section: SectionId;
  status: 'running' | 'complete' | 'failed';
  startedAt: string;
  updatedAt: string;
  finishedAt?: string;
  progress: JobProgress;
  /** Everything completed so far. Complete once status is `complete`. */
  partial: T;
  error?: string;
}

/** Handle given to the work function so it can report as it goes. */
export interface JobContext<T> {
  /** Sets the number of units of work, once it is known. */
  setTotal(total: number): void;
  /** Records one completed unit and publishes the result so far. */
  advance(partial: T, label?: string): void;
  /**
   * Publishes an absolute progress position. Used by work that already counts
   * its own units, so the two counters cannot drift apart.
   */
  report(partial: T, progress: { completed: number; total: number; label?: string }): void;
  /** Publishes an updated result without advancing the counter. */
  update(partial: T): void;
  /** True once the job has been cancelled or the runner shut down. */
  readonly cancelled: boolean;
}

interface JobRecord<T> {
  snapshot: JobSnapshot<T>;
  cancelled: boolean;
  promise: Promise<void>;
}

const DEFAULT_RETENTION_MS = 10 * 60 * 1000;

export class JobRunner {
  private readonly jobs = new Map<string, JobRecord<unknown>>();
  /** Jobs currently running, keyed by caller-supplied dedupe key. */
  private readonly byKey = new Map<string, string>();

  constructor(private readonly retentionMs = DEFAULT_RETENTION_MS) {}

  /**
   * Starts a job and returns its first snapshot immediately. When `key` matches
   * a job that is still running, that job is returned instead of starting a
   * second identical scan.
   */
  start<T>(options: {
    section: SectionId;
    key: string;
    initial: T;
    run: (context: JobContext<T>) => Promise<T>;
  }): JobSnapshot<T> {
    const existingId = this.byKey.get(options.key);
    if (existingId) {
      const existing = this.jobs.get(existingId);
      if (existing && existing.snapshot.status === 'running') {
        return existing.snapshot as JobSnapshot<T>;
      }
    }

    const now = new Date().toISOString();
    const id = randomUUID();
    const snapshot: JobSnapshot<T> = {
      id,
      section: options.section,
      status: 'running',
      startedAt: now,
      updatedAt: now,
      progress: { completed: 0, total: 0 },
      partial: options.initial,
    };

    const record: JobRecord<T> = { snapshot, cancelled: false, promise: Promise.resolve() };
    this.jobs.set(id, record as JobRecord<unknown>);
    this.byKey.set(options.key, id);

    const context: JobContext<T> = {
      setTotal: (total) => {
        snapshot.progress.total = total;
        snapshot.updatedAt = new Date().toISOString();
      },
      advance: (partial, label) => {
        snapshot.progress.completed += 1;
        if (label) snapshot.progress.label = label;
        snapshot.partial = partial;
        snapshot.updatedAt = new Date().toISOString();
      },
      report: (partial, progress) => {
        snapshot.progress.completed = progress.completed;
        if (progress.total > 0) snapshot.progress.total = progress.total;
        if (progress.label) snapshot.progress.label = progress.label;
        snapshot.partial = partial;
        snapshot.updatedAt = new Date().toISOString();
      },
      update: (partial) => {
        snapshot.partial = partial;
        snapshot.updatedAt = new Date().toISOString();
      },
      get cancelled() {
        return record.cancelled;
      },
    };

    record.promise = options
      .run(context)
      .then((result) => {
        snapshot.partial = result;
        snapshot.status = 'complete';
        // A completed job reports full progress even if the work reported
        // fewer units than it declared, so the UI never sticks at 9/10.
        snapshot.progress.completed = Math.max(
          snapshot.progress.completed,
          snapshot.progress.total
        );
      })
      .catch((error: unknown) => {
        snapshot.status = 'failed';
        snapshot.error = (error as Error).message;
        logger.warn('Background job failed', {
          section: options.section,
          reason: (error as Error).message,
        });
      })
      .finally(() => {
        snapshot.finishedAt = new Date().toISOString();
        snapshot.updatedAt = snapshot.finishedAt;
        if (this.byKey.get(options.key) === id) this.byKey.delete(options.key);
        this.sweep();
      });

    return snapshot;
  }

  get<T>(id: string): JobSnapshot<T> | undefined {
    return this.jobs.get(id)?.snapshot as JobSnapshot<T> | undefined;
  }

  /** Waits for a job to settle. Used by tests and by blocking API callers. */
  async wait(id: string): Promise<void> {
    await this.jobs.get(id)?.promise;
  }

  cancel(id: string): boolean {
    const record = this.jobs.get(id);
    if (!record || record.snapshot.status !== 'running') return false;
    record.cancelled = true;
    return true;
  }

  /** Drops finished jobs once they are older than the retention window. */
  private sweep(now = Date.now()): void {
    for (const [id, record] of this.jobs) {
      if (record.snapshot.status === 'running') continue;
      const finished = Date.parse(record.snapshot.finishedAt ?? record.snapshot.updatedAt);
      if (Number.isFinite(finished) && now - finished > this.retentionMs) this.jobs.delete(id);
    }
  }

  get size(): number {
    return this.jobs.size;
  }

  clear(): void {
    for (const record of this.jobs.values()) record.cancelled = true;
    this.jobs.clear();
    this.byKey.clear();
  }
}
