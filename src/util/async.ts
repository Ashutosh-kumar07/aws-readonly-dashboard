/** Small async helpers: concurrency limiting, retry with backoff, deduplication. */

export type Task<T> = () => Promise<T>;

/** Runs tasks with a bounded number of simultaneous executions. */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  if (limit < 1) throw new Error('concurrency limit must be >= 1');
  const results = new Array<R>(items.length);
  let cursor = 0;

  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await worker(items[index] as T, index);
    }
  });

  await Promise.all(runners);
  return results;
}

export interface RetryOptions {
  retries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  /** Return true when the error is worth retrying. */
  shouldRetry: (error: unknown, attempt: number) => boolean;
  /** Injectable for tests. */
  sleep?: (ms: number) => Promise<void>;
  /** Injectable for tests; defaults to Math.random. */
  random?: () => number;
}

export const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/** Retries a task using full-jitter exponential backoff. */
export async function withRetry<T>(task: Task<T>, options: RetryOptions): Promise<T> {
  const sleep = options.sleep ?? defaultSleep;
  const random = options.random ?? Math.random;
  let attempt = 0;

  for (;;) {
    try {
      return await task();
    } catch (error) {
      if (attempt >= options.retries || !options.shouldRetry(error, attempt)) throw error;
      const exponential = Math.min(options.maxDelayMs, options.baseDelayMs * 2 ** attempt);
      await sleep(Math.round(exponential * (0.5 + random() * 0.5)));
      attempt += 1;
    }
  }
}

/** Collapses concurrent identical work into a single in-flight promise. */
export class RequestDeduplicator {
  private readonly inFlight = new Map<string, Promise<unknown>>();

  run<T>(key: string, task: Task<T>): Promise<T> {
    const existing = this.inFlight.get(key);
    if (existing) return existing as Promise<T>;
    const promise = task().finally(() => {
      this.inFlight.delete(key);
    });
    this.inFlight.set(key, promise);
    return promise;
  }

  get size(): number {
    return this.inFlight.size;
  }
}

/** The shared shape of a deadline failure, so classification stays consistent. */
export function timeoutError(message: string): Error {
  const error = new Error(message);
  error.name = 'TimeoutError';
  return error;
}

/** Rejects if the promise has not settled within `ms`. */
export async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  message = 'Operation timed out'
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(timeoutError(message)), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
