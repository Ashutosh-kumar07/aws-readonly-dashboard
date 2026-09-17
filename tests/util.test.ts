/** Concurrency, retry, deduplication, logging redaction and the data lifecycle. */

import { describe, expect, it } from 'vitest';

import {
  mapWithConcurrency,
  withRetry,
  withTimeout,
  RequestDeduplicator,
} from '../src/util/async.js';
import { Logger, redactSecrets } from '../src/util/logger.js';
import { AwsDataStore } from '../src/services/data-store.js';
import { selectionKey } from '../src/services/types.js';

describe('concurrency control', () => {
  it('never exceeds the configured limit', async () => {
    let active = 0;
    let peak = 0;
    await mapWithConcurrency(
      Array.from({ length: 30 }, (_, index) => index),
      4,
      async (value) => {
        active += 1;
        peak = Math.max(peak, active);
        await new Promise((resolve) => setTimeout(resolve, 1));
        active -= 1;
        return value;
      }
    );
    expect(peak).toBeLessThanOrEqual(4);
  });

  it('preserves input order in the results', async () => {
    const result = await mapWithConcurrency([3, 1, 2], 3, async (value) => {
      await new Promise((resolve) => setTimeout(resolve, value));
      return value * 10;
    });
    expect(result).toEqual([30, 10, 20]);
  });

  it('rejects a limit below one', async () => {
    await expect(mapWithConcurrency([1], 0, async (value) => value)).rejects.toThrow();
  });
});

describe('retry with backoff', () => {
  it('retries until the task succeeds', async () => {
    let attempts = 0;
    const result = await withRetry(
      async () => {
        attempts += 1;
        if (attempts < 3) throw new Error('transient');
        return 'ok';
      },
      { retries: 5, baseDelayMs: 1, maxDelayMs: 2, shouldRetry: () => true, sleep: async () => {} }
    );
    expect(result).toBe('ok');
    expect(attempts).toBe(3);
  });

  it('stops when the error is not retryable', async () => {
    let attempts = 0;
    await expect(
      withRetry(
        async () => {
          attempts += 1;
          throw new Error('permanent');
        },
        {
          retries: 5,
          baseDelayMs: 1,
          maxDelayMs: 2,
          shouldRetry: () => false,
          sleep: async () => {},
        }
      )
    ).rejects.toThrow('permanent');
    expect(attempts).toBe(1);
  });

  it('gives up after the retry budget', async () => {
    let attempts = 0;
    await expect(
      withRetry(
        async () => {
          attempts += 1;
          throw new Error('always');
        },
        {
          retries: 2,
          baseDelayMs: 1,
          maxDelayMs: 2,
          shouldRetry: () => true,
          sleep: async () => {},
        }
      )
    ).rejects.toThrow();
    expect(attempts).toBe(3);
  });

  it('backs off exponentially with jitter', async () => {
    const delays: number[] = [];
    await withRetry(
      async () => {
        if (delays.length < 3) throw new Error('again');
        return 'done';
      },
      {
        retries: 5,
        baseDelayMs: 100,
        maxDelayMs: 10_000,
        shouldRetry: () => true,
        random: () => 1,
        sleep: async (ms) => {
          delays.push(ms);
        },
      }
    );
    expect(delays).toEqual([100, 200, 400]);
  });
});

describe('request deduplication', () => {
  it('collapses concurrent identical work', async () => {
    const dedupe = new RequestDeduplicator();
    let runs = 0;
    const task = async () => {
      runs += 1;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return 'value';
    };
    const [a, b] = await Promise.all([dedupe.run('key', task), dedupe.run('key', task)]);
    expect(a).toBe('value');
    expect(b).toBe('value');
    expect(runs).toBe(1);
    expect(dedupe.size).toBe(0);
  });
});

describe('timeouts', () => {
  it('rejects when the promise is too slow', async () => {
    await expect(withTimeout(new Promise(() => {}), 5, 'too slow')).rejects.toThrow('too slow');
  });

  it('resolves a fast promise', async () => {
    await expect(withTimeout(Promise.resolve('quick'), 50)).resolves.toBe('quick');
  });
});

describe('log redaction', () => {
  it('never prints values under secret-looking keys', () => {
    const output = redactSecrets({
      password: 'hunter2',
      secretAccessKey: 'abc',
      nested: { token: 'xyz' },
    });
    expect(JSON.stringify(output)).not.toContain('hunter2');
    expect(JSON.stringify(output)).not.toContain('xyz');
  });

  it('redacts credential-shaped values wherever they appear', () => {
    const output = redactSecrets({ note: 'key AKIAIOSFODNN7EXAMPLE leaked' });
    expect(JSON.stringify(output)).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('honours the configured level', () => {
    const lines: string[] = [];
    const logger = new Logger('warn', (line) => lines.push(line));
    logger.debug('debug');
    logger.info('info');
    logger.warn('warn');
    logger.error('error');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('WARN');
  });

  it('prints nothing when silent', () => {
    const lines: string[] = [];
    const logger = new Logger('silent', (line) => lines.push(line));
    logger.error('nope');
    expect(lines).toHaveLength(0);
  });
});

describe('the in-memory AWS data lifecycle', () => {
  const selection = { profiles: ['dev'], regions: ['us-east-1'] };

  it('fetches once and then reuses what is in memory', async () => {
    const store = new AwsDataStore();
    let fetches = 0;
    const fetcher = async () => {
      fetches += 1;
      return { value: fetches };
    };

    const first = await store.resolve('billing', selection, fetcher);
    const second = await store.resolve('billing', selection, fetcher);

    expect(first.fromCache).toBe(false);
    expect(second.fromCache).toBe(true);
    expect(fetches).toBe(1);
  });

  it('refetches when a refresh is forced', async () => {
    const store = new AwsDataStore();
    let fetches = 0;
    const fetcher = async () => ({ value: (fetches += 1) });

    await store.resolve('billing', selection, fetcher);
    const refreshed = await store.resolve('billing', selection, fetcher, { force: true });

    expect(refreshed.fromCache).toBe(false);
    expect(fetches).toBe(2);
  });

  it('keys data by profile and region selection', async () => {
    const store = new AwsDataStore();
    const fetcher = async () => ({ ok: true });

    await store.resolve('billing', selection, fetcher);
    expect(store.has('billing', selection)).toBe(true);
    expect(store.has('billing', { profiles: ['prd'], regions: ['us-east-1'] })).toBe(false);
    expect(store.has('billing', { profiles: ['dev'], regions: ['eu-west-1'] })).toBe(false);
  });

  it('treats a different configuration variant as different data', async () => {
    const store = new AwsDataStore();
    let fetches = 0;
    const fetcher = async () => ({ value: (fetches += 1) });

    await store.resolve('billing', selection, fetcher, { variant: '7d' });
    await store.resolve('billing', selection, fetcher, { variant: '30d' });
    expect(fetches).toBe(2);
  });

  it('invalidates one section or everything', async () => {
    const store = new AwsDataStore();
    await store.resolve('billing', selection, async () => ({ a: 1 }));
    await store.resolve('security', selection, async () => ({ b: 2 }));

    store.invalidateSection('billing');
    expect(store.has('billing', selection)).toBe(false);
    expect(store.has('security', selection)).toBe(true);

    store.invalidateAll();
    expect(store.stats().size).toBe(0);
  });

  it('collapses concurrent fetches for the same selection', async () => {
    const store = new AwsDataStore();
    let fetches = 0;
    const fetcher = async () => {
      fetches += 1;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return { ok: true };
    };
    await Promise.all([
      store.resolve('billing', selection, fetcher),
      store.resolve('billing', selection, fetcher),
    ]);
    expect(fetches).toBe(1);
  });

  it('builds a stable, order-independent selection key', () => {
    expect(selectionKey('billing', { profiles: ['b', 'a'], regions: ['z', 'y'] })).toBe(
      selectionKey('billing', { profiles: ['a', 'b'], regions: ['y', 'z'] })
    );
  });
});
