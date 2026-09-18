/** Background jobs with partial results. */

import { describe, expect, it } from 'vitest';

import { JobRunner } from '../src/server/job-runner.js';
import { JobCancelledError } from '../src/util/errors.js';

const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 5));

describe('JobRunner', () => {
  it('returns a running snapshot immediately, before the work finishes', async () => {
    const runner = new JobRunner();
    let release = (): void => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const snapshot = runner.start<string[]>({
      section: 'security',
      key: 'a',
      initial: [],
      run: async () => {
        await gate;
        return ['done'];
      },
    });

    expect(snapshot.status).toBe('running');
    expect(snapshot.partial).toEqual([]);
    expect(snapshot.id).toBeTruthy();

    release();
    await runner.wait(snapshot.id);
    expect(runner.get(snapshot.id)?.status).toBe('complete');
    expect(runner.get<string[]>(snapshot.id)?.partial).toEqual(['done']);
  });

  it('publishes partial results as work advances, before it finishes', async () => {
    const runner = new JobRunner();
    // One gate per unit of work, so the test can observe the job mid-flight the
    // way the dashboard's polling does.
    const gates = [0, 1, 2].map(() => {
      let release = (): void => {};
      const promise = new Promise<void>((resolve) => {
        release = resolve;
      });
      return { promise, release };
    });

    const snapshot = runner.start<string[]>({
      section: 'security',
      key: 'b',
      initial: [],
      run: async (job) => {
        job.setTotal(3);
        const found: string[] = [];
        for (const [index, item] of ['one', 'two', 'three'].entries()) {
          await gates[index]!.promise;
          found.push(item);
          job.advance([...found], item);
        }
        return found;
      },
    });

    expect(runner.get<string[]>(snapshot.id)?.partial).toEqual([]);

    gates[0]!.release();
    await settle();
    expect(runner.get<string[]>(snapshot.id)?.partial).toEqual(['one']);
    expect(runner.get(snapshot.id)?.progress).toMatchObject({ completed: 1, total: 3 });
    expect(runner.get(snapshot.id)?.status).toBe('running');

    gates[1]!.release();
    await settle();
    expect(runner.get<string[]>(snapshot.id)?.partial).toEqual(['one', 'two']);
    expect(runner.get(snapshot.id)?.progress.label).toBe('two');

    gates[2]!.release();
    await runner.wait(snapshot.id);
    expect(runner.get(snapshot.id)?.status).toBe('complete');
    expect(runner.get(snapshot.id)?.progress).toMatchObject({ completed: 3, total: 3 });
  });

  it('adopts an absolute progress position without double counting', async () => {
    const runner = new JobRunner();
    const snapshot = runner.start<number>({
      section: 'security',
      key: 'c',
      initial: 0,
      run: async (job) => {
        job.setTotal(2);
        // The work counts its own units; the job must not add its own increments.
        job.report(10, { completed: 12, total: 22, label: 'check A' });
        job.report(20, { completed: 19, total: 22, label: 'check B' });
        return 20;
      },
    });

    await runner.wait(snapshot.id);
    const done = runner.get<number>(snapshot.id)!;
    expect(done.progress.total).toBe(22);
    expect(done.progress.completed).toBe(22); // completion fills the bar
    expect(done.partial).toBe(20);
  });

  it('records a failure without throwing to the caller', async () => {
    const runner = new JobRunner();
    const snapshot = runner.start<string | null>({
      section: 'billing',
      key: 'd',
      initial: null,
      run: async () => {
        throw new Error('Cost Explorer is not enabled');
      },
    });

    await runner.wait(snapshot.id);
    const failed = runner.get(snapshot.id)!;
    expect(failed.status).toBe('failed');
    expect(failed.error).toContain('Cost Explorer');
    expect(failed.finishedAt).toBeTruthy();
  });

  it('reuses a running job for the same key rather than scanning twice', async () => {
    const runner = new JobRunner();
    let runs = 0;
    let release = (): void => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const start = (): ReturnType<typeof runner.start<number>> =>
      runner.start<number>({
        section: 'security',
        key: 'same',
        initial: 0,
        run: async () => {
          runs += 1;
          await gate;
          return runs;
        },
      });

    const first = start();
    const second = start();
    expect(second.id).toBe(first.id);
    expect(runs).toBe(1);

    release();
    await runner.wait(first.id);
  });

  it('starts a fresh job for the same key once the previous one finished', async () => {
    const runner = new JobRunner();
    const first = runner.start<number>({
      section: 'security',
      key: 'k',
      initial: 0,
      run: async () => 1,
    });
    await runner.wait(first.id);
    await settle();
    const second = runner.start<number>({
      section: 'security',
      key: 'k',
      initial: 0,
      run: async () => 2,
    });
    expect(second.id).not.toBe(first.id);
  });

  it('exposes cancellation to the work function', async () => {
    const runner = new JobRunner();
    let observed: boolean | undefined;
    let release = (): void => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const snapshot = runner.start<boolean>({
      section: 'security',
      key: 'cancel',
      initial: false,
      run: async (job) => {
        await gate;
        observed = job.cancelled;
        return true;
      },
    });

    expect(runner.cancel(snapshot.id)).toBe(true);
    release();
    await runner.wait(snapshot.id);
    expect(observed).toBe(true);
  });

  it('keeps a finished job readable for the retention window', async () => {
    const runner = new JobRunner(60_000);
    const job = runner.start<number>({
      section: 'billing',
      key: 'r',
      initial: 0,
      run: async () => 1,
    });
    await runner.wait(job.id);
    await settle();
    expect(runner.get(job.id)?.status).toBe('complete');
  });

  it('discards a finished job once the retention window has passed', async () => {
    const runner = new JobRunner(0);
    const first = runner.start<number>({
      section: 'billing',
      key: 'r1',
      initial: 0,
      run: async () => 1,
    });
    await runner.wait(first.id);
    // Let the clock move past the (zero) retention window; the sweep runs when
    // the next job settles.
    await new Promise((resolve) => setTimeout(resolve, 20));
    const second = runner.start<number>({
      section: 'billing',
      key: 'r2',
      initial: 0,
      run: async () => 2,
    });
    await runner.wait(second.id);
    await settle();
    expect(runner.get(first.id)).toBeUndefined();
    expect(runner.get(second.id)).toBeDefined();
  });
  it('ends a cancelled job as cancelled, keeping the partial result out of `complete`', async () => {
    const runner = new JobRunner();
    let release = (): void => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const unitsRun: string[] = [];

    const snapshot = runner.start<string[]>({
      section: 'security',
      key: 'cancel-me',
      initial: [],
      run: async (job) => {
        for (const unit of ['one', 'two', 'three']) {
          // Work checks at each unit boundary, exactly as the scans do.
          if (job.cancelled) throw new JobCancelledError();
          unitsRun.push(unit);
          job.advance([...unitsRun], unit);
          await gate;
        }
        return [...unitsRun];
      },
    });

    await settle();
    expect(runner.cancel(snapshot.id)).toBe(true);
    release();
    await runner.wait(snapshot.id);

    const finished = runner.get<string[]>(snapshot.id);
    expect(finished?.status).toBe('cancelled');
    // The work stopped rather than running to the end.
    expect(unitsRun).toEqual(['one']);
    // And the partial it had is never promoted to a complete result.
    expect(finished?.partial).toEqual(['one']);
  });

  it('refuses to cancel a job that has already finished', async () => {
    const runner = new JobRunner();
    const snapshot = runner.start<string>({
      section: 'billing',
      key: 'done',
      initial: '',
      run: async () => 'finished',
    });
    await runner.wait(snapshot.id);
    expect(runner.cancel(snapshot.id)).toBe(false);
    expect(runner.get(snapshot.id)?.status).toBe('complete');
  });
});
