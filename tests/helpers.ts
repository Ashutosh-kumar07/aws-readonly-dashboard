/** Shared test helpers: fake AWS clients and temp config directories. */

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { SdkClientLike } from '../src/aws/access-layer.js';

export interface FakeCall {
  command: string;
  input: unknown;
}

/** An SDK-shaped client whose responses are scripted per command name. */
export class FakeClient implements SdkClientLike {
  readonly calls: FakeCall[] = [];
  destroyed = false;

  constructor(private readonly responses: Record<string, unknown | (() => unknown)> = {}) {}

  async send(command: any): Promise<any> {
    const name = command?.constructor?.name ?? 'UnknownCommand';
    this.calls.push({ command: name, input: command?.input });
    const key = name.endsWith('Command') ? name.slice(0, -'Command'.length) : name;
    const response = this.responses[key];
    if (typeof response === 'function') return (response as () => unknown)();
    if (response instanceof Error) throw response;
    return response ?? {};
  }

  destroy(): void {
    this.destroyed = true;
  }
}

/** Builds a command-like object whose constructor name drives the guard. */
export function makeCommand(name: string, input: unknown = {}): unknown {
  class Command {
    constructor(readonly input: unknown) {}
  }
  Object.defineProperty(Command, 'name', { value: `${name}Command` });
  return new Command(input);
}

export function awsError(name: string, message = name, statusCode?: number): Error {
  const error = new Error(message);
  error.name = name;
  (error as any).$metadata = { httpStatusCode: statusCode };
  return error;
}

export async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'arod-test-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
