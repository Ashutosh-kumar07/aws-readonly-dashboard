/**
 * Gemini CLI provider.
 *
 * The dashboard reuses the user's existing Gemini CLI authentication by
 * invoking the CLI in a child process. It never stores Gemini credentials, never
 * installs the CLI, and never calls it unless the user explicitly asked for an
 * analysis.
 */

import { spawn } from 'node:child_process';

import { logger } from '../../util/logger.js';
import type { GeminiConfig } from '../../config/schema.js';
import {
  AiProviderError,
  type AiProvider,
  type AiProviderRequest,
  type AiProviderResponse,
  type AiProviderStatus,
} from './types.js';

export interface SpawnResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export type Spawner = (
  command: string,
  args: string[],
  options: { input?: string; timeoutMs: number }
) => Promise<SpawnResult>;

/** Default spawner: writes the prompt on stdin so it never appears in argv. */
export const defaultSpawner: Spawner = (command, args, options) =>
  new Promise<SpawnResult>((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      // Prompt content is passed via stdin; the environment is inherited so the
      // user's existing Gemini CLI authentication applies.
      env: process.env,
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, options.timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut });
    });

    if (options.input !== undefined) {
      child.stdin.end(options.input);
    } else {
      child.stdin.end();
    }
  });

export class GeminiCliProvider implements AiProvider {
  readonly id = 'gemini' as const;
  readonly name = 'Gemini CLI';
  private cachedStatus: AiProviderStatus | undefined;

  constructor(
    private config: GeminiConfig,
    private readonly spawner: Spawner = defaultSpawner
  ) {}

  setConfig(config: GeminiConfig): void {
    this.config = config;
    this.cachedStatus = undefined;
  }

  /** Probes for the CLI. Runs at startup and when configuration changes. */
  async status(force = false): Promise<AiProviderStatus> {
    if (this.cachedStatus && !force) return this.cachedStatus;

    const base: AiProviderStatus = {
      id: this.id,
      name: this.name,
      available: false,
      configured: true,
      enabled: true,
      label: 'Non-LLM mode',
      detail: 'Gemini CLI was not found on PATH.',
    };

    try {
      const result = await this.spawner(this.config.command, ['--version'], { timeoutMs: 10_000 });
      if (result.code === 0) {
        const version = result.stdout.trim().split('\n')[0]?.trim();
        this.cachedStatus = {
          ...base,
          available: true,
          label: 'Gemini CLI: Available',
          ...(version
            ? { version, detail: `Detected ${version}` }
            : { detail: 'Detected on PATH' }),
        };
        return this.cachedStatus;
      }
      this.cachedStatus = {
        ...base,
        detail: `"${this.config.command} --version" exited with code ${result.code ?? 'unknown'}.`,
      };
    } catch (error) {
      logger.debug('Gemini CLI probe failed', { reason: (error as Error).message });
      this.cachedStatus = {
        ...base,
        detail: `Gemini CLI could not be started: ${(error as Error).message}`,
      };
    }
    return this.cachedStatus;
  }

  async generate(request: AiProviderRequest): Promise<AiProviderResponse> {
    const status = await this.status();
    if (!status.available) {
      throw new AiProviderError(
        'Gemini CLI is not available. The dashboard is in non-LLM mode; install and authenticate the Gemini CLI, or configure a custom LLM endpoint in Settings.',
        this.name,
        'unavailable'
      );
    }

    const args = [...this.config.args];
    if (this.config.model) args.push('--model', this.config.model);

    const startedAt = Date.now();
    let result: SpawnResult;
    try {
      result = await this.spawner(this.config.command, args, {
        input: request.prompt,
        timeoutMs: request.timeoutMs,
      });
    } catch (error) {
      throw new AiProviderError(
        `Gemini CLI could not be started: ${(error as Error).message}`,
        this.name,
        'transport'
      );
    }

    if (result.timedOut) {
      throw new AiProviderError(
        `Gemini CLI did not respond within ${Math.round(request.timeoutMs / 1000)}s.`,
        this.name,
        'timeout'
      );
    }
    if (result.code !== 0) {
      throw new AiProviderError(
        `Gemini CLI exited with code ${result.code ?? 'unknown'}: ${result.stderr.trim().slice(0, 500)}`,
        this.name,
        'transport'
      );
    }
    if (!result.stdout.trim()) {
      throw new AiProviderError('Gemini CLI returned an empty response.', this.name, 'response');
    }

    return {
      text: result.stdout,
      provider: this.name,
      ...(this.config.model ? { model: this.config.model } : {}),
      durationMs: Date.now() - startedAt,
    };
  }
}
