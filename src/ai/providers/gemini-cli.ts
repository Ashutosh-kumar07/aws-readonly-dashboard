/**
 * Gemini CLI provider.
 *
 * The dashboard reuses the user's existing Gemini CLI authentication by
 * invoking the CLI in a child process. It never stores Gemini credentials, never
 * installs the CLI, and never calls it unless the user explicitly asked for an
 * analysis.
 *
 * Detection reports three distinct states, because "we could not run it" and
 * "you are not signed in" need different actions from the user:
 *
 *   available       — the CLI ran and reported its version
 *   unauthenticated — the CLI is installed but has no auth method configured
 *   not-found       — the CLI could not be located or started
 */

import { logger } from '../../util/logger.js';
import type { GeminiConfig } from '../../config/schema.js';
import {
  AiProviderError,
  type AiProvider,
  type AiProviderRequest,
  type AiProviderResponse,
  type AiProviderStatus,
} from './types.js';
import {
  resolveCommand,
  runCommand,
  UnsafeCommandError,
  type ResolvedCommand,
  type SpawnOutcome,
} from './command-resolver.js';

export interface SpawnResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  spawnError?: NodeJS.ErrnoException;
}

export type Spawner = (
  command: string,
  args: string[],
  options: { input?: string; timeoutMs: number }
) => Promise<SpawnResult>;

/**
 * The CLI exits non-zero with this on stderr when no auth method is configured.
 * Recognising it turns a confusing "the response was not JSON" error into a
 * precise instruction.
 */
const AUTH_ERROR_PATTERN =
  /set an auth method|GEMINI_API_KEY|not authenticated|please (log|sign) ?in/i;

/**
 * Instruction passed with `-p`. The CLI documents `-p` as "appended to input on
 * stdin (if any)" and as the explicit trigger for headless mode, so the bulk of
 * the prompt travels on stdin — which also avoids the 8191-character command
 * line limit on Windows — while this short flag guarantees non-interactive use.
 */
const HEADLESS_INSTRUCTION = 'Follow the instructions above and reply with the JSON object only.';

export class GeminiCliProvider implements AiProvider {
  readonly id = 'gemini' as const;
  readonly name = 'Gemini CLI';
  private cachedStatus: AiProviderStatus | undefined;
  private resolved: ResolvedCommand | undefined;

  constructor(
    private config: GeminiConfig,
    /** Injectable for tests; production uses the resolver-backed path. */
    private readonly spawner?: Spawner
  ) {}

  setConfig(config: GeminiConfig): void {
    this.config = config;
    this.cachedStatus = undefined;
    this.resolved = undefined;
  }

  /** Locates the executable once, then reuses the result. */
  private async resolve(): Promise<ResolvedCommand> {
    if (!this.resolved) this.resolved = await resolveCommand(this.config.command);
    return this.resolved;
  }

  private async run(
    args: string[],
    options: { input?: string; timeoutMs: number }
  ): Promise<SpawnOutcome> {
    if (this.spawner) {
      return this.spawner(this.config.command, args, options);
    }
    const resolved = await this.resolve();
    return runCommand(resolved.command, {
      args,
      ...(options.input !== undefined ? { input: options.input } : {}),
      timeoutMs: options.timeoutMs,
      useShell: resolved.useShell,
    });
  }

  /**
   * Probes for the CLI. This is a capability check, not an AI call: no prompt
   * and no data leave the machine.
   */
  async status(force = false): Promise<AiProviderStatus> {
    if (this.cachedStatus && !force) return this.cachedStatus;
    if (force) this.resolved = undefined;

    const base: AiProviderStatus = {
      id: this.id,
      name: this.name,
      available: false,
      configured: true,
      enabled: true,
      label: 'Non-LLM mode',
    };

    let resolved: ResolvedCommand | undefined;
    try {
      // The injected spawner path (tests) has no resolution step.
      if (!this.spawner) resolved = await this.resolve();
    } catch (error) {
      if (error instanceof UnsafeCommandError) {
        this.cachedStatus = { ...base, detail: error.message };
        return this.cachedStatus;
      }
      throw error;
    }

    const where = resolved?.resolvedPath ? ` (${resolved.resolvedPath})` : '';

    try {
      const result = await this.run(['--version'], { timeoutMs: this.config.probeTimeoutMs });

      if (result.spawnError) {
        this.cachedStatus = {
          ...base,
          detail: this.describeSpawnFailure(result.spawnError, resolved),
        };
        return this.cachedStatus;
      }

      if (result.timedOut) {
        this.cachedStatus = {
          ...base,
          detail:
            `"${this.config.command} --version" did not respond within ` +
            `${Math.round(this.config.probeTimeoutMs / 1000)}s. Increase the probe timeout in Settings if the CLI is slow to start.`,
        };
        return this.cachedStatus;
      }

      if (result.code === 0) {
        const version = result.stdout.trim().split('\n')[0]?.trim();
        this.cachedStatus = {
          ...base,
          available: true,
          label: 'Gemini CLI: Available',
          ...(version ? { version } : {}),
          detail: version ? `Detected ${version}${where}` : `Detected on PATH${where}`,
        };
        return this.cachedStatus;
      }

      // It ran but refused. An auth failure is the common, fixable case.
      const output = `${result.stderr}\n${result.stdout}`;
      if (AUTH_ERROR_PATTERN.test(output)) {
        this.cachedStatus = {
          ...base,
          label: 'Gemini CLI: Not authenticated',
          detail:
            'The Gemini CLI is installed but has no authentication configured. ' +
            'Run "gemini" once in a terminal and complete sign-in, then re-check providers.',
        };
        return this.cachedStatus;
      }

      this.cachedStatus = {
        ...base,
        detail:
          `"${this.config.command} --version"${where} exited with code ${result.code ?? 'unknown'}` +
          `${result.stderr.trim() ? `: ${result.stderr.trim().slice(0, 300)}` : '.'}`,
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

  /** Turns a spawn errno into something the user can act on. */
  private describeSpawnFailure(
    error: NodeJS.ErrnoException,
    resolved: ResolvedCommand | undefined
  ): string {
    const command = this.config.command;
    if (error.code === 'ENOENT') {
      return (
        `"${command}" was not found. Install it with "npm install -g @google/gemini-cli", ` +
        'or set the full path to the executable in Settings → Gemini CLI → Command. ' +
        (process.platform === 'win32'
          ? 'On Windows the executable is usually %APPDATA%\\npm\\gemini.cmd.'
          : 'If it works in your terminal but not here, the dashboard was started with a different PATH.')
      );
    }
    if (error.code === 'EACCES') {
      return `"${resolved?.resolvedPath ?? command}" is not executable by this user.`;
    }
    return `Gemini CLI could not be started: ${error.message}`;
  }

  async generate(request: AiProviderRequest): Promise<AiProviderResponse> {
    const status = await this.status();
    if (!status.available) {
      throw new AiProviderError(
        status.detail
          ? `${status.label}. ${status.detail}`
          : 'Gemini CLI is not available. Install and authenticate it, or configure a custom LLM endpoint in Settings.',
        this.name,
        'unavailable'
      );
    }

    const args = [...this.config.args];
    if (this.config.model) args.push('--model', this.config.model);
    // `-p` guarantees headless mode instead of relying on TTY detection; the
    // payload itself stays on stdin.
    args.push('-p', HEADLESS_INSTRUCTION);

    const startedAt = Date.now();
    let result: SpawnOutcome;
    try {
      result = await this.run(args, { input: request.prompt, timeoutMs: request.timeoutMs });
    } catch (error) {
      throw new AiProviderError(
        `Gemini CLI could not be started: ${(error as Error).message}`,
        this.name,
        'transport'
      );
    }

    if (result.spawnError) {
      throw new AiProviderError(
        this.describeSpawnFailure(result.spawnError, this.resolved),
        this.name,
        'unavailable'
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
      const output = `${result.stderr}\n${result.stdout}`;
      if (AUTH_ERROR_PATTERN.test(output)) {
        throw new AiProviderError(
          'The Gemini CLI is not authenticated. Run "gemini" once in a terminal and complete sign-in, then try again.',
          this.name,
          'configuration'
        );
      }
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
