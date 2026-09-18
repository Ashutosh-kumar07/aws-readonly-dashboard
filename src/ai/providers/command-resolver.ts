/**
 * Locating and safely spawning a CLI executable across platforms.
 *
 * The hard case is Windows. `npm install -g @google/gemini-cli` installs a
 * `gemini.cmd` batch shim, and Node cannot execute `.cmd` or `.bat` files
 * through `child_process.spawn` unless `shell` is set — since the fix for
 * CVE-2024-27980 it refuses outright. A CLI that works perfectly in the user's
 * terminal therefore fails with ENOENT when the dashboard spawns it, which is
 * exactly the "installed but reported as missing" symptom this module exists to
 * prevent.
 */

import { spawn } from 'node:child_process';
import { delimiter, isAbsolute, join } from 'node:path';
import { access, constants } from 'node:fs/promises';

/**
 * Characters that would change the meaning of a command once it is handed to a
 * shell. A configured command containing any of them is refused rather than
 * quoted, because there is no legitimate reason for an executable name to
 * contain them.
 */
const SHELL_METACHARACTERS = /[&|;<>()$`\n\r"'^*?[\]{}!~]/;

export interface ResolvedCommand {
  /** The command to hand to `spawn`. */
  command: string;
  /** Whether the command must be run through a shell (Windows shims). */
  useShell: boolean;
  /** Absolute path when the executable could be located, for diagnostics. */
  resolvedPath?: string;
  /** How the command was found, shown in the UI to make failures debuggable. */
  source: 'absolute-path' | 'path-lookup' | 'bare-command';
}

export class UnsafeCommandError extends Error {
  override readonly name = 'UnsafeCommandError';
}

/** Windows executable extensions that require a shell to launch. */
const SHELL_REQUIRED_EXTENSIONS = ['.cmd', '.bat'];

/** Extensions Windows will try when a bare command name is given. */
function windowsCandidates(command: string): string[] {
  const extensions = (process.env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD')
    .split(';')
    .map((extension) => extension.trim().toLowerCase())
    .filter(Boolean);
  // npm shims are .cmd, so try those first: they are the common case.
  const ordered = ['.cmd', '.exe', ...extensions.filter((e) => e !== '.cmd' && e !== '.exe')];
  return [...new Set(ordered)].map((extension) => `${command}${extension}`);
}

async function isExecutable(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

export interface ResolveOptions {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
}

/**
 * Finds an executable without invoking a shell, by walking PATH the way the
 * operating system would.
 */
export async function resolveCommand(
  command: string,
  options: ResolveOptions = {}
): Promise<ResolvedCommand> {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const isWindows = platform === 'win32';

  if (SHELL_METACHARACTERS.test(command)) {
    throw new UnsafeCommandError(
      `The configured Gemini CLI command contains characters that are not valid in an executable name: ${command}. ` +
        'Set it to a plain command name such as "gemini", or to the full path of the executable.'
    );
  }

  const needsShell = (path: string): boolean =>
    isWindows &&
    SHELL_REQUIRED_EXTENSIONS.some((extension) => path.toLowerCase().endsWith(extension));

  if (isAbsolute(command) || command.includes('/') || (isWindows && command.includes('\\'))) {
    return {
      command,
      useShell: needsShell(command),
      ...((await isExecutable(command)) ? { resolvedPath: command } : {}),
      source: 'absolute-path',
    };
  }

  const searchPath = (env.PATH ?? env.Path ?? '').split(delimiter).filter(Boolean);
  const names = isWindows ? windowsCandidates(command) : [command];

  for (const directory of searchPath) {
    for (const name of names) {
      const candidate = join(directory, name);
      if (await isExecutable(candidate)) {
        return {
          command: candidate,
          useShell: needsShell(candidate),
          resolvedPath: candidate,
          source: 'path-lookup',
        };
      }
    }
  }

  // Not found on PATH. On Windows, still go through a shell: the shim may be
  // reachable via a PATH entry this process cannot read, and cmd.exe resolves
  // .cmd files that spawn cannot.
  return { command, useShell: isWindows, source: 'bare-command' };
}

export interface SpawnOutcome {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** Set when the process could not be started at all. */
  spawnError?: NodeJS.ErrnoException;
}

export interface RunOptions {
  args: string[];
  input?: string;
  timeoutMs: number;
  useShell: boolean;
  env?: NodeJS.ProcessEnv;
}

/**
 * Runs a command, capturing output. A failure to start is returned as
 * `spawnError` rather than thrown, so callers can tell "not installed" apart
 * from "ran and failed".
 */
export function runCommand(command: string, options: RunOptions): Promise<SpawnOutcome> {
  return new Promise<SpawnOutcome>((resolve) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;

    const child = spawn(command, options.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      // The environment is inherited so the CLI's existing authentication applies.
      env: options.env ?? process.env,
      // Windows shims (.cmd) can only be launched through a shell. The command
      // and arguments are validated by resolveCommand before reaching here.
      shell: options.useShell,
      windowsHide: true,
    });

    const finish = (outcome: SpawnOutcome): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(outcome);
    };

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, options.timeoutMs);

    child.stdout?.on('data', (chunk) => {
      stdout += String(chunk);
    });
    child.stderr?.on('data', (chunk) => {
      stderr += String(chunk);
    });

    child.on('error', (error) => {
      finish({ code: null, stdout, stderr, timedOut, spawnError: error as NodeJS.ErrnoException });
    });

    child.on('close', (code) => {
      finish({ code, stdout, stderr, timedOut });
    });

    // Writing to a process that failed to start raises EPIPE; it is not useful.
    child.stdin?.on('error', () => {});
    if (options.input !== undefined) child.stdin?.end(options.input);
    else child.stdin?.end();
  });
}
