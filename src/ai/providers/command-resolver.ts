/**
 * Locating and safely spawning a CLI executable across platforms.
 *
 * The hard case is Windows. `npm install -g @google/gemini-cli` installs a
 * `gemini.cmd` batch shim, and Node cannot execute `.cmd` or `.bat` files
 * through `child_process.spawn` unless a shell is involved — since the fix for
 * CVE-2024-27980 it refuses outright. A CLI that works perfectly in the user's
 * terminal therefore fails with ENOENT when the dashboard spawns it, which is
 * exactly the "installed but reported as missing" symptom this module exists to
 * prevent.
 *
 * The trap on the other side is `shell: true`, which does not quote anything:
 * Node joins the arguments with spaces and hands the result to the shell, so
 * `['-p', 'two words']` arrives as `-p two words` — a flag plus two positional
 * arguments. This module therefore builds the `cmd.exe` command line itself and
 * quotes every argument, so an argument is still one argument on the other side.
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
  /** Whether the command must be launched through cmd.exe (Windows shims). */
  useShell: boolean;
  /** Absolute path when the executable could be located, for diagnostics. */
  resolvedPath?: string;
  /** How the command was found, shown in the UI to make failures debuggable. */
  source: 'absolute-path' | 'path-lookup' | 'bare-command';
}

export class UnsafeCommandError extends Error {
  override readonly name = 'UnsafeCommandError';
}

/** Windows executable extensions that cannot be spawned directly. */
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

  // Not found on PATH. On Windows, still go through cmd.exe: the shim may be
  // reachable via a PATH entry this process cannot read, and cmd.exe resolves
  // .cmd files that spawn cannot.
  return { command, useShell: isWindows, source: 'bare-command' };
}

/**
 * Characters that cmd.exe would act on even inside a quoted argument: `%` and
 * `!` are expanded as variables, and a newline ends the command. There is no
 * escape that survives every configuration, so an argument containing one is
 * refused rather than silently mangled.
 */
const CMD_UNQUOTABLE = /[%!\r\n]/;

/**
 * Quotes one argument the way the Windows C runtime parses it back: wrap in
 * double quotes, double any backslashes that precede a quote, and escape the
 * quotes themselves.
 */
export function quoteWindowsArgument(argument: string): string {
  if (argument === '') return '""';
  if (!/[\s"]/.test(argument)) return argument;

  let quoted = '"';
  let backslashes = 0;
  for (const character of argument) {
    if (character === '\\') {
      backslashes += 1;
      continue;
    }
    if (character === '"') {
      quoted += '\\'.repeat(backslashes * 2 + 1) + '"';
      backslashes = 0;
      continue;
    }
    quoted += '\\'.repeat(backslashes) + character;
    backslashes = 0;
  }
  return `${quoted}${'\\'.repeat(backslashes * 2)}"`;
}

export interface SpawnPlan {
  /** The executable to spawn. */
  file: string;
  /** Arguments exactly as `spawn` should receive them. */
  args: string[];
  /** True when `args` is a pre-built command line that Node must not re-quote. */
  windowsVerbatimArguments: boolean;
}

/**
 * Decides how to invoke a resolved command.
 *
 * Everywhere but a Windows shim this is a direct, shell-free spawn. For a
 * `.cmd` or `.bat` the invocation goes through `cmd.exe /d /s /c` with a
 * command line this function builds and quotes, which is what `shell: true`
 * fails to do.
 */
export function buildInvocation(
  command: string,
  args: readonly string[],
  options: { useShell: boolean; comSpec?: string }
): SpawnPlan {
  if (!options.useShell) {
    return { file: command, args: [...args], windowsVerbatimArguments: false };
  }

  for (const argument of [command, ...args]) {
    if (CMD_UNQUOTABLE.test(argument)) {
      throw new UnsafeCommandError(
        'An argument for the Gemini CLI contains a character Windows command ' +
          `processing would reinterpret (% ! or a line break): ${argument.slice(0, 80)}. ` +
          'Remove it from the command or arguments in Settings.'
      );
    }
  }

  // `/d` skips AutoRun scripts, `/s` gives the documented "strip the outer
  // quotes and run the rest verbatim" parsing, `/c` runs and exits.
  const commandLine = [command, ...args].map(quoteWindowsArgument).join(' ');
  return {
    file: options.comSpec ?? process.env.ComSpec ?? 'cmd.exe',
    args: ['/d', '/s', '/c', `"${commandLine}"`],
    windowsVerbatimArguments: true,
  };
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

    const plan = buildInvocation(command, options.args, { useShell: options.useShell });

    const child = spawn(plan.file, plan.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      // The environment is inherited so the CLI's existing authentication applies.
      env: options.env ?? process.env,
      // Never `shell: true`: it would join the arguments with spaces and lose
      // the quoting. A Windows shim goes through the cmd.exe line built above.
      windowsVerbatimArguments: plan.windowsVerbatimArguments,
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
