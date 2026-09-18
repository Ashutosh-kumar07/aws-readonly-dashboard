/**
 * Cross-platform Gemini CLI detection.
 *
 * The bug these tests exist for: on Windows `npm i -g @google/gemini-cli`
 * installs `gemini.cmd`, and Node cannot spawn a `.cmd` without a shell, so a
 * CLI that works in the user's terminal was reported as "Non-LLM mode".
 */

import { describe, expect, it } from 'vitest';
import { mkdir, writeFile, chmod } from 'node:fs/promises';
import { join } from 'node:path';

import { resolveCommand, UnsafeCommandError } from '../src/ai/providers/command-resolver.js';
import { GeminiCliProvider, type Spawner } from '../src/ai/providers/gemini-cli.js';
import { defaultConfig } from '../src/config/schema.js';
import { withTempDir } from './helpers.js';

function geminiConfig(command: string): ReturnType<typeof defaultConfig>['ai']['gemini'] {
  return { ...defaultConfig().ai.gemini, command };
}

/** A spawner scripted per invocation, mirroring the real result shape. */
function scripted(results: {
  version?: {
    code?: number;
    stdout?: string;
    stderr?: string;
    timedOut?: boolean;
    spawnError?: NodeJS.ErrnoException;
  };
}): Spawner {
  return async (_command, args) => {
    const isVersion = args.includes('--version');
    const result = isVersion ? results.version : undefined;
    return {
      code: result?.code ?? 0,
      stdout: result?.stdout ?? '',
      stderr: result?.stderr ?? '',
      timedOut: result?.timedOut ?? false,
      ...(result?.spawnError ? { spawnError: result.spawnError } : {}),
    };
  };
}

describe('command resolution', () => {
  it('requires a shell for a Windows .cmd shim', async () => {
    const resolved = await resolveCommand('C:\\Users\\a\\AppData\\Roaming\\npm\\gemini.cmd', {
      platform: 'win32',
    });
    // This is the fix: without a shell, Node refuses to run a .cmd at all.
    expect(resolved.useShell).toBe(true);
  });

  it('requires a shell for a bare command on Windows', async () => {
    const resolved = await resolveCommand('gemini', {
      platform: 'win32',
      env: { PATH: 'C:\\nowhere', PATHEXT: '.COM;.EXE;.BAT;.CMD' },
    });
    expect(resolved.useShell).toBe(true);
  });

  it('does not use a shell on POSIX platforms', async () => {
    const resolved = await resolveCommand('gemini', {
      platform: 'linux',
      env: { PATH: '/nowhere' },
    });
    expect(resolved.useShell).toBe(false);
    expect(resolved.source).toBe('bare-command');
  });

  it('finds an executable on PATH and reports where it came from', async () => {
    await withTempDir(async (dir) => {
      const bin = join(dir, 'bin');
      await mkdir(bin, { recursive: true });
      const target = join(bin, 'gemini');
      await writeFile(target, '#!/bin/sh\necho 1.2.3\n');
      await chmod(target, 0o755);

      const resolved = await resolveCommand('gemini', { platform: 'linux', env: { PATH: bin } });
      expect(resolved.resolvedPath).toBe(target);
      expect(resolved.source).toBe('path-lookup');
      expect(resolved.useShell).toBe(false);
    });
  });

  it('prefers the .cmd shim when resolving on Windows', async () => {
    await withTempDir(async (dir) => {
      await writeFile(join(dir, 'gemini.cmd'), '@echo off\r\necho 1.2.3\r\n');
      const resolved = await resolveCommand('gemini', {
        platform: 'win32',
        env: { PATH: dir, PATHEXT: '.COM;.EXE;.BAT;.CMD' },
      });
      expect(resolved.resolvedPath).toBe(join(dir, 'gemini.cmd'));
      expect(resolved.useShell).toBe(true);
    });
  });

  it('treats an absolute path as given', async () => {
    const resolved = await resolveCommand('/usr/local/bin/gemini', { platform: 'linux' });
    expect(resolved.source).toBe('absolute-path');
    expect(resolved.command).toBe('/usr/local/bin/gemini');
  });

  it('refuses a command containing shell metacharacters', async () => {
    // A shell is used on Windows, so the command must never be able to carry
    // one of these through from configuration.
    for (const command of [
      'gemini && rm -rf /',
      'gemini; whoami',
      'gemini | tee x',
      'gemini $(id)',
    ]) {
      await expect(resolveCommand(command)).rejects.toThrow(UnsafeCommandError);
    }
  });
});

describe('Gemini CLI status', () => {
  it('reports the version when the CLI answers', async () => {
    const provider = new GeminiCliProvider(
      geminiConfig('gemini'),
      scripted({ version: { code: 0, stdout: '0.60.0\n' } })
    );
    const status = await provider.status(true);
    expect(status.available).toBe(true);
    expect(status.label).toBe('Gemini CLI: Available');
    expect(status.version).toBe('0.60.0');
  });

  it('distinguishes "installed but not authenticated" from "missing"', async () => {
    const provider = new GeminiCliProvider(
      geminiConfig('gemini'),
      scripted({
        version: {
          code: 41,
          stderr:
            'Please set an Auth method in your /root/.gemini/settings.json or specify one of the following environment variables before running: GEMINI_API_KEY',
        },
      })
    );
    const status = await provider.status(true);
    expect(status.available).toBe(false);
    expect(status.label).toBe('Gemini CLI: Not authenticated');
    expect(status.detail).toMatch(/complete sign-in/i);
  });

  it('gives actionable advice when the binary cannot be found', async () => {
    const enoent: NodeJS.ErrnoException = Object.assign(new Error('spawn gemini ENOENT'), {
      code: 'ENOENT',
    });
    const provider = new GeminiCliProvider(
      geminiConfig('gemini'),
      scripted({ version: { spawnError: enoent } })
    );
    const status = await provider.status(true);
    expect(status.available).toBe(false);
    expect(status.label).toBe('Non-LLM mode');
    expect(status.detail).toMatch(/npm install -g @google\/gemini-cli/);
    expect(status.detail).toMatch(/Settings/);
  });

  it('reports a probe timeout as its own case', async () => {
    const provider = new GeminiCliProvider(
      geminiConfig('gemini'),
      scripted({ version: { timedOut: true } })
    );
    const status = await provider.status(true);
    expect(status.detail).toMatch(/did not respond/i);
  });

  it('surfaces a non-zero exit with the CLI stderr', async () => {
    const provider = new GeminiCliProvider(
      geminiConfig('gemini'),
      scripted({ version: { code: 3, stderr: 'unsupported node version' } })
    );
    const status = await provider.status(true);
    expect(status.detail).toContain('exited with code 3');
    expect(status.detail).toContain('unsupported node version');
  });

  it('caches the probe result and re-probes only when forced', async () => {
    let probes = 0;
    const provider = new GeminiCliProvider(geminiConfig('gemini'), async () => {
      probes += 1;
      return { code: 0, stdout: '0.60.0', stderr: '', timedOut: false };
    });
    await provider.status(true);
    await provider.status();
    expect(probes).toBe(1);
    await provider.status(true);
    expect(probes).toBe(2);
  });
});

describe('Gemini CLI invocation', () => {
  it('forces headless mode with -p and keeps the payload on stdin', async () => {
    let seenArgs: string[] = [];
    let seenInput: string | undefined;
    const provider = new GeminiCliProvider(
      { ...geminiConfig('gemini'), model: 'gemini-2.5-pro' },
      async (_command, args, options) => {
        if (args.includes('--version'))
          return { code: 0, stdout: '0.60.0', stderr: '', timedOut: false };
        seenArgs = args;
        seenInput = options.input;
        return { code: 0, stdout: '{"summary":"ok"}', stderr: '', timedOut: false };
      }
    );

    const bigPrompt = 'x'.repeat(50_000);
    await provider.generate({ prompt: bigPrompt, payloadJson: '{}', timeoutMs: 5_000 });

    expect(seenArgs).toContain('-p');
    expect(seenArgs).toContain('--model');
    expect(seenArgs).toContain('gemini-2.5-pro');
    // A 50k prompt on argv would exceed the Windows command line limit.
    expect(seenArgs.join(' ').length).toBeLessThan(500);
    expect(seenInput).toBe(bigPrompt);
  });

  it('reports an auth failure during generation precisely', async () => {
    const provider = new GeminiCliProvider(geminiConfig('gemini'), async (_command, args) => {
      if (args.includes('--version'))
        return { code: 0, stdout: '0.60.0', stderr: '', timedOut: false };
      return { code: 41, stdout: '', stderr: 'Please set an Auth method', timedOut: false };
    });

    await expect(
      provider.generate({ prompt: 'p', payloadJson: '{}', timeoutMs: 5_000 })
    ).rejects.toThrow(/not authenticated/i);
  });
});
