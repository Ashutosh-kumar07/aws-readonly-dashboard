/**
 * End-to-end server behaviour: port selection, the HTTP API, and the guarantee
 * that no AI call happens without an explicit user action.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { writeFile, chmod, readFile, mkdir, access } from 'node:fs/promises';
import { join } from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';

import { startServer, type StartedServer } from '../src/server/index.js';
import { findAvailablePort, isPortAvailable, DEFAULT_PORT } from '../src/server/port.js';
import { openBrowser } from '../src/server/browser.js';

let dir: string;
let server: StartedServer;
let geminiLog: string;

async function request(path: string, init: { method?: string; body?: unknown } = {}) {
  const response = await fetch(`${server.url}${path}`, {
    method: init.method ?? 'GET',
    headers: init.body ? { 'Content-Type': 'application/json' } : {},
    body: init.body ? JSON.stringify(init.body) : undefined,
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text ? JSON.parse(text) : null,
    contentType: response.headers.get('content-type'),
  };
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'arod-server-'));
  geminiLog = join(dir, 'gemini-invocations.log');

  // A stand-in for the Gemini CLI that records every invocation, so the tests
  // can prove the dashboard never calls it on its own.
  const shimDir = join(dir, 'bin');
  await mkdir(shimDir, { recursive: true });
  const shim = join(shimDir, 'gemini');
  await writeFile(
    shim,
    `#!/bin/sh\necho "$@" >> "${geminiLog}"\necho '{"summary":"stub"}'\n`,
    'utf8'
  );
  await chmod(shim, 0o755);
  process.env.PATH = `${shimDir}:${process.env.PATH}`;

  server = await startServer({ port: 9301, configDir: dir, logLevel: 'silent' });
}, 30000);

afterAll(async () => {
  await server?.close();
  await rm(dir, { recursive: true, force: true });
});

describe('port selection', () => {
  it('defaults to 9001', () => {
    expect(DEFAULT_PORT).toBe(9001);
  });

  it('reports the port it actually bound', () => {
    expect(server.port).toBe(9301);
    expect(server.portSelection.changed).toBe(false);
    expect(server.url).toContain('9301');
  });

  it('moves to the next free port when the preferred one is busy', async () => {
    const selection = await findAvailablePort(9301, '127.0.0.1');
    expect(selection.port).toBeGreaterThan(9301);
    expect(selection.requestedPort).toBe(9301);
    expect(selection.changed).toBe(true);
  });

  it('knows whether a port is free', async () => {
    expect(await isPortAvailable(9301, '127.0.0.1')).toBe(false);
    expect(await isPortAvailable(9399, '127.0.0.1')).toBe(true);
  });

  it('binds to loopback by default', () => {
    expect(server.host).toBe('127.0.0.1');
  });
});

describe('static assets', () => {
  it('serves the dashboard shell', async () => {
    const response = await fetch(`${server.url}/`);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    expect(await response.text()).toContain('AWS Read-Only Dashboard');
  });

  it('serves the JavaScript modules and stylesheet', async () => {
    for (const [path, type] of [
      ['/js/app.js', 'javascript'],
      ['/styles.css', 'text/css'],
    ]) {
      const response = await fetch(`${server.url}${path}`);
      expect(response.status, path).toBe(200);
      expect(response.headers.get('content-type'), path).toContain(type as string);
    }
  });

  it('sets a restrictive content security policy', async () => {
    const response = await fetch(`${server.url}/`);
    const csp = response.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it('refuses path traversal', async () => {
    const response = await fetch(`${server.url}/../package.json`);
    const body = await response.text();
    expect(body).not.toContain('"devDependencies"');
  });
});

describe('the dashboard API', () => {
  it('reports status, version and read-only mode', async () => {
    const { status, body } = await request('/api/status');
    expect(status).toBe(200);
    expect(body.readOnly).toBe(true);
    expect(body.name).toBe('aws-readonly-dashboard');
    expect(body.server.port).toBe(9301);
    expect(body.ai.promptVersion).toBeTruthy();
  });

  it('returns the region catalogue with global listed separately', async () => {
    const { body } = await request('/api/regions');
    expect(body.regions.length).toBeGreaterThan(20);
    expect(body.global.id).toBe('global');
    expect(body.global.alwaysIncluded).toBe(true);
  });

  it('publishes the read-only allowlist and required IAM actions', async () => {
    const { body } = await request('/api/permissions');
    expect(body.iamActions).toContain('ce:GetCostAndUsage');
    expect(
      body.iamActions.every((action: string) => !/(:Put|:Create|:Delete|:Update)/.test(action))
    ).toBe(true);
    expect(body.operations.length).toBeGreaterThan(40);
  });

  it('describes the security checks', async () => {
    const { body } = await request('/api/security/checks');
    expect(body.checks.length).toBeGreaterThanOrEqual(12);
  });

  it('lists locally discovered profiles without making AWS calls', async () => {
    const before = (await request('/api/status')).body.apiCalls;
    const { body } = await request('/api/profiles');
    expect(Array.isArray(body.profiles)).toBe(true);
    const after = (await request('/api/status')).body.apiCalls;
    expect(after).toBe(before);
  });

  it('reads and writes configuration', async () => {
    const write = await request('/api/config', {
      method: 'PUT',
      body: { billing: { dollarThreshold: 42 }, regions: { selected: ['eu-west-1'] } },
    });
    expect(write.status).toBe(200);
    expect(write.body.billing.dollarThreshold).toBe(42);

    const read = await request('/api/config');
    expect(read.body.regions.selected).toEqual(['eu-west-1']);

    const onDisk = JSON.parse(await readFile(join(dir, 'config.json'), 'utf8'));
    expect(onDisk.billing.dollarThreshold).toBe(42);
  });

  it('rejects a configuration change that would widen AWS access', async () => {
    const response = await request('/api/config', {
      method: 'PUT',
      body: { allowWrites: true, disabledApiCategories: ['s3'] },
    });
    expect(response.body.allowWrites).toBeUndefined();
    expect(response.body.disabledApiCategories).toEqual(['s3']);
    // Restore, so later assertions are not affected.
    await request('/api/config', { method: 'PUT', body: { disabledApiCategories: [] } });
  });

  it('returns AWS API usage statistics', async () => {
    const { body } = await request('/api/aws-usage');
    expect(body).toHaveProperty('totalCalls');
    expect(body).toHaveProperty('categories');
    expect(body).toHaveProperty('recentCalls');
  });

  it('returns a section envelope with no profiles selected, without calling AWS', async () => {
    const { status, body } = await request('/api/sections/billing', {
      method: 'POST',
      body: { profiles: [] },
    });
    expect(status).toBe(200);
    expect(body.section).toBe('billing');
    expect(body.profiles).toEqual([]);
  });

  it('404s an unknown API route', async () => {
    const { status, body } = await request('/api/nope');
    expect(status).toBe(404);
    expect(body.error).toContain('No such API route');
  });

  it('rejects a malformed JSON body', async () => {
    const response = await fetch(`${server.url}/api/profiles/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{ broken',
    });
    expect(response.status).toBe(400);
  });

  it('validates the finding status value', async () => {
    const { status } = await request('/api/security/findings/does-not-exist', {
      method: 'PATCH',
      body: { status: 'obliterated' },
    });
    expect(status).toBe(400);
  });

  it('404s a status change for an unknown finding', async () => {
    const { status } = await request('/api/security/findings/does-not-exist', {
      method: 'PATCH',
      body: { status: 'ignored' },
    });
    expect(status).toBe(404);
  });
});

describe('AI is never invoked automatically', () => {
  it('does not call the provider during startup, status, config or section loads', async () => {
    await request('/api/status');
    await request('/api/config');
    await request('/api/profiles');
    await request('/api/sections/billing', { method: 'POST', body: { profiles: [] } });
    await request('/api/sections/security', { method: 'POST', body: { profiles: [] } });
    await request('/api/sections/cloudwatch', { method: 'POST', body: { profiles: [] } });
    await request('/api/sections/compute-optimizer', { method: 'POST', body: { profiles: [] } });
    await request('/api/sections/refresh-all', { method: 'POST', body: { profiles: [] } });
    await request('/api/aws-usage');

    let log = '';
    try {
      await access(geminiLog);
      log = await readFile(geminiLog, 'utf8');
    } catch {
      log = '';
    }

    // Startup probes the CLI with --version, which is a capability check, not an
    // AI call. Nothing else may have invoked it.
    const invocations = log.split('\n').filter(Boolean);
    expect(invocations.every((line) => line.trim() === '--version')).toBe(true);
  });

  it('reports AI status without generating anything', async () => {
    const { body } = await request('/api/ai/status');
    expect(body).toHaveProperty('nonLlmMode');
    expect(body).toHaveProperty('providers');
  });

  it('requires an explicit section selection to analyse', async () => {
    const { status, body } = await request('/api/ai/analyze', {
      method: 'POST',
      body: { sections: [] },
    });
    expect(status).toBe(400);
    expect(body.error).toMatch(/at least one section/i);
  });
});

describe('local data deletion', () => {
  it('removes the application directory and resets defaults', async () => {
    const { status, body } = await request('/api/config', { method: 'DELETE' });
    expect(status).toBe(200);
    expect(body.deleted).toBe(true);

    const config = await request('/api/config');
    expect(config.body.billing.dollarThreshold).toBe(20);
  });
});

describe('browser launch', () => {
  it('refuses to open a non-local URL', () => {
    expect(openBrowser('https://example.com')).toBe(false);
  });

  it('spawns a platform-appropriate opener for a localhost URL', () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const fakeSpawn = ((command: string, args: string[]) => {
      calls.push({ command, args });
      return { on() {}, unref() {} };
    }) as never;

    expect(openBrowser('http://localhost:9001', { platform: 'darwin', spawnFn: fakeSpawn })).toBe(
      true
    );
    expect(calls[0]?.command).toBe('open');

    expect(openBrowser('http://127.0.0.1:9001', { platform: 'linux', spawnFn: fakeSpawn })).toBe(
      true
    );
    expect(calls[1]?.command).toBe('xdg-open');

    expect(openBrowser('http://localhost:9001', { platform: 'win32', spawnFn: fakeSpawn })).toBe(
      true
    );
    expect(calls[2]?.command).toBe('cmd');
  });
});
