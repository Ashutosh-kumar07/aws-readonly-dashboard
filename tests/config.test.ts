/** Local JSON configuration: persistence, validation, migration and deletion. */

import { describe, expect, it } from 'vitest';
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { join } from 'node:path';

import { ConfigService } from '../src/config/config-service.js';
import {
  CONFIG_VERSION,
  defaultConfig,
  migrateConfig,
  normaliseConfig,
  MAX_AI_HISTORY_RETENTION_DAYS,
} from '../src/config/schema.js';
import { resolveConfigPaths } from '../src/config/paths.js';
import { writeJsonFile, readJsonFile } from '../src/config/json-store.js';
import { withTempDir } from './helpers.js';

describe('configuration defaults', () => {
  it('matches the documented product defaults', () => {
    const config = defaultConfig();
    expect(config.version).toBe(CONFIG_VERSION);
    expect(config.billing.comparisonDays).toBe(7);
    expect(config.billing.dollarThreshold).toBe(20);
    expect(config.billing.percentThreshold).toBe(10);
    expect(config.cloudwatch.growthPercentThreshold).toBe(5);
    expect(config.cloudwatch.growthBytesThreshold).toBe(2 * 1024 * 1024 * 1024);
    expect(config.ai.provider).toBe('gemini');
    expect(config.ai.history.enabled).toBe(false);
    expect(config.ai.history.retentionDays).toBe(7);
    expect(config.ai.custom.enabled).toBe(false);
  });
});

describe('configuration normalisation', () => {
  it('clamps out-of-range values instead of trusting the file', () => {
    const config = normaliseConfig({
      billing: { dollarThreshold: -50, percentThreshold: 99999, comparisonDays: 3 },
      cloudwatch: { longRetentionDays: 100000, growthWindowDays: 0 },
      ai: { history: { retentionDays: 900 } },
    });
    expect(config.billing.dollarThreshold).toBe(0);
    expect(config.billing.percentThreshold).toBe(10000);
    expect(config.billing.comparisonDays).toBe(7); // 3 is not a supported period
    expect(config.cloudwatch.longRetentionDays).toBeLessThanOrEqual(3653);
    expect(config.cloudwatch.growthWindowDays).toBeGreaterThanOrEqual(1);
    expect(config.ai.history.retentionDays).toBe(MAX_AI_HISTORY_RETENTION_DAYS);
  });

  it('accepts every supported comparison period', () => {
    for (const days of [1, 7, 14, 30, 60, 90]) {
      expect(normaliseConfig({ billing: { comparisonDays: days } }).billing.comparisonDays).toBe(
        days
      );
    }
  });

  it('drops unknown keys and junk shapes', () => {
    const config = normaliseConfig({
      totallyUnknown: 'value',
      profiles: 'not-an-object',
      regions: { selected: ['us-east-1', 42, 'eu-west-1'] },
    });
    expect((config as unknown as Record<string, unknown>).totallyUnknown).toBeUndefined();
    expect(config.regions.selected).toEqual(['us-east-1', 'eu-west-1']);
  });

  it('restores a locked sanitization rule that was deleted from the file', () => {
    const config = normaliseConfig({
      ai: {
        sanitization: {
          rules: [{ id: 'email', enabled: false, strategy: 'redact', builtin: true }],
        },
      },
    });
    const locked = config.ai.sanitization.rules.find((rule) => rule.id === 'aws-credentials');
    expect(locked).toBeDefined();
    expect(locked?.enabled).toBe(true);
  });

  it('refuses to disable a locked sanitization rule', () => {
    const config = normaliseConfig({
      ai: {
        sanitization: {
          rules: [{ id: 'aws-credentials', enabled: false, strategy: 'redact', builtin: true }],
        },
      },
    });
    expect(
      config.ai.sanitization.rules.find((rule) => rule.id === 'aws-credentials')?.enabled
    ).toBe(true);
  });

  it('allows a default rule to be disabled by the user', () => {
    const config = normaliseConfig({
      ai: {
        sanitization: {
          rules: [{ id: 'hostname', enabled: false, strategy: 'redact', builtin: true }],
        },
      },
    });
    expect(config.ai.sanitization.rules.find((rule) => rule.id === 'hostname')?.enabled).toBe(
      false
    );
  });

  it('rejects a custom rule with an invalid regular expression', () => {
    const config = normaliseConfig({
      ai: {
        sanitization: {
          rules: [
            { id: 'aws-credentials', enabled: true, strategy: 'redact', builtin: true },
            {
              id: 'broken',
              label: 'Broken',
              pattern: '([unclosed',
              strategy: 'redact',
              enabled: true,
            },
          ],
        },
      },
    });
    expect(config.ai.sanitization.rules.find((rule) => rule.id === 'broken')).toBeUndefined();
  });

  it('keeps a valid custom rule', () => {
    const config = normaliseConfig({
      ai: {
        sanitization: {
          rules: [
            { id: 'aws-credentials', enabled: true, strategy: 'redact', builtin: true },
            {
              id: 'ticket',
              label: 'Tickets',
              pattern: 'TICKET-\\d+',
              strategy: 'pseudonymize',
              enabled: true,
            },
          ],
        },
      },
    });
    const rule = config.ai.sanitization.rules.find((entry) => entry.id === 'ticket');
    expect(rule?.pattern).toBe('TICKET-\\d+');
    expect(rule?.strategy).toBe('pseudonymize');
  });
});

describe('configuration migration', () => {
  it('migrates an unversioned document up to the current version', () => {
    const { config, migratedFrom } = migrateConfig({ billing: { dollarThreshold: 42 } });
    expect(migratedFrom).toBe(0);
    expect(config.version).toBe(CONFIG_VERSION);
    expect(config.billing.dollarThreshold).toBe(42);
  });

  it('does not re-migrate a current document', () => {
    const { migratedFrom } = migrateConfig(defaultConfig());
    expect(migratedFrom).toBeUndefined();
  });

  it('keeps "off" meaning off when a Lambda limit of 0 changes meaning', () => {
    // Version 2 redefines 0 as "inspect every function". A stored 0 meant the
    // opposite, so the intent moves to the check list rather than silently
    // becoming a full scan of every function in every region.
    const { config } = migrateConfig({
      version: 1,
      security: { maxLambdaPolicyLookupsPerRegion: 0 },
    });

    expect(config.security.disabledChecks).toContain('lambda-public-resource-policy');
    expect(config.security.maxLambdaPolicyLookupsPerRegion).toBe(100);
  });

  it('leaves a non-zero Lambda limit alone', () => {
    const { config } = migrateConfig({
      version: 1,
      security: { maxLambdaPolicyLookupsPerRegion: 250, disabledChecks: [] },
    });
    expect(config.security.maxLambdaPolicyLookupsPerRegion).toBe(250);
    expect(config.security.disabledChecks).toEqual([]);
  });

  it('falls back to defaults for a non-object document', () => {
    expect(migrateConfig('nonsense').config.version).toBe(CONFIG_VERSION);
    expect(migrateConfig(null).config.billing.comparisonDays).toBe(7);
  });
});

describe('ConfigService', () => {
  it('persists updates as JSON and reloads them', async () => {
    await withTempDir(async (dir) => {
      const service = new ConfigService({ configDir: dir });
      await service.load();
      await service.update({
        billing: { dollarThreshold: 55 },
        regions: { selected: ['eu-west-1'] },
      });

      const onDisk = JSON.parse(await readFile(join(dir, 'config.json'), 'utf8'));
      expect(onDisk.billing.dollarThreshold).toBe(55);

      const reloaded = new ConfigService({ configDir: dir });
      const config = await reloaded.load();
      expect(config.billing.dollarThreshold).toBe(55);
      expect(config.regions.selected).toEqual(['eu-west-1']);
    });
  });

  it('writes files with owner-only permissions', async () => {
    await withTempDir(async (dir) => {
      const service = new ConfigService({ configDir: dir });
      await service.load();
      await service.update({ billing: { dollarThreshold: 1 } });
      const info = await stat(join(dir, 'config.json'));
      // 0o600 — readable and writable only by the owner.
      expect(info.mode & 0o777).toBe(0o600);
    });
  });

  it('survives a corrupt configuration file', async () => {
    await withTempDir(async (dir) => {
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, 'config.json'), '{ not json at all', 'utf8');
      const service = new ConfigService({ configDir: dir });
      const config = await service.load();
      expect(config.version).toBe(CONFIG_VERSION);
      expect(config.billing.comparisonDays).toBe(7);
    });
  });

  it('serialises concurrent updates without losing any of them', async () => {
    await withTempDir(async (dir) => {
      const service = new ConfigService({ configDir: dir });
      await service.load();
      await Promise.all([
        service.update({ billing: { dollarThreshold: 10 } }),
        service.update({ billing: { percentThreshold: 25 } }),
        service.update({ regions: { selected: ['us-west-2'] } }),
      ]);
      const config = service.current;
      expect(config.billing.percentThreshold).toBe(25);
      expect(config.regions.selected).toEqual(['us-west-2']);
    });
  });

  it('deletes every local file and resets to defaults', async () => {
    await withTempDir(async (dir) => {
      const service = new ConfigService({ configDir: dir });
      await service.load();
      await service.update({ billing: { dollarThreshold: 99 } });
      await writeJsonFile(service.paths.findingsFile, { version: 1, findings: {} });
      await writeJsonFile(service.paths.aiHistoryFile, { version: 1, entries: [] });

      const result = await service.deleteAll();

      expect(result.removed).toHaveLength(3);
      expect(await readJsonFile(service.paths.configFile)).toBeUndefined();
      expect(service.current.billing.dollarThreshold).toBe(20);
    });
  });

  it('notifies listeners when configuration changes', async () => {
    await withTempDir(async (dir) => {
      const service = new ConfigService({ configDir: dir });
      await service.load();
      let seen = 0;
      service.onChange(() => {
        seen += 1;
      });
      await service.update({ billing: { dollarThreshold: 5 } });
      expect(seen).toBe(1);
    });
  });
});

describe('configuration paths', () => {
  it('prefers an explicit directory, then the environment, then the home directory', () => {
    expect(resolveConfigPaths('/tmp/explicit').dir).toBe('/tmp/explicit');
    expect(
      resolveConfigPaths(undefined, { AWS_READONLY_DASHBOARD_HOME: '/tmp/env' } as never).dir
    ).toBe('/tmp/env');
    expect(resolveConfigPaths(undefined, {} as never).dir).toMatch(/\.aws-readonly-dashboard$/);
  });

  it('places all three JSON files inside the directory', () => {
    const paths = resolveConfigPaths('/tmp/explicit');
    expect(paths.configFile).toBe('/tmp/explicit/config.json');
    expect(paths.findingsFile).toBe('/tmp/explicit/security-findings.json');
    expect(paths.aiHistoryFile).toBe('/tmp/explicit/ai-history.json');
  });
});

describe('atomic JSON writes', () => {
  it('leaves no temporary files behind', async () => {
    await withTempDir(async (dir) => {
      const target = join(dir, 'doc.json');
      await writeJsonFile(target, { hello: 'world' });
      expect(await readJsonFile(target)).toEqual({ hello: 'world' });
      const { readdir } = await import('node:fs/promises');
      const entries = await readdir(dir);
      expect(entries.filter((entry) => entry.endsWith('.tmp'))).toHaveLength(0);
    });
  });
});
