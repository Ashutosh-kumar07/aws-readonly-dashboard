/**
 * Configuration service: load, persist, patch and delete local configuration.
 *
 * Writes are serialised through a single promise chain so concurrent dashboard
 * requests can never interleave and corrupt the document.
 */

import { logger } from '../util/logger.js';
import { deleteDir, deleteFile, fileExists, readJsonFile, writeJsonFile } from './json-store.js';
import { resolveConfigPaths, type ConfigPaths } from './paths.js';
import {
  CONFIG_VERSION,
  defaultConfig,
  migrateConfig,
  normaliseConfig,
  type AppConfig,
} from './schema.js';

export interface ConfigServiceOptions {
  /** Explicit configuration directory (from `--config-dir`). */
  configDir?: string;
  env?: NodeJS.ProcessEnv;
}

type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends Array<infer U>
    ? U[]
    : T[K] extends object
      ? DeepPartial<T[K]>
      : T[K];
};

function deepMerge<T>(base: T, patch: DeepPartial<T>): T {
  if (patch === undefined || patch === null) return base;
  if (Array.isArray(patch)) return patch as unknown as T;
  if (typeof patch !== 'object' || typeof base !== 'object' || base === null) {
    return patch as unknown as T;
  }
  const result: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [key, value] of Object.entries(patch as Record<string, unknown>)) {
    const current = (base as Record<string, unknown>)[key];
    result[key] =
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      current &&
      typeof current === 'object'
        ? deepMerge(current, value as DeepPartial<unknown>)
        : value;
  }
  return result as T;
}

export class ConfigService {
  readonly paths: ConfigPaths;
  private config: AppConfig = defaultConfig();
  private loaded = false;
  private queue: Promise<unknown> = Promise.resolve();
  private readonly listeners = new Set<(config: AppConfig) => void>();

  constructor(options: ConfigServiceOptions = {}) {
    this.paths = resolveConfigPaths(options.configDir, options.env);
  }

  async load(): Promise<AppConfig> {
    const raw = await readJsonFile<unknown>(this.paths.configFile);
    if (raw === undefined) {
      this.config = defaultConfig();
      this.loaded = true;
      return this.config;
    }
    const { config, migratedFrom } = migrateConfig(raw);
    this.config = config;
    this.loaded = true;
    if (migratedFrom !== undefined) {
      logger.info(`Migrated local configuration from version ${migratedFrom} to ${CONFIG_VERSION}`);
      await this.persist();
    }
    return this.config;
  }

  get current(): AppConfig {
    if (!this.loaded) logger.debug('Configuration read before load(); returning defaults');
    return this.config;
  }

  onChange(listener: (config: AppConfig) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(): void {
    for (const listener of this.listeners) {
      try {
        listener(this.config);
      } catch (error) {
        logger.warn('Configuration listener failed', { reason: (error as Error).message });
      }
    }
  }

  private async persist(): Promise<void> {
    await writeJsonFile(this.paths.configFile, this.config);
  }

  /** Serialises mutations so two concurrent requests cannot clobber each other. */
  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = this.queue.then(task, task);
    this.queue = run.catch(() => undefined);
    return run;
  }

  /** Applies a partial update, normalises it, persists and notifies listeners. */
  async update(patch: DeepPartial<AppConfig>): Promise<AppConfig> {
    return this.enqueue(async () => {
      const merged = deepMerge(this.config, patch);
      this.config = normaliseConfig(merged);
      await this.persist();
      this.emit();
      return this.config;
    });
  }

  /** Replaces the whole document (still normalised). */
  async replace(next: unknown): Promise<AppConfig> {
    return this.enqueue(async () => {
      this.config = normaliseConfig(next);
      await this.persist();
      this.emit();
      return this.config;
    });
  }

  /**
   * Removes every locally persisted file this application owns and resets the
   * in-memory configuration to defaults.
   */
  async deleteAll(): Promise<{ removed: string[]; directoryRemoved: boolean }> {
    return this.enqueue(async () => {
      const removed: string[] = [];
      for (const file of [
        this.paths.configFile,
        this.paths.findingsFile,
        this.paths.aiHistoryFile,
      ]) {
        if (await fileExists(file)) {
          await deleteFile(file);
          removed.push(file);
        }
      }
      const directoryRemoved = await deleteDir(this.paths.dir);
      this.config = defaultConfig();
      this.emit();
      return { removed, directoryRemoved };
    });
  }
}
