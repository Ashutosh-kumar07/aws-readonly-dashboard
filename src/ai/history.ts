/**
 * AI history.
 *
 * Off by default. When enabled, only the *sanitized* request and the model
 * response are retained — never raw AWS data, and never the placeholder→value
 * mapping that would undo the pseudonymization.
 *
 * Retention defaults to 7 days and is capped at 30. Expired entries are removed
 * on every load and on every write.
 */

import { readJsonFile, writeJsonFile } from '../config/json-store.js';
import { MAX_AI_HISTORY_RETENTION_DAYS } from '../config/schema.js';
import type { SectionId } from '../services/types.js';
import type { AiAnalysis } from './response.js';

export const AI_HISTORY_VERSION = 1;

export interface AiHistoryEntry {
  id: string;
  createdAt: string;
  provider: string;
  promptVersion: string;
  profiles: string[];
  regions: string[];
  sections: SectionId[];
  kind: 'section' | 'cross-section';
  /** The sanitized prompt exactly as it was sent. */
  sanitizedPrompt: string;
  /** The sanitized payload exactly as it was sent. */
  sanitizedPayload: unknown;
  /** Raw provider response text. */
  response: string;
  /** Parsed analysis, when the response validated. */
  analysis?: AiAnalysis;
  error?: string;
}

interface HistoryDocument {
  version: number;
  entries: AiHistoryEntry[];
}

const DAY_MS = 24 * 60 * 60 * 1000;

export class AiHistoryStore {
  private document: HistoryDocument = { version: AI_HISTORY_VERSION, entries: [] };
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly filePath: string) {}

  async load(retentionDays: number): Promise<void> {
    const raw = await readJsonFile<HistoryDocument>(this.filePath);
    const entries = Array.isArray(raw?.entries) ? raw.entries : [];
    this.document = { version: AI_HISTORY_VERSION, entries };
    await this.prune(retentionDays);
  }

  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = this.queue.then(task, task);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async persist(): Promise<void> {
    await writeJsonFile(this.filePath, this.document);
  }

  /** Drops entries older than the retention window. Returns how many were removed. */
  async prune(retentionDays: number, now: Date = new Date()): Promise<number> {
    const days = Math.min(Math.max(retentionDays, 1), MAX_AI_HISTORY_RETENTION_DAYS);
    const cutoff = now.getTime() - days * DAY_MS;
    return this.enqueue(async () => {
      const before = this.document.entries.length;
      this.document.entries = this.document.entries.filter((entry) => {
        const timestamp = Date.parse(entry.createdAt);
        return Number.isFinite(timestamp) && timestamp >= cutoff;
      });
      const removed = before - this.document.entries.length;
      if (removed > 0) await this.persist();
      return removed;
    });
  }

  async append(entry: AiHistoryEntry, retentionDays: number): Promise<void> {
    await this.enqueue(async () => {
      this.document.entries.push(entry);
      // Keep the file bounded even within the retention window.
      if (this.document.entries.length > 500) {
        this.document.entries = this.document.entries.slice(-500);
      }
      await this.persist();
    });
    await this.prune(retentionDays);
  }

  /**
   * History relevant to one analysis. Profile isolation is enforced here: an
   * entry is only relevant when every profile it used is also in scope now.
   */
  relevant(options: {
    profiles: readonly string[];
    sections: readonly SectionId[];
    limit?: number;
  }): AiHistoryEntry[] {
    const scope = new Set(options.profiles);
    const sections = new Set(options.sections);
    return this.document.entries
      .filter(
        (entry) =>
          entry.profiles.length > 0 && entry.profiles.every((profile) => scope.has(profile))
      )
      .filter((entry) => entry.sections.some((section) => sections.has(section)))
      .slice(-(options.limit ?? 5));
  }

  list(filter?: { profiles?: readonly string[] }): AiHistoryEntry[] {
    const entries = [...this.document.entries].reverse();
    if (!filter?.profiles?.length) return entries;
    const scope = new Set(filter.profiles);
    return entries.filter((entry) => entry.profiles.every((profile) => scope.has(profile)));
  }

  get size(): number {
    return this.document.entries.length;
  }

  async clear(): Promise<number> {
    return this.enqueue(async () => {
      const removed = this.document.entries.length;
      this.document.entries = [];
      await this.persist();
      return removed;
    });
  }

  async delete(id: string): Promise<boolean> {
    return this.enqueue(async () => {
      const before = this.document.entries.length;
      this.document.entries = this.document.entries.filter((entry) => entry.id !== id);
      const changed = this.document.entries.length !== before;
      if (changed) await this.persist();
      return changed;
    });
  }
}
