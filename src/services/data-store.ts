/**
 * In-memory AWS data lifecycle.
 *
 * AWS data is held only for the lifetime of the local server process. Opening a
 * section fetches its data; returning to a section reuses what is already in
 * memory; Refresh (per section) and Refresh All discard and refetch. Nothing
 * here is ever written to disk.
 */

import { RequestDeduplicator } from '../util/async.js';
import type { SectionId, Selection } from './types.js';
import { selectionKey } from './types.js';

interface Entry<T> {
  value: T;
  fetchedAt: number;
  key: string;
  section: SectionId;
}

export interface CacheStats {
  entries: Array<{ section: SectionId; key: string; fetchedAt: string; ageSeconds: number }>;
  size: number;
}

export class AwsDataStore {
  private readonly entries = new Map<string, Entry<unknown>>();
  private readonly dedupe = new RequestDeduplicator();

  /**
   * Returns in-memory data when present, otherwise fetches it. `force` bypasses
   * the in-memory copy (the Refresh buttons).
   */
  async resolve<T>(
    section: SectionId,
    selection: Selection,
    fetcher: () => Promise<T>,
    options: { force?: boolean; variant?: string } = {}
  ): Promise<{ value: T; fromCache: boolean; fetchedAt: string }> {
    const key = selectionKey(section, selection, options.variant ?? '');

    if (!options.force) {
      const existing = this.entries.get(key) as Entry<T> | undefined;
      if (existing) {
        return {
          value: existing.value,
          fromCache: true,
          fetchedAt: new Date(existing.fetchedAt).toISOString(),
        };
      }
    }

    const value = await this.dedupe.run(key, fetcher);
    const fetchedAt = Date.now();
    this.entries.set(key, { value, fetchedAt, key, section });
    return { value, fromCache: false, fetchedAt: new Date(fetchedAt).toISOString() };
  }

  /** Data already in memory for a section, if any. Used to build AI payloads. */
  peek<T>(section: SectionId, selection: Selection, variant = ''): T | undefined {
    const entry = this.entries.get(selectionKey(section, selection, variant));
    return entry?.value as T | undefined;
  }

  has(section: SectionId, selection: Selection, variant = ''): boolean {
    return this.entries.has(selectionKey(section, selection, variant));
  }

  invalidateSection(section: SectionId): void {
    for (const [key, entry] of this.entries) {
      if (entry.section === section) this.entries.delete(key);
    }
  }

  invalidateAll(): void {
    this.entries.clear();
  }

  stats(): CacheStats {
    const now = Date.now();
    return {
      size: this.entries.size,
      entries: [...this.entries.values()].map((entry) => ({
        section: entry.section,
        key: entry.key,
        fetchedAt: new Date(entry.fetchedAt).toISOString(),
        ageSeconds: Math.round((now - entry.fetchedAt) / 1000),
      })),
    };
  }
}
