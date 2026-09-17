/**
 * Persistence of *user decisions* about security findings.
 *
 * Only the minimum needed to keep a finding filterable after it stops being
 * detected is stored: its identity, its status, and a short summary. Raw AWS
 * evidence is never written to disk — it lives in memory with the rest of the
 * AWS data.
 */

import { readJsonFile, writeJsonFile } from '../../config/json-store.js';
import type { FindingStatus } from '../../config/schema.js';
import type { Severity } from './types.js';

export const FINDING_STORE_VERSION = 1;

export interface PersistedFinding {
  id: string;
  status: FindingStatus;
  checkId: string;
  title: string;
  severity: Severity;
  profile: string;
  accountId?: string;
  region: string;
  resourceId: string;
  resourceType: string;
  firstSeenAt: string;
  lastSeenAt: string;
  updatedAt: string;
  note?: string;
}

interface StoreDocument {
  version: number;
  findings: Record<string, PersistedFinding>;
}

export class FindingStore {
  private document: StoreDocument = { version: FINDING_STORE_VERSION, findings: {} };
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly filePath: string) {}

  async load(): Promise<void> {
    const raw = await readJsonFile<StoreDocument>(this.filePath);
    if (!raw || typeof raw !== 'object' || typeof raw.findings !== 'object') {
      this.document = { version: FINDING_STORE_VERSION, findings: {} };
      return;
    }
    const findings: Record<string, PersistedFinding> = {};
    for (const [id, value] of Object.entries(raw.findings ?? {})) {
      if (!value || typeof value !== 'object') continue;
      const status = (value as PersistedFinding).status;
      if (!['open', 'acknowledged', 'ignored', 'resolved'].includes(status)) continue;
      findings[id] = { ...(value as PersistedFinding), id };
    }
    this.document = { version: FINDING_STORE_VERSION, findings };
  }

  all(): PersistedFinding[] {
    return Object.values(this.document.findings);
  }

  get(id: string): PersistedFinding | undefined {
    return this.document.findings[id];
  }

  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    const run = this.queue.then(task, task);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async persist(): Promise<void> {
    await writeJsonFile(this.filePath, this.document);
  }

  /** Records that a finding was seen in the current scan. */
  async upsertSeen(findings: readonly PersistedFinding[]): Promise<void> {
    if (findings.length === 0) return;
    await this.enqueue(async () => {
      for (const finding of findings) {
        const existing = this.document.findings[finding.id];
        this.document.findings[finding.id] = existing
          ? {
              ...existing,
              ...finding,
              // A user decision always wins over the scanner's default status.
              status: existing.status === 'resolved' ? 'open' : existing.status,
              firstSeenAt: existing.firstSeenAt,
              ...(existing.note ? { note: existing.note } : {}),
            }
          : finding;
      }
      await this.persist();
    });
  }

  /** Marks findings that were previously seen but are no longer detected. */
  async markResolved(
    seenIds: ReadonlySet<string>,
    scope: { profiles: ReadonlySet<string>; regions: ReadonlySet<string> }
  ): Promise<PersistedFinding[]> {
    return this.enqueue(async () => {
      const now = new Date().toISOString();
      const resolved: PersistedFinding[] = [];
      for (const finding of Object.values(this.document.findings)) {
        if (seenIds.has(finding.id)) continue;
        if (!scope.profiles.has(finding.profile)) continue;
        if (finding.region !== 'global' && !scope.regions.has(finding.region)) continue;
        if (finding.status === 'resolved') {
          resolved.push(finding);
          continue;
        }
        const updated: PersistedFinding = { ...finding, status: 'resolved', updatedAt: now };
        this.document.findings[finding.id] = updated;
        resolved.push(updated);
      }
      if (resolved.length) await this.persist();
      return resolved;
    });
  }

  async setStatus(
    id: string,
    status: FindingStatus,
    note?: string
  ): Promise<PersistedFinding | undefined> {
    return this.enqueue(async () => {
      const existing = this.document.findings[id];
      if (!existing) return undefined;
      const updated: PersistedFinding = {
        ...existing,
        status,
        updatedAt: new Date().toISOString(),
        ...(note !== undefined ? { note } : {}),
      };
      this.document.findings[id] = updated;
      await this.persist();
      return updated;
    });
  }

  async deleteResolved(): Promise<number> {
    return this.enqueue(async () => {
      let removed = 0;
      for (const [id, finding] of Object.entries(this.document.findings)) {
        if (finding.status === 'resolved') {
          delete this.document.findings[id];
          removed += 1;
        }
      }
      if (removed) await this.persist();
      return removed;
    });
  }

  async delete(id: string): Promise<boolean> {
    return this.enqueue(async () => {
      if (!this.document.findings[id]) return false;
      delete this.document.findings[id];
      await this.persist();
      return true;
    });
  }
}
