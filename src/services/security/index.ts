/**
 * Security analyzer runner.
 *
 * Runs every enabled check for every selected profile, once globally and once
 * per selected region, then merges the results with the persisted user
 * decisions (acknowledged / ignored / resolved).
 */

import { mapWithConcurrency } from '../../util/async.js';
import { JobCancelledError } from '../../util/errors.js';
import { GLOBAL_SCOPE } from '../../aws/regions.js';
import type { AwsAccessLayer } from '../../aws/access-layer.js';
import type { AppConfig } from '../../config/schema.js';
import type { EvaluationIssue, ProfileScoped } from '../types.js';
import { SECURITY_CHECKS } from './registry.js';
import { FindingStore, type PersistedFinding } from './finding-store.js';
import { SEVERITY_RANK, type CheckContext, type SecurityFinding, type Severity } from './types.js';

export * from './types.js';
export { FindingStore } from './finding-store.js';
export { SECURITY_CHECKS, describeChecks } from './registry.js';

export interface CheckStatus {
  checkId: string;
  title: string;
  service: string;
  scope: 'regional' | 'global';
  region: string;
  state: 'evaluated' | 'not-evaluated' | 'disabled';
  findingCount: number;
  resourcesEvaluated?: number;
  truncated?: boolean;
  issues: EvaluationIssue[];
}

export interface SecurityData {
  findings: SecurityFinding[];
  /** Findings that were previously seen and are now resolved. */
  resolvedFindings: SecurityFinding[];
  checks: CheckStatus[];
  summary: {
    total: number;
    bySeverity: Record<Severity, number>;
    byStatus: Record<string, number>;
    evaluatedChecks: number;
    notEvaluatedChecks: number;
  };
}

/** Progress emitted as each check finishes, so results can be shown early. */
export interface SecurityProgress {
  completed: number;
  total: number;
  /** The check and region that just finished. */
  label: string;
  /** Everything found so far, ready to render. */
  data: SecurityData;
  issues: EvaluationIssue[];
}

export interface RunSecurityOptions {
  access: AwsAccessLayer;
  config: AppConfig;
  store: FindingStore;
  profile: string;
  accountId?: string;
  regions: string[];
  section?: string;
  /** Concurrency across (check × region) units. */
  concurrency?: number;
  /**
   * Called after each check completes. A scan of many checks across many
   * regions takes far longer than a user will watch a spinner, so partial
   * results are published as they arrive.
   */
  onProgress?: (progress: SecurityProgress) => void;
  /** Checked before each check runs, so a cancelled scan stops making AWS calls. */
  shouldStop?: () => boolean;
}

function toPersisted(finding: SecurityFinding): PersistedFinding {
  return {
    id: finding.id,
    status: finding.status,
    checkId: finding.checkId,
    title: finding.title,
    severity: finding.severity,
    profile: finding.profile,
    ...(finding.accountId ? { accountId: finding.accountId } : {}),
    region: finding.region,
    resourceId: finding.resourceId,
    resourceType: finding.resourceType,
    firstSeenAt: finding.firstSeenAt,
    lastSeenAt: finding.lastSeenAt,
    updatedAt: finding.updatedAt ?? finding.lastSeenAt,
    ...(finding.note ? { note: finding.note } : {}),
  };
}

function fromPersisted(persisted: PersistedFinding): SecurityFinding {
  return {
    id: persisted.id,
    checkId: persisted.checkId,
    title: persisted.title,
    severity: persisted.severity,
    profile: persisted.profile,
    ...(persisted.accountId ? { accountId: persisted.accountId } : {}),
    region: persisted.region,
    resourceType: persisted.resourceType,
    resourceId: persisted.resourceId,
    source: 'Local history',
    evidence: {
      note: 'This finding is no longer detected. Only its identity is retained locally; AWS evidence is not persisted.',
    },
    why: 'The condition that produced this finding was not detected in the most recent scan.',
    recommendation:
      'No action needed. Delete resolved findings when you no longer need the history.',
    status: persisted.status,
    firstSeenAt: persisted.firstSeenAt,
    lastSeenAt: persisted.lastSeenAt,
    updatedAt: persisted.updatedAt,
    ...(persisted.note ? { note: persisted.note } : {}),
    stale: true,
  };
}

/** Sorts findings and computes the summary counts shown in the dashboard. */
function buildSecurityData(
  findings: SecurityFinding[],
  resolvedFindings: SecurityFinding[],
  checks: CheckStatus[]
): SecurityData {
  const sorted = [...findings].sort((a, b) => {
    const rank = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    return rank !== 0 ? rank : a.title.localeCompare(b.title);
  });

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const byStatus: Record<string, number> = { open: 0, acknowledged: 0, ignored: 0, resolved: 0 };
  for (const finding of sorted) {
    bySeverity[finding.severity] += 1;
    byStatus[finding.status] = (byStatus[finding.status] ?? 0) + 1;
  }
  byStatus.resolved = (byStatus.resolved ?? 0) + resolvedFindings.length;

  return {
    findings: sorted,
    resolvedFindings,
    checks,
    summary: {
      total: sorted.length,
      bySeverity,
      byStatus,
      evaluatedChecks: checks.filter((check) => check.state === 'evaluated').length,
      notEvaluatedChecks: checks.filter((check) => check.state === 'not-evaluated').length,
    },
  };
}

/** Runs the security analyzer for a single profile across the selected regions. */
export async function runSecurityAnalysis(
  options: RunSecurityOptions
): Promise<ProfileScoped<SecurityData>> {
  const section = options.section ?? 'security';
  const disabled = new Set(options.config.security.disabledChecks);
  const units: Array<{ check: (typeof SECURITY_CHECKS)[number]; region: string }> = [];

  for (const check of SECURITY_CHECKS) {
    if (disabled.has(check.id)) continue;
    if (check.scope === 'global') {
      units.push({ check, region: GLOBAL_SCOPE });
    } else {
      for (const region of options.regions) units.push({ check, region });
    }
  }

  const findings: SecurityFinding[] = [];
  const checks: CheckStatus[] = [];
  const issues: EvaluationIssue[] = [];
  let completed = 0;

  await mapWithConcurrency(units, options.concurrency ?? 6, async (unit) => {
    // Stopping happens at a check boundary: no AWS call is started after this.
    if (options.shouldStop?.()) throw new JobCancelledError();
    const context: CheckContext = {
      access: options.access,
      profile: options.profile,
      ...(options.accountId ? { accountId: options.accountId } : {}),
      region: unit.region,
      config: options.config,
      section: `${section}:${unit.check.id}`,
    };
    const result = await unit.check.run(context);

    findings.push(...result.findings);
    issues.push(...result.issues);
    checks.push({
      checkId: unit.check.id,
      title: unit.check.title,
      service: unit.check.service,
      scope: unit.check.scope,
      region: unit.region,
      state: result.evaluated ? 'evaluated' : 'not-evaluated',
      findingCount: result.findings.length,
      ...(result.resourcesEvaluated !== undefined
        ? { resourcesEvaluated: result.resourcesEvaluated }
        : {}),
      ...(result.truncated ? { truncated: true } : {}),
      issues: result.issues,
    });

    completed += 1;
    if (options.onProgress) {
      // Snapshot what is known so far. The persisted statuses and the resolved
      // set are only merged at the end, so a partial view is explicitly marked
      // as still running by the caller rather than implying completeness.
      options.onProgress({
        completed,
        total: units.length,
        label: `${unit.check.title} (${unit.region})`,
        data: buildSecurityData([...findings], [], [...checks]),
        issues: [...issues],
      });
    }
  });

  for (const check of SECURITY_CHECKS) {
    if (!disabled.has(check.id)) continue;
    checks.push({
      checkId: check.id,
      title: check.title,
      service: check.service,
      scope: check.scope,
      region: check.scope === 'global' ? GLOBAL_SCOPE : options.regions.join(','),
      state: 'disabled',
      findingCount: 0,
      issues: [],
    });
  }

  // Merge persisted user decisions onto the freshly detected findings.
  for (const finding of findings) {
    const persisted = options.store.get(finding.id);
    if (!persisted) continue;
    finding.status = persisted.status === 'resolved' ? 'open' : persisted.status;
    finding.firstSeenAt = persisted.firstSeenAt;
    if (persisted.note) finding.note = persisted.note;
    if (persisted.updatedAt) finding.updatedAt = persisted.updatedAt;
  }

  await options.store.upsertSeen(findings.map(toPersisted));

  const seenIds = new Set(findings.map((finding) => finding.id));
  const resolved = await options.store.markResolved(seenIds, {
    profiles: new Set([options.profile]),
    regions: new Set(options.regions),
  });
  const resolvedFindings = resolved
    .filter((finding) => finding.profile === options.profile)
    .map(fromPersisted);

  const data = buildSecurityData(findings, resolvedFindings, checks);

  return {
    profile: options.profile,
    ...(options.accountId ? { accountId: options.accountId } : {}),
    status: issues.length === 0 ? 'ok' : 'partial',
    data,
    issues,
  };
}
