/** Security analyzer contracts. Each check is an independent, testable unit. */

import { createHash } from 'node:crypto';

import type { AwsAccessLayer } from '../../aws/access-layer.js';
import type { AppConfig, FindingStatus } from '../../config/schema.js';
import type { EvaluationIssue } from '../types.js';

export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Readonly<Record<Severity, number>> = Object.freeze({
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
});

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}

export interface SecurityFinding {
  /** Stable fingerprint; identical across runs for the same underlying issue. */
  id: string;
  checkId: string;
  title: string;
  severity: Severity;
  profile: string;
  accountId?: string;
  /** AWS region, or `global` for non-regional resources. */
  region: string;
  resourceType: string;
  resourceId: string;
  resourceArn?: string;
  /** Source system: a native check name, or the AWS security service. */
  source: string;
  /** Structured evidence taken verbatim from the AWS response. */
  evidence: Record<string, unknown>;
  /** Why this matters, in plain language. */
  why: string;
  /** What a human could do in AWS. The application never performs it. */
  recommendation: string;
  status: FindingStatus;
  firstSeenAt: string;
  lastSeenAt: string;
  updatedAt?: string;
  note?: string;
  /** True when the finding was not seen in the latest scan. */
  stale?: boolean;
}

export interface CheckContext {
  access: AwsAccessLayer;
  profile: string;
  accountId?: string;
  /** `global` for non-regional checks. */
  region: string;
  config: AppConfig;
  /** Section label used for API-call accounting. */
  section: string;
}

export interface CheckResult {
  findings: SecurityFinding[];
  issues: EvaluationIssue[];
  /** False when the check could not be completed (permissions, service off, …). */
  evaluated: boolean;
  resourcesEvaluated?: number;
  /** Set when the check intentionally examined only part of the inventory. */
  truncated?: boolean;
}

export interface SecurityCheck {
  id: string;
  title: string;
  /** AWS service the check inspects, used for grouping in the UI. */
  service: string;
  scope: 'regional' | 'global';
  description: string;
  requiredPermissions: string[];
  run(context: CheckContext): Promise<CheckResult>;
}

/** Deterministic fingerprint so a finding keeps its status across scans. */
export function fingerprint(parts: {
  profile: string;
  region: string;
  checkId: string;
  resourceId: string;
  discriminator?: string;
}): string {
  const input = [
    parts.profile,
    parts.region,
    parts.checkId,
    parts.resourceId,
    parts.discriminator ?? '',
  ].join('|');
  return createHash('sha256').update(input).digest('hex').slice(0, 24);
}

export interface BuildFindingInput {
  context: CheckContext;
  checkId: string;
  title: string;
  severity: Severity;
  resourceType: string;
  resourceId: string;
  resourceArn?: string;
  region?: string;
  source: string;
  evidence: Record<string, unknown>;
  why: string;
  recommendation: string;
  discriminator?: string;
}

export function buildFinding(input: BuildFindingInput): SecurityFinding {
  const now = new Date().toISOString();
  const region = input.region ?? input.context.region;
  return {
    id: fingerprint({
      profile: input.context.profile,
      region,
      checkId: input.checkId,
      resourceId: input.resourceId,
      ...(input.discriminator ? { discriminator: input.discriminator } : {}),
    }),
    checkId: input.checkId,
    title: input.title,
    severity: input.severity,
    profile: input.context.profile,
    ...(input.context.accountId ? { accountId: input.context.accountId } : {}),
    region,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    ...(input.resourceArn ? { resourceArn: input.resourceArn } : {}),
    source: input.source,
    evidence: input.evidence,
    why: input.why,
    recommendation: input.recommendation,
    status: 'open',
    firstSeenAt: now,
    lastSeenAt: now,
  };
}
