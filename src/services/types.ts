/** Types shared by the dashboard's application services. */

import type { AwsErrorKind, ClassifiedAwsError } from '../util/errors.js';
import type { ApiCategory } from '../aws/allowlist.js';

export const SECTION_IDS = [
  'billing',
  'security',
  'compute-optimizer',
  'cloudwatch',
  'cloudtrail',
] as const;

export type SectionId = (typeof SECTION_IDS)[number];

export function isSectionId(value: string): value is SectionId {
  return (SECTION_IDS as readonly string[]).includes(value);
}

/**
 * A single "we could not evaluate this" record. The dashboard renders these
 * distinctly from "no findings" so a permission gap is never displayed as a
 * clean bill of health.
 */
export interface EvaluationIssue {
  profile: string;
  accountId?: string;
  region: string;
  /** AWS service or analyzer the issue belongs to. */
  service: string;
  /** Check identifier when the issue came from a specific security check. */
  check?: string;
  kind: AwsErrorKind;
  label: string;
  message: string;
  missingPermission?: string;
  requiredPermission?: string;
  /**
   * An offer the dashboard can act on directly, such as raising a scan limit
   * that stopped a check short. Naming the setting is not much use if acting on
   * it means hunting through Settings.
   */
  suggestion?: {
    /** Key within `security` configuration. */
    setting: 'maxLambdaPolicyLookupsPerRegion' | 'maxBucketsPerScan';
    /** Value to store when the offer is accepted. 0 means "no limit". */
    value: number;
    /** Button text, e.g. "Inspect all 529 functions". */
    label: string;
  };
}

export function issueFromError(
  error: ClassifiedAwsError,
  scope: {
    profile: string;
    accountId?: string;
    region: string;
    service: string;
    check?: string;
    requiredPermission?: string;
  },
  label: string
): EvaluationIssue {
  return {
    profile: scope.profile,
    ...(scope.accountId ? { accountId: scope.accountId } : {}),
    region: scope.region,
    service: scope.service,
    ...(scope.check ? { check: scope.check } : {}),
    kind: error.kind,
    label,
    message: error.message,
    // "needs <action>" is only shown when the failure really is a permission
    // problem. A timeout or a region mismatch on a call that *would* need
    // `s3:GetBucketLocation` is not evidence that the permission is missing,
    // and saying so sends people to edit a policy that is already correct.
    // `requiredPermission` still travels with the issue as the check's
    // declared need.
    ...(error.missingPermission
      ? { missingPermission: error.missingPermission }
      : scope.requiredPermission && error.kind === 'access-denied'
        ? { missingPermission: scope.requiredPermission }
        : {}),
    ...(scope.requiredPermission ? { requiredPermission: scope.requiredPermission } : {}),
  };
}

/** Per-profile envelope so profile/account context is never lost. */
export interface ProfileScoped<T> {
  profile: string;
  accountId?: string;
  arn?: string;
  status: 'ok' | 'partial' | 'failed';
  data?: T;
  issues: EvaluationIssue[];
}

export interface SectionResult<T> {
  section: SectionId;
  fetchedAt: string;
  profiles: Array<ProfileScoped<T>>;
  regions: string[];
  /** AWS API categories touched while producing this result. */
  categories: ApiCategory[];
}

export interface Selection {
  profiles: string[];
  regions: string[];
}

/** Stable key for an in-memory section cache entry. */
export function selectionKey(section: SectionId, selection: Selection, suffix = ''): string {
  const profiles = [...selection.profiles].sort().join(',');
  const regions = [...selection.regions].sort().join(',');
  return `${section}|${profiles}|${regions}|${suffix}`;
}
