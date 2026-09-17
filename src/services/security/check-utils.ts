/** Helpers shared by the individual security checks. */

import { classifyAwsError, ERROR_KIND_LABEL } from '../../util/errors.js';
import { issueFromError, type EvaluationIssue } from '../types.js';
import type { CheckContext, CheckResult, SecurityCheck } from './types.js';

export function issueFor(
  context: CheckContext,
  error: unknown,
  options: { service: string; check: string; requiredPermission?: string; detail?: string }
): EvaluationIssue {
  const classified = classifyAwsError(error);
  const label = options.detail
    ? `${ERROR_KIND_LABEL[classified.kind]} (${options.detail})`
    : ERROR_KIND_LABEL[classified.kind];
  return issueFromError(
    classified,
    {
      profile: context.profile,
      ...(context.accountId ? { accountId: context.accountId } : {}),
      region: context.region,
      service: options.service,
      check: options.check,
      ...(options.requiredPermission ? { requiredPermission: options.requiredPermission } : {}),
    },
    label
  );
}

/** A check result meaning "nothing to report and the check actually ran". */
export function evaluated(result: Partial<CheckResult> = {}): CheckResult {
  return { findings: [], issues: [], evaluated: true, ...result };
}

/** A check result meaning "this could not be evaluated"; never reported as secure. */
export function notEvaluated(
  issues: EvaluationIssue[],
  findings: CheckResult['findings'] = []
): CheckResult {
  return { findings, issues, evaluated: false };
}

/**
 * Wraps a check so an unexpected exception degrades to "unable to evaluate"
 * rather than taking down the whole security scan.
 */
export function safeCheck(check: SecurityCheck): SecurityCheck {
  return {
    ...check,
    async run(context: CheckContext): Promise<CheckResult> {
      try {
        return await check.run(context);
      } catch (error) {
        return notEvaluated([
          issueFor(context, error, {
            service: check.service,
            check: check.id,
            ...(check.requiredPermissions[0]
              ? { requiredPermission: check.requiredPermissions[0] }
              : {}),
          }),
        ]);
      }
    },
  };
}

/** Normalises a numeric GuardDuty/Inspector severity onto the shared scale. */
export function numericSeverity(value: number | undefined): 'critical' | 'high' | 'medium' | 'low' {
  const score = value ?? 0;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/** Normalises an AWS severity label onto the shared scale. */
export function labelSeverity(label: string | undefined): 'critical' | 'high' | 'medium' | 'low' {
  switch ((label ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
    case 'INFORMATIONAL':
      return 'low';
    default:
      return 'medium';
  }
}

export function truncateText(value: string | undefined, max = 400): string {
  if (!value) return '';
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}
