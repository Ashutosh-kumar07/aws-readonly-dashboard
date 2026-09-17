/**
 * Security check registry.
 *
 * Adding a check is a one-line change here plus a self-contained module in
 * `checks/`. Nothing else in the application needs to know about it.
 */

import { safeCheck } from './check-utils.js';
import type { SecurityCheck } from './types.js';

import { securityHubCheck } from './checks/security-hub.js';
import { guardDutyCheck } from './checks/guardduty.js';
import { inspectorCheck } from './checks/inspector.js';
import { accessAnalyzerCheck } from './checks/access-analyzer.js';
import { trustedAdvisorCheck } from './checks/trusted-advisor.js';
import { awsConfigCheck } from './checks/config.js';
import { cloudTrailConfigurationCheck } from './checks/cloudtrail.js';
import { s3PublicAccessCheck, s3AccountPublicAccessBlockCheck } from './checks/s3.js';
import { lambdaVpcCheck, lambdaPublicPolicyCheck } from './checks/lambda.js';
import { securityGroupCheck } from './checks/security-groups.js';
import { iamHygieneCheck } from './checks/iam.js';

export const SECURITY_CHECKS: readonly SecurityCheck[] = Object.freeze(
  [
    securityHubCheck,
    guardDutyCheck,
    inspectorCheck,
    accessAnalyzerCheck,
    trustedAdvisorCheck,
    awsConfigCheck,
    cloudTrailConfigurationCheck,
    s3AccountPublicAccessBlockCheck,
    s3PublicAccessCheck,
    lambdaVpcCheck,
    lambdaPublicPolicyCheck,
    securityGroupCheck,
    iamHygieneCheck,
  ].map(safeCheck)
);

export function checksForScope(scope: 'regional' | 'global'): SecurityCheck[] {
  return SECURITY_CHECKS.filter((check) => check.scope === scope);
}

export function describeChecks(): Array<{
  id: string;
  title: string;
  service: string;
  scope: string;
  description: string;
  requiredPermissions: string[];
}> {
  return SECURITY_CHECKS.map((check) => ({
    id: check.id,
    title: check.title,
    service: check.service,
    scope: check.scope,
    description: check.description,
    requiredPermissions: [...check.requiredPermissions],
  }));
}
