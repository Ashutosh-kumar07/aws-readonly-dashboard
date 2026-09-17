/**
 * The AWS read-only allowlist.
 *
 * This module is the single source of truth for which AWS API operations this
 * application is permitted to invoke. It is a compile-time constant that is
 * deep-frozen at module load. It is never read from disk, never merged with
 * user configuration, and never mutated at runtime.
 *
 * User configuration can only ever *narrow* what is reachable (by disabling a
 * category); it can never widen it. Any operation that is not listed here is
 * refused by `src/aws/readonly-guard.ts` before an AWS request is constructed.
 */

/** Stable category identifiers used for API-call accounting and UI grouping. */
export const API_CATEGORIES = [
  'billing',
  'security-hub',
  'guardduty',
  'inspector',
  'iam',
  'access-analyzer',
  'trusted-advisor',
  'config',
  's3',
  'lambda',
  'security-groups',
  'cloudwatch',
  'cloudtrail',
  'compute-optimizer',
  'ec2',
  'identity',
] as const;

export type ApiCategory = (typeof API_CATEGORIES)[number];

export const API_CATEGORY_LABELS: Readonly<Record<ApiCategory, string>> = Object.freeze({
  billing: 'Billing / Cost Explorer',
  'security-hub': 'Security Hub',
  guardduty: 'GuardDuty',
  inspector: 'Inspector',
  iam: 'IAM',
  'access-analyzer': 'IAM Access Analyzer',
  'trusted-advisor': 'Trusted Advisor',
  config: 'AWS Config',
  s3: 'S3',
  lambda: 'Lambda',
  'security-groups': 'Security Groups',
  cloudwatch: 'CloudWatch',
  cloudtrail: 'CloudTrail',
  'compute-optimizer': 'Compute Optimizer',
  ec2: 'EC2',
  identity: 'Account / Identity',
});

/** SDK client keys this application knows how to construct. */
export const SERVICE_KEYS = [
  'sts',
  'iam',
  'cost-explorer',
  'securityhub',
  'guardduty',
  'inspector2',
  'accessanalyzer',
  'support',
  'config-service',
  'cloudtrail',
  's3',
  's3-control',
  'lambda',
  'ec2',
  'cloudwatch-logs',
  'cloudwatch',
  'compute-optimizer',
] as const;

export type ServiceKey = (typeof SERVICE_KEYS)[number];

export interface AllowedOperation {
  /** The AWS API operation name, e.g. `DescribeSecurityGroups`. */
  operation: string;
  /** Accounting/UI category the call is attributed to. */
  category: ApiCategory;
  /** IAM action required, used for permission documentation and error hints. */
  iamAction: string;
  /** True when the API is only available from a global endpoint. */
  global?: boolean;
}

type ServiceAllowlist = Readonly<Record<ServiceKey, readonly AllowedOperation[]>>;

const RAW_ALLOWLIST: ServiceAllowlist = {
  sts: [
    { operation: 'GetCallerIdentity', category: 'identity', iamAction: 'sts:GetCallerIdentity' },
  ],

  iam: [
    {
      operation: 'GetAccountSummary',
      category: 'iam',
      iamAction: 'iam:GetAccountSummary',
      global: true,
    },
    {
      operation: 'GetAccountPasswordPolicy',
      category: 'iam',
      iamAction: 'iam:GetAccountPasswordPolicy',
      global: true,
    },
    { operation: 'ListUsers', category: 'iam', iamAction: 'iam:ListUsers', global: true },
    { operation: 'ListAccessKeys', category: 'iam', iamAction: 'iam:ListAccessKeys', global: true },
    { operation: 'ListMFADevices', category: 'iam', iamAction: 'iam:ListMFADevices', global: true },
    {
      operation: 'ListAttachedUserPolicies',
      category: 'iam',
      iamAction: 'iam:ListAttachedUserPolicies',
      global: true,
    },
    {
      operation: 'ListUserPolicies',
      category: 'iam',
      iamAction: 'iam:ListUserPolicies',
      global: true,
    },
    { operation: 'ListRoles', category: 'iam', iamAction: 'iam:ListRoles', global: true },
    {
      operation: 'GetAccessKeyLastUsed',
      category: 'iam',
      iamAction: 'iam:GetAccessKeyLastUsed',
      global: true,
    },
  ],

  'cost-explorer': [
    {
      operation: 'GetCostAndUsage',
      category: 'billing',
      iamAction: 'ce:GetCostAndUsage',
      global: true,
    },
    {
      operation: 'GetDimensionValues',
      category: 'billing',
      iamAction: 'ce:GetDimensionValues',
      global: true,
    },
    {
      operation: 'GetCostCategories',
      category: 'billing',
      iamAction: 'ce:GetCostCategories',
      global: true,
    },
    { operation: 'GetTags', category: 'billing', iamAction: 'ce:GetTags', global: true },
  ],

  securityhub: [
    { operation: 'DescribeHub', category: 'security-hub', iamAction: 'securityhub:DescribeHub' },
    { operation: 'GetFindings', category: 'security-hub', iamAction: 'securityhub:GetFindings' },
    {
      operation: 'GetEnabledStandards',
      category: 'security-hub',
      iamAction: 'securityhub:GetEnabledStandards',
    },
  ],

  guardduty: [
    { operation: 'ListDetectors', category: 'guardduty', iamAction: 'guardduty:ListDetectors' },
    { operation: 'GetDetector', category: 'guardduty', iamAction: 'guardduty:GetDetector' },
    { operation: 'ListFindings', category: 'guardduty', iamAction: 'guardduty:ListFindings' },
    { operation: 'GetFindings', category: 'guardduty', iamAction: 'guardduty:GetFindings' },
  ],

  inspector2: [
    {
      operation: 'BatchGetAccountStatus',
      category: 'inspector',
      iamAction: 'inspector2:BatchGetAccountStatus',
    },
    { operation: 'ListFindings', category: 'inspector', iamAction: 'inspector2:ListFindings' },
    { operation: 'ListCoverage', category: 'inspector', iamAction: 'inspector2:ListCoverage' },
  ],

  accessanalyzer: [
    {
      operation: 'ListAnalyzers',
      category: 'access-analyzer',
      iamAction: 'access-analyzer:ListAnalyzers',
    },
    {
      operation: 'ListFindings',
      category: 'access-analyzer',
      iamAction: 'access-analyzer:ListFindings',
    },
    {
      operation: 'ListFindingsV2',
      category: 'access-analyzer',
      iamAction: 'access-analyzer:ListFindingsV2',
    },
    {
      operation: 'GetFinding',
      category: 'access-analyzer',
      iamAction: 'access-analyzer:GetFinding',
    },
  ],

  support: [
    {
      operation: 'DescribeTrustedAdvisorChecks',
      category: 'trusted-advisor',
      iamAction: 'support:DescribeTrustedAdvisorChecks',
      global: true,
    },
    {
      operation: 'DescribeTrustedAdvisorCheckResult',
      category: 'trusted-advisor',
      iamAction: 'support:DescribeTrustedAdvisorCheckResult',
      global: true,
    },
    {
      operation: 'DescribeTrustedAdvisorCheckSummaries',
      category: 'trusted-advisor',
      iamAction: 'support:DescribeTrustedAdvisorCheckSummaries',
      global: true,
    },
  ],

  'config-service': [
    {
      operation: 'DescribeConfigurationRecorders',
      category: 'config',
      iamAction: 'config:DescribeConfigurationRecorders',
    },
    {
      operation: 'DescribeConfigurationRecorderStatus',
      category: 'config',
      iamAction: 'config:DescribeConfigurationRecorderStatus',
    },
    {
      operation: 'DescribeConfigRules',
      category: 'config',
      iamAction: 'config:DescribeConfigRules',
    },
    {
      operation: 'DescribeComplianceByConfigRule',
      category: 'config',
      iamAction: 'config:DescribeComplianceByConfigRule',
    },
    {
      operation: 'DescribeDeliveryChannels',
      category: 'config',
      iamAction: 'config:DescribeDeliveryChannels',
    },
    {
      operation: 'GetComplianceDetailsByConfigRule',
      category: 'config',
      iamAction: 'config:GetComplianceDetailsByConfigRule',
    },
  ],

  cloudtrail: [
    { operation: 'LookupEvents', category: 'cloudtrail', iamAction: 'cloudtrail:LookupEvents' },
    { operation: 'DescribeTrails', category: 'cloudtrail', iamAction: 'cloudtrail:DescribeTrails' },
    { operation: 'ListTrails', category: 'cloudtrail', iamAction: 'cloudtrail:ListTrails' },
    { operation: 'GetTrailStatus', category: 'cloudtrail', iamAction: 'cloudtrail:GetTrailStatus' },
    {
      operation: 'GetEventSelectors',
      category: 'cloudtrail',
      iamAction: 'cloudtrail:GetEventSelectors',
    },
  ],

  s3: [
    { operation: 'ListBuckets', category: 's3', iamAction: 's3:ListAllMyBuckets', global: true },
    { operation: 'GetBucketLocation', category: 's3', iamAction: 's3:GetBucketLocation' },
    { operation: 'GetBucketPolicyStatus', category: 's3', iamAction: 's3:GetBucketPolicyStatus' },
    {
      operation: 'GetPublicAccessBlock',
      category: 's3',
      iamAction: 's3:GetBucketPublicAccessBlock',
    },
    { operation: 'GetBucketAcl', category: 's3', iamAction: 's3:GetBucketAcl' },
    {
      operation: 'GetBucketEncryption',
      category: 's3',
      iamAction: 's3:GetEncryptionConfiguration',
    },
    { operation: 'GetBucketVersioning', category: 's3', iamAction: 's3:GetBucketVersioning' },
    { operation: 'GetBucketLogging', category: 's3', iamAction: 's3:GetBucketLogging' },
  ],

  's3-control': [
    {
      operation: 'GetPublicAccessBlock',
      category: 's3',
      iamAction: 's3:GetAccountPublicAccessBlock',
      global: true,
    },
  ],

  lambda: [
    { operation: 'ListFunctions', category: 'lambda', iamAction: 'lambda:ListFunctions' },
    {
      operation: 'GetFunctionConfiguration',
      category: 'lambda',
      iamAction: 'lambda:GetFunctionConfiguration',
    },
    { operation: 'GetPolicy', category: 'lambda', iamAction: 'lambda:GetPolicy' },
    {
      operation: 'ListFunctionUrlConfigs',
      category: 'lambda',
      iamAction: 'lambda:ListFunctionUrlConfigs',
    },
  ],

  ec2: [
    { operation: 'DescribeRegions', category: 'ec2', iamAction: 'ec2:DescribeRegions' },
    {
      operation: 'DescribeSecurityGroups',
      category: 'security-groups',
      iamAction: 'ec2:DescribeSecurityGroups',
    },
    {
      operation: 'DescribeSecurityGroupRules',
      category: 'security-groups',
      iamAction: 'ec2:DescribeSecurityGroupRules',
    },
    {
      operation: 'DescribeNetworkInterfaces',
      category: 'security-groups',
      iamAction: 'ec2:DescribeNetworkInterfaces',
    },
    { operation: 'DescribeVpcs', category: 'ec2', iamAction: 'ec2:DescribeVpcs' },
  ],

  'cloudwatch-logs': [
    { operation: 'DescribeLogGroups', category: 'cloudwatch', iamAction: 'logs:DescribeLogGroups' },
    {
      operation: 'DescribeLogStreams',
      category: 'cloudwatch',
      iamAction: 'logs:DescribeLogStreams',
    },
    {
      operation: 'ListTagsForResource',
      category: 'cloudwatch',
      iamAction: 'logs:ListTagsForResource',
    },
  ],

  cloudwatch: [
    { operation: 'GetMetricData', category: 'cloudwatch', iamAction: 'cloudwatch:GetMetricData' },
    {
      operation: 'GetMetricStatistics',
      category: 'cloudwatch',
      iamAction: 'cloudwatch:GetMetricStatistics',
    },
    { operation: 'ListMetrics', category: 'cloudwatch', iamAction: 'cloudwatch:ListMetrics' },
  ],

  'compute-optimizer': [
    {
      operation: 'GetEnrollmentStatus',
      category: 'compute-optimizer',
      iamAction: 'compute-optimizer:GetEnrollmentStatus',
    },
    {
      operation: 'GetRecommendationSummaries',
      category: 'compute-optimizer',
      iamAction: 'compute-optimizer:GetRecommendationSummaries',
    },
    {
      operation: 'GetEC2InstanceRecommendations',
      category: 'compute-optimizer',
      iamAction: 'compute-optimizer:GetEC2InstanceRecommendations',
    },
    {
      operation: 'GetAutoScalingGroupRecommendations',
      category: 'compute-optimizer',
      iamAction: 'compute-optimizer:GetAutoScalingGroupRecommendations',
    },
    {
      operation: 'GetEBSVolumeRecommendations',
      category: 'compute-optimizer',
      iamAction: 'compute-optimizer:GetEBSVolumeRecommendations',
    },
    {
      operation: 'GetLambdaFunctionRecommendations',
      category: 'compute-optimizer',
      iamAction: 'compute-optimizer:GetLambdaFunctionRecommendations',
    },
    {
      operation: 'GetECSServiceRecommendations',
      category: 'compute-optimizer',
      iamAction: 'compute-optimizer:GetECSServiceRecommendations',
    },
    {
      operation: 'GetRDSDatabaseRecommendations',
      category: 'compute-optimizer',
      iamAction: 'compute-optimizer:GetRDSDatabaseRecommendations',
    },
    {
      operation: 'GetIdleRecommendations',
      category: 'compute-optimizer',
      iamAction: 'compute-optimizer:GetIdleRecommendations',
    },
  ],
};

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

/** The frozen allowlist. Mutating it is impossible in both strict and sloppy mode. */
export const ALLOWLIST: ServiceAllowlist = deepFreeze(RAW_ALLOWLIST);

const INDEX: ReadonlyMap<string, AllowedOperation> = (() => {
  const index = new Map<string, AllowedOperation>();
  for (const service of SERVICE_KEYS) {
    for (const entry of ALLOWLIST[service]) index.set(`${service}:${entry.operation}`, entry);
  }
  return index;
})();

export function lookupAllowedOperation(
  service: ServiceKey | string,
  operation: string
): AllowedOperation | undefined {
  return INDEX.get(`${service}:${operation}`);
}

export function isServiceKey(value: string): value is ServiceKey {
  return (SERVICE_KEYS as readonly string[]).includes(value);
}

/** Every allowlisted operation, flattened — used by docs, tests, and the UI. */
export function allAllowedOperations(): Array<AllowedOperation & { service: ServiceKey }> {
  return SERVICE_KEYS.flatMap((service) =>
    ALLOWLIST[service].map((entry) => ({ ...entry, service }))
  );
}

/** Distinct IAM actions required by the full allowlist (least-privilege reference). */
export function requiredIamActions(): string[] {
  return [...new Set(allAllowedOperations().map((entry) => entry.iamAction))].sort();
}
