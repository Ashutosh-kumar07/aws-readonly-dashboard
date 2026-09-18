/**
 * Local configuration schema, defaults and migrations.
 *
 * Only user preferences live here. Raw AWS data is never written to disk; see
 * `src/services/data-store.ts` for the in-memory AWS data lifecycle.
 */

import type { ApiCategory } from '../aws/allowlist.js';

export const CONFIG_VERSION = 2;

export const COMPARISON_PERIODS = [1, 7, 14, 30, 60, 90] as const;
export type ComparisonPeriod = (typeof COMPARISON_PERIODS)[number];

export type SanitizationStrategy = 'redact' | 'pseudonymize' | 'partial';

export interface SanitizationRule {
  id: string;
  label: string;
  strategy: SanitizationStrategy;
  enabled: boolean;
  /** Built-in rules cannot be edited, only disabled (unless locked). */
  builtin: boolean;
  /**
   * Locked rules protect credential material. They can never be disabled —
   * secrets are not a privacy preference.
   */
  locked?: boolean;
  /** Custom rules carry their own regular expression source. */
  pattern?: string;
  flags?: string;
  /** Replacement label used for redaction, e.g. `EMAIL`. */
  placeholder?: string;
  description?: string;
}

export interface CustomProviderHeader {
  key: string;
  value: string;
}

export interface CustomLlmConfig {
  enabled: boolean;
  name: string;
  endpoint: string;
  method: 'POST' | 'PUT' | 'GET';
  headers: CustomProviderHeader[];
  /**
   * Request body template. `{{prompt}}` and `{{payload}}` placeholders are
   * substituted with the sanitized prompt and the sanitized JSON payload.
   */
  bodyTemplate: string;
  /** Dot path into the JSON response holding the model text, e.g. `choices.0.message.content`. */
  responsePath: string;
  timeoutMs: number;
  /** Set once the user has acknowledged that data leaves the machine. */
  acknowledgedDataEgress: boolean;
}

export interface GeminiConfig {
  command: string;
  args: string[];
  model?: string;
  timeoutMs: number;
  /** How long the startup capability probe may take. CLIs can be slow to boot. */
  probeTimeoutMs: number;
}

export interface AiHistoryConfig {
  enabled: boolean;
  retentionDays: number;
  /** Include retained history in future AI requests. */
  includeInRequests: boolean;
}

export interface AiConfig {
  provider: 'gemini' | 'custom';
  gemini: GeminiConfig;
  custom: CustomLlmConfig;
  history: AiHistoryConfig;
  sanitization: {
    rules: SanitizationRule[];
  };
}

export interface BillingConfig {
  comparisonDays: ComparisonPeriod;
  dollarThreshold: number;
  percentThreshold: number;
  /** Cost metric requested from Cost Explorer. */
  metric: 'UnblendedCost' | 'AmortizedCost' | 'NetUnblendedCost' | 'BlendedCost';
  includeCredits: boolean;
}

export interface CloudWatchConfig {
  growthPercentThreshold: number;
  growthBytesThreshold: number;
  longRetentionDays: number;
  /** How many log groups to inspect per region, largest first. */
  maxLogGroupsPerRegion: number;
  /** Window, in days, over which growth is measured. */
  growthWindowDays: number;
}

export interface CloudTrailConfig {
  pageSize: number;
  maxEventsPerSearch: number;
  defaultLookbackHours: number;
}

export type FindingStatus = 'open' | 'acknowledged' | 'ignored' | 'resolved';

export interface SecurityConfig {
  /** Check identifiers the user switched off. */
  disabledChecks: string[];
  severityFilter: Array<'critical' | 'high' | 'medium' | 'low'>;
  /**
   * How many Lambda functions per region the resource-policy check may inspect.
   * Each function costs one `lambda:GetPolicy` call, so this trades AWS API
   * volume against coverage. 0 means no limit — every function is inspected.
   * To switch the check off, disable `lambda-public-resource-policy` in
   * `disabledChecks`. The VPC check always covers every function regardless.
   */
  maxLambdaPolicyLookupsPerRegion: number;
  /**
   * How many S3 buckets a scan may inspect. Each bucket costs up to five
   * read calls.
   */
  maxBucketsPerScan: number;
}

export interface UiConfig {
  theme: 'system' | 'light' | 'dark';
  defaultSection: string;
  autoOpenBrowser: boolean;
}

export interface AppConfig {
  version: number;
  profiles: { selected: string[] };
  regions: { selected: string[] };
  billing: BillingConfig;
  cloudwatch: CloudWatchConfig;
  cloudtrail: CloudTrailConfig;
  security: SecurityConfig;
  ai: AiConfig;
  ui: UiConfig;
  /** API categories the user disabled. Narrows the allowlist; never widens it. */
  disabledApiCategories: ApiCategory[];
}

export const DEFAULT_SANITIZATION_RULES: readonly SanitizationRule[] = Object.freeze([
  {
    id: 'aws-credentials',
    label: 'AWS access keys and secrets',
    strategy: 'redact',
    enabled: true,
    builtin: true,
    locked: true,
    placeholder: 'CREDENTIAL',
    description:
      'Credential material is never sent to any AI provider. This rule cannot be disabled.',
  },
  {
    id: 'email',
    label: 'Email addresses',
    strategy: 'redact',
    enabled: true,
    builtin: true,
    placeholder: 'EMAIL',
    description: 'Addresses such as alice@example.com are replaced with <EMAIL>.',
  },
  {
    id: 'ip-address',
    label: 'IP addresses',
    strategy: 'redact',
    enabled: true,
    builtin: true,
    placeholder: 'IP',
    description:
      'IPv4 and IPv6 addresses are replaced with <IP>. 0.0.0.0/0 is preserved because it is a policy value, not an identifier.',
  },
  {
    id: 'aws-account-id',
    label: 'AWS account IDs',
    strategy: 'pseudonymize',
    enabled: true,
    builtin: true,
    placeholder: 'ACCOUNT',
    description: '12-digit account IDs become stable placeholders such as <ACCOUNT_1>.',
  },
  {
    id: 'iam-username',
    label: 'IAM user names',
    strategy: 'pseudonymize',
    enabled: true,
    builtin: true,
    placeholder: 'USER',
    description: 'IAM user names become <USER_1>, <USER_2>, … consistently within one request.',
  },
  {
    id: 'iam-role',
    label: 'IAM role names',
    strategy: 'pseudonymize',
    enabled: true,
    builtin: true,
    placeholder: 'ROLE',
    description: 'IAM role names become <ROLE_1>, <ROLE_2>, … consistently within one request.',
  },
  {
    id: 'arn',
    label: 'ARNs',
    strategy: 'partial',
    enabled: true,
    builtin: true,
    placeholder: 'ARN',
    description:
      'ARNs keep their service and resource type but lose the account ID and resource name.',
  },
  {
    id: 'hostname',
    label: 'Hostnames and DNS names',
    strategy: 'redact',
    enabled: true,
    builtin: true,
    placeholder: 'HOST',
    description: 'Fully-qualified host names are replaced with <HOST>.',
  },
  {
    id: 'resource-identifier',
    label: 'Instance, volume and ENI identifiers',
    strategy: 'pseudonymize',
    enabled: true,
    builtin: true,
    placeholder: 'RESOURCE',
    description: 'Identifiers such as i-0abc… and vol-0abc… become stable placeholders.',
  },
]);

export function defaultConfig(): AppConfig {
  return {
    version: CONFIG_VERSION,
    profiles: { selected: [] },
    regions: { selected: ['us-east-1'] },
    billing: {
      comparisonDays: 7,
      dollarThreshold: 20,
      percentThreshold: 10,
      metric: 'UnblendedCost',
      includeCredits: false,
    },
    cloudwatch: {
      growthPercentThreshold: 5,
      growthBytesThreshold: 2 * 1024 * 1024 * 1024,
      longRetentionDays: 90,
      maxLogGroupsPerRegion: 200,
      growthWindowDays: 7,
    },
    cloudtrail: {
      pageSize: 50,
      maxEventsPerSearch: 2000,
      defaultLookbackHours: 24,
    },
    security: {
      disabledChecks: [],
      severityFilter: ['critical', 'high', 'medium', 'low'],
      maxLambdaPolicyLookupsPerRegion: 100,
      maxBucketsPerScan: 250,
    },
    ai: {
      provider: 'gemini',
      gemini: {
        command: 'gemini',
        args: [],
        timeoutMs: 120_000,
        probeTimeoutMs: 20_000,
      },
      custom: {
        enabled: false,
        name: 'Custom LLM',
        endpoint: '',
        method: 'POST',
        headers: [{ key: 'Content-Type', value: 'application/json' }],
        bodyTemplate: '{\n  "prompt": {{prompt}},\n  "data": {{payload}}\n}',
        responsePath: '',
        timeoutMs: 120_000,
        acknowledgedDataEgress: false,
      },
      history: {
        enabled: false,
        retentionDays: 7,
        includeInRequests: true,
      },
      sanitization: {
        rules: DEFAULT_SANITIZATION_RULES.map((rule) => ({ ...rule })),
      },
    },
    ui: {
      theme: 'system',
      defaultSection: 'overview',
      autoOpenBrowser: true,
    },
    disabledApiCategories: [],
  };
}

export const MAX_AI_HISTORY_RETENTION_DAYS = 30;

type Migration = (config: Record<string, any>) => Record<string, any>;

/**
 * Migrations are applied in order for every version below `CONFIG_VERSION`.
 * Index 0 migrates a version-0 (pre-versioning) document to version 1.
 */
export const MIGRATIONS: readonly Migration[] = Object.freeze([
  (config) => ({ ...config, version: 1 }),
  // Version 2 redefines a Lambda lookup limit of 0 as "inspect every
  // function". A stored 0 meant "switch the check off", so that intent is
  // carried over to the check list, which is where switching a check off
  // belongs, rather than being silently turned into a full scan.
  (config) => {
    const security = { ...((config.security as Record<string, any>) ?? {}) };
    if (security.maxLambdaPolicyLookupsPerRegion === 0) {
      const disabled = new Set<string>(
        Array.isArray(security.disabledChecks) ? security.disabledChecks : []
      );
      disabled.add('lambda-public-resource-policy');
      security.disabledChecks = [...disabled];
      security.maxLambdaPolicyLookupsPerRegion = 100;
    }
    return { ...config, security, version: 2 };
  },
]);

function clamp(value: unknown, min: number, max: number, fallback: number): number {
  const numeric = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(max, Math.max(min, numeric));
}

function asStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter((item): item is string => typeof item === 'string');
}

function normaliseRule(raw: any, index: number): SanitizationRule | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const id = typeof raw.id === 'string' && raw.id.trim() ? raw.id.trim() : `custom-${index}`;
  const builtinDefault = DEFAULT_SANITIZATION_RULES.find((rule) => rule.id === id);
  const strategy: SanitizationStrategy = ['redact', 'pseudonymize', 'partial'].includes(
    raw.strategy
  )
    ? raw.strategy
    : (builtinDefault?.strategy ?? 'redact');

  if (builtinDefault) {
    return {
      ...builtinDefault,
      // A locked rule stays enabled no matter what the file says.
      enabled: builtinDefault.locked ? true : raw.enabled !== false,
      strategy,
    };
  }

  if (typeof raw.pattern !== 'string' || !raw.pattern.trim()) return undefined;
  try {
    // Validate the pattern here so a malformed rule can never reach the sanitizer.
    new RegExp(raw.pattern, typeof raw.flags === 'string' ? raw.flags : 'g');
  } catch {
    return undefined;
  }

  return {
    id,
    label: typeof raw.label === 'string' && raw.label ? raw.label : id,
    strategy,
    enabled: raw.enabled !== false,
    builtin: false,
    pattern: raw.pattern,
    flags: typeof raw.flags === 'string' ? raw.flags : 'g',
    placeholder:
      typeof raw.placeholder === 'string' && raw.placeholder
        ? raw.placeholder.replace(/[^A-Za-z0-9_]/g, '').toUpperCase() || 'CUSTOM'
        : 'CUSTOM',
    ...(typeof raw.description === 'string' ? { description: raw.description } : {}),
  };
}

/**
 * Coerces an arbitrary (possibly hand-edited) document into a valid config.
 * Unknown keys are dropped, out-of-range numbers are clamped, and locked
 * sanitization rules are restored.
 */
export function normaliseConfig(raw: unknown): AppConfig {
  const base = defaultConfig();
  if (!raw || typeof raw !== 'object') return base;
  const input = raw as Record<string, any>;

  const selectedProfiles = asStringArray(input.profiles?.selected) ?? base.profiles.selected;
  const selectedRegions = asStringArray(input.regions?.selected) ?? base.regions.selected;

  const comparisonDays = COMPARISON_PERIODS.includes(input.billing?.comparisonDays)
    ? (input.billing.comparisonDays as ComparisonPeriod)
    : base.billing.comparisonDays;

  const rules: SanitizationRule[] = [];
  const seenRuleIds = new Set<string>();
  const rawRules = Array.isArray(input.ai?.sanitization?.rules) ? input.ai.sanitization.rules : [];
  rawRules.forEach((rule: unknown, index: number) => {
    const normalised = normaliseRule(rule, index);
    if (normalised && !seenRuleIds.has(normalised.id)) {
      seenRuleIds.add(normalised.id);
      rules.push(normalised);
    }
  });
  // Locked rules are always present, even if the file removed them.
  for (const rule of DEFAULT_SANITIZATION_RULES) {
    if (rule.locked && !seenRuleIds.has(rule.id)) {
      rules.unshift({ ...rule });
      seenRuleIds.add(rule.id);
    }
  }

  const customHeaders: CustomProviderHeader[] = Array.isArray(input.ai?.custom?.headers)
    ? input.ai.custom.headers
        .filter((header: any) => header && typeof header.key === 'string' && header.key.trim())
        .map((header: any) => ({ key: String(header.key), value: String(header.value ?? '') }))
    : base.ai.custom.headers;

  const method = ['POST', 'PUT', 'GET'].includes(input.ai?.custom?.method)
    ? input.ai.custom.method
    : base.ai.custom.method;

  const provider = input.ai?.provider === 'custom' ? 'custom' : 'gemini';

  const disabledApiCategories = (asStringArray(input.disabledApiCategories) ?? []) as ApiCategory[];

  return {
    version: CONFIG_VERSION,
    profiles: { selected: selectedProfiles },
    regions: { selected: selectedRegions },
    billing: {
      comparisonDays,
      dollarThreshold: clamp(
        input.billing?.dollarThreshold,
        0,
        1_000_000,
        base.billing.dollarThreshold
      ),
      percentThreshold: clamp(
        input.billing?.percentThreshold,
        0,
        10_000,
        base.billing.percentThreshold
      ),
      metric: ['UnblendedCost', 'AmortizedCost', 'NetUnblendedCost', 'BlendedCost'].includes(
        input.billing?.metric
      )
        ? input.billing.metric
        : base.billing.metric,
      includeCredits: input.billing?.includeCredits === true,
    },
    cloudwatch: {
      growthPercentThreshold: clamp(
        input.cloudwatch?.growthPercentThreshold,
        0,
        10_000,
        base.cloudwatch.growthPercentThreshold
      ),
      growthBytesThreshold: clamp(
        input.cloudwatch?.growthBytesThreshold,
        0,
        Number.MAX_SAFE_INTEGER,
        base.cloudwatch.growthBytesThreshold
      ),
      longRetentionDays: clamp(
        input.cloudwatch?.longRetentionDays,
        1,
        3653,
        base.cloudwatch.longRetentionDays
      ),
      maxLogGroupsPerRegion: clamp(
        input.cloudwatch?.maxLogGroupsPerRegion,
        1,
        5000,
        base.cloudwatch.maxLogGroupsPerRegion
      ),
      growthWindowDays: clamp(
        input.cloudwatch?.growthWindowDays,
        1,
        90,
        base.cloudwatch.growthWindowDays
      ),
    },
    cloudtrail: {
      pageSize: clamp(input.cloudtrail?.pageSize, 10, 200, base.cloudtrail.pageSize),
      maxEventsPerSearch: clamp(
        input.cloudtrail?.maxEventsPerSearch,
        50,
        20_000,
        base.cloudtrail.maxEventsPerSearch
      ),
      defaultLookbackHours: clamp(
        input.cloudtrail?.defaultLookbackHours,
        1,
        2160,
        base.cloudtrail.defaultLookbackHours
      ),
    },
    security: {
      disabledChecks: asStringArray(input.security?.disabledChecks) ?? [],
      severityFilter:
        (asStringArray(input.security?.severityFilter)?.filter((value) =>
          ['critical', 'high', 'medium', 'low'].includes(value)
        ) as SecurityConfig['severityFilter']) ?? base.security.severityFilter,
      maxLambdaPolicyLookupsPerRegion: clamp(
        input.security?.maxLambdaPolicyLookupsPerRegion,
        0,
        10_000,
        base.security.maxLambdaPolicyLookupsPerRegion
      ),
      maxBucketsPerScan: clamp(
        input.security?.maxBucketsPerScan,
        1,
        10_000,
        base.security.maxBucketsPerScan
      ),
    },
    ai: {
      provider,
      gemini: {
        command:
          typeof input.ai?.gemini?.command === 'string' && input.ai.gemini.command.trim()
            ? input.ai.gemini.command.trim()
            : base.ai.gemini.command,
        args: asStringArray(input.ai?.gemini?.args) ?? base.ai.gemini.args,
        ...(typeof input.ai?.gemini?.model === 'string' && input.ai.gemini.model
          ? { model: input.ai.gemini.model }
          : {}),
        timeoutMs: clamp(input.ai?.gemini?.timeoutMs, 5_000, 900_000, base.ai.gemini.timeoutMs),
        probeTimeoutMs: clamp(
          input.ai?.gemini?.probeTimeoutMs,
          1_000,
          120_000,
          base.ai.gemini.probeTimeoutMs
        ),
      },
      custom: {
        enabled: input.ai?.custom?.enabled === true,
        name:
          typeof input.ai?.custom?.name === 'string' && input.ai.custom.name.trim()
            ? input.ai.custom.name.trim()
            : base.ai.custom.name,
        endpoint:
          typeof input.ai?.custom?.endpoint === 'string' ? input.ai.custom.endpoint.trim() : '',
        method,
        headers: customHeaders,
        bodyTemplate:
          typeof input.ai?.custom?.bodyTemplate === 'string' && input.ai.custom.bodyTemplate.trim()
            ? input.ai.custom.bodyTemplate
            : base.ai.custom.bodyTemplate,
        responsePath:
          typeof input.ai?.custom?.responsePath === 'string'
            ? input.ai.custom.responsePath.trim()
            : '',
        timeoutMs: clamp(input.ai?.custom?.timeoutMs, 5_000, 900_000, base.ai.custom.timeoutMs),
        acknowledgedDataEgress: input.ai?.custom?.acknowledgedDataEgress === true,
      },
      history: {
        enabled: input.ai?.history?.enabled === true,
        retentionDays: clamp(
          input.ai?.history?.retentionDays,
          1,
          MAX_AI_HISTORY_RETENTION_DAYS,
          base.ai.history.retentionDays
        ),
        includeInRequests: input.ai?.history?.includeInRequests !== false,
      },
      sanitization: { rules: rules.length ? rules : base.ai.sanitization.rules },
    },
    ui: {
      theme: ['system', 'light', 'dark'].includes(input.ui?.theme) ? input.ui.theme : base.ui.theme,
      defaultSection:
        typeof input.ui?.defaultSection === 'string' && input.ui.defaultSection
          ? input.ui.defaultSection
          : base.ui.defaultSection,
      autoOpenBrowser: input.ui?.autoOpenBrowser !== false,
    },
    disabledApiCategories,
  };
}

/** Applies migrations to bring an on-disk document up to `CONFIG_VERSION`. */
export function migrateConfig(raw: unknown): { config: AppConfig; migratedFrom?: number } {
  if (!raw || typeof raw !== 'object') return { config: defaultConfig() };
  const document = raw as Record<string, any>;
  const fromVersion = typeof document.version === 'number' ? document.version : 0;

  let working = document;
  for (let version = fromVersion; version < CONFIG_VERSION; version += 1) {
    const migration = MIGRATIONS[version];
    if (migration) working = migration(working);
  }

  const config = normaliseConfig(working);
  return fromVersion < CONFIG_VERSION ? { config, migratedFrom: fromVersion } : { config };
}
