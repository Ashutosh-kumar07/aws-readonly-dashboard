/**
 * PII / sensitive-data sanitization for AI payloads.
 *
 * Every AI request is built as:
 *
 *   AWS data → relevant-data selection → aggregation → sanitization →
 *   pseudonymization → AI provider
 *
 * There is no code path that reaches a provider without passing through this
 * module: `AiOrchestrator` sanitizes before it selects a provider, and the
 * providers receive only the sanitized payload.
 *
 * The approach is deliberately balanced. Identifiers that reveal *who* or
 * *where* are removed or pseudonymized; identifiers that carry infrastructure
 * meaning (bucket names, Lambda names, security group IDs) are preserved so the
 * model can still reason about the environment.
 */

import { isIP } from 'node:net';

import type { SanitizationRule } from '../config/schema.js';

export interface SanitizationReport {
  rules: Array<{ id: string; label: string; strategy: string; matches: number; enabled: boolean }>;
  /** Placeholder → category, so the UI can explain the output. */
  placeholders: Array<{ placeholder: string; category: string }>;
  totalReplacements: number;
  /** Rules the user disabled, so the UI can warn about what is being sent. */
  disabledRules: Array<{ id: string; label: string }>;
}

export interface SanitizationResult<T = unknown> {
  value: T;
  report: SanitizationReport;
  /**
   * Placeholder → original value. Stays on the local machine: it is returned to
   * the browser so findings can be decoded, and is never sent to a provider or
   * written to AI history.
   */
  mapping: Record<string, string>;
}

const PRESERVED_DOMAIN_SUFFIXES = ['amazonaws.com', 'aws.amazon.com', 'amazonaws.com.cn'];

/** Keys whose values are IAM user names. */
const USER_KEY_PATTERN = /^(user_?name|iam_?user|principal_?user|userIdentityUserName)$/i;
/** Keys whose values are IAM role names. */
const ROLE_KEY_PATTERN = /^(role_?name|iam_?role|assumed_?role)$/i;
/** Keys whose values are credential material, regardless of content. */
const SECRET_KEY_PATTERN =
  /(secret|password|passwd|token|credential|api_?key|authorization|private_?key|session_?token)/i;

interface Matcher {
  id: string;
  label: string;
  strategy: SanitizationRule['strategy'];
  placeholder: string;
  apply(value: string, ctx: SanitizerContext, key?: string): string;
}

class SanitizerContext {
  private readonly counters = new Map<string, number>();
  readonly mapping = new Map<string, string>();
  private readonly reverse = new Map<string, string>();
  readonly counts = new Map<string, number>();

  pseudonym(category: string, original: string): string {
    const existing = this.reverse.get(`${category}:${original}`);
    if (existing) return existing;
    const next = (this.counters.get(category) ?? 0) + 1;
    this.counters.set(category, next);
    const placeholder = `<${category}_${next}>`;
    this.reverse.set(`${category}:${original}`, placeholder);
    this.mapping.set(placeholder, original);
    return placeholder;
  }

  count(ruleId: string, amount = 1): void {
    this.counts.set(ruleId, (this.counts.get(ruleId) ?? 0) + amount);
  }
}

const CREDENTIAL_PATTERNS: RegExp[] = [
  /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  /\bAIza[0-9A-Za-z_-]{20,}\b/g,
  /\bghp_[0-9A-Za-z]{20,}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/gi,
  /\b[A-Za-z0-9/+]{40}\b/g, // AWS secret access key shape
];

const EMAIL_PATTERN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b(?:\/\d{1,2})?/g;
/**
 * Candidate IPv6 spans. Colon-separated hex is ambiguous — `arn:aws:ec2:` looks
 * like one — so every candidate is validated with `net.isIP` before it is
 * treated as an address.
 */
const IPV6_PATTERN = /(?:[0-9A-Fa-f]{1,4}:){2,7}(?::|[0-9A-Fa-f]{1,4})(?:\/\d{1,3})?/g;

/** Splits a `value/prefix` pair and reports whether the value is a real IP. */
function parseIpCandidate(candidate: string): { address: string; suffix: string } | undefined {
  const slash = candidate.indexOf('/');
  const address = slash === -1 ? candidate : candidate.slice(0, slash);
  const suffix = slash === -1 ? '' : candidate.slice(slash);
  return isIP(address) === 0 ? undefined : { address, suffix };
}
const ACCOUNT_PATTERN = /\b\d{12}\b/g;
const ARN_PATTERN = /arn:(aws[a-z-]*):([a-z0-9-]+):([a-z0-9-]*):(\d{12}|):([^\s"']+)/g;
const HOSTNAME_PATTERN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,}[a-z]{2,}\b/gi;
const RESOURCE_ID_PATTERN =
  /\b(i|vol|eni|subnet|vpc|snap|ami|igw|nat|rtb|acl|eipalloc)-[0-9a-f]{8,17}\b/g;

/** CIDR values that are policy statements rather than identifiers. */
const POLICY_CIDRS = new Set(['0.0.0.0/0', '::/0', '0.0.0.0', '255.255.255.255', '127.0.0.1']);

/** ARN resource types whose names carry infrastructure meaning worth keeping. */
const PRESERVED_ARN_SERVICES = new Set(['s3', 'lambda', 'ec2-security-group']);

function isPreservedHost(host: string): boolean {
  const lower = host.toLowerCase();
  return PRESERVED_DOMAIN_SUFFIXES.some(
    (suffix) => lower === suffix || lower.endsWith(`.${suffix}`)
  );
}

function buildMatchers(rules: readonly SanitizationRule[]): Matcher[] {
  const matchers: Matcher[] = [];

  for (const rule of rules) {
    if (!rule.enabled && !rule.locked) continue;

    switch (rule.id) {
      case 'aws-credentials':
        matchers.push({
          id: rule.id,
          label: rule.label,
          strategy: rule.strategy,
          placeholder: 'CREDENTIAL',
          apply(value, ctx, key) {
            if (key && SECRET_KEY_PATTERN.test(key) && value.length > 3) {
              ctx.count(this.id);
              return '<CREDENTIAL>';
            }
            let output = value;
            for (const pattern of CREDENTIAL_PATTERNS) {
              output = output.replace(pattern, () => {
                ctx.count(this.id);
                return '<CREDENTIAL>';
              });
            }
            return output;
          },
        });
        break;

      case 'email':
        matchers.push({
          id: rule.id,
          label: rule.label,
          strategy: rule.strategy,
          placeholder: 'EMAIL',
          apply(value, ctx) {
            return value.replace(EMAIL_PATTERN, (match) => {
              ctx.count(this.id);
              return this.strategy === 'pseudonymize' ? ctx.pseudonym('EMAIL', match) : '<EMAIL>';
            });
          },
        });
        break;

      case 'ip-address':
        matchers.push({
          id: rule.id,
          label: rule.label,
          strategy: rule.strategy,
          placeholder: 'IP',
          apply(value, ctx) {
            const replaceIp = (match: string): string => {
              if (POLICY_CIDRS.has(match)) return match;
              const parsed = parseIpCandidate(match);
              // Not an address (an ARN segment, a version string, …): leave it alone.
              if (!parsed) return match;
              if (POLICY_CIDRS.has(parsed.address)) return match;
              ctx.count(this.id);
              return this.strategy === 'pseudonymize'
                ? `${ctx.pseudonym('IP', parsed.address)}${parsed.suffix}`
                : `<IP>${parsed.suffix}`;
            };
            return value.replace(IPV4_PATTERN, replaceIp).replace(IPV6_PATTERN, replaceIp);
          },
        });
        break;

      case 'aws-account-id':
        matchers.push({
          id: rule.id,
          label: rule.label,
          strategy: rule.strategy,
          placeholder: 'ACCOUNT',
          apply(value, ctx) {
            return value.replace(ACCOUNT_PATTERN, (match) => {
              ctx.count(this.id);
              return this.strategy === 'redact' ? '<ACCOUNT>' : ctx.pseudonym('ACCOUNT', match);
            });
          },
        });
        break;

      case 'iam-username':
        matchers.push({
          id: rule.id,
          label: rule.label,
          strategy: rule.strategy,
          placeholder: 'USER',
          apply(value, ctx, key) {
            if (key && USER_KEY_PATTERN.test(key)) {
              ctx.count(this.id);
              return this.strategy === 'redact' ? '<USER>' : ctx.pseudonym('USER', value);
            }
            return value.replace(
              /(:user\/)([^\s"'/]+)/g,
              (_match, prefix: string, name: string) => {
                ctx.count(this.id);
                return `${prefix}${this.strategy === 'redact' ? '<USER>' : ctx.pseudonym('USER', name)}`;
              }
            );
          },
        });
        break;

      case 'iam-role':
        matchers.push({
          id: rule.id,
          label: rule.label,
          strategy: rule.strategy,
          placeholder: 'ROLE',
          apply(value, ctx, key) {
            if (key && ROLE_KEY_PATTERN.test(key)) {
              ctx.count(this.id);
              return this.strategy === 'redact' ? '<ROLE>' : ctx.pseudonym('ROLE', value);
            }
            return value.replace(
              /(:role\/|:assumed-role\/)([^\s"'/]+)/g,
              (_match, prefix: string, name: string) => {
                ctx.count(this.id);
                return `${prefix}${this.strategy === 'redact' ? '<ROLE>' : ctx.pseudonym('ROLE', name)}`;
              }
            );
          },
        });
        break;

      case 'arn':
        matchers.push({
          id: rule.id,
          label: rule.label,
          strategy: rule.strategy,
          placeholder: 'ARN',
          apply(value, ctx) {
            return value.replace(
              ARN_PATTERN,
              (
                match,
                partition: string,
                service: string,
                region: string,
                account: string,
                resource: string
              ) => {
                ctx.count(this.id);
                if (this.strategy === 'redact') return '<ARN>';
                if (this.strategy === 'pseudonymize') return ctx.pseudonym('ARN', match);
                const accountPart = account ? ctx.pseudonym('ACCOUNT', account) : '';
                if (PRESERVED_ARN_SERVICES.has(service)) {
                  // Keep names that carry infrastructure meaning.
                  return `arn:${partition}:${service}:${region}:${accountPart}:${resource}`;
                }
                const separatorIndex = Math.max(resource.indexOf('/'), resource.indexOf(':'));
                if (separatorIndex === -1) {
                  return `arn:${partition}:${service}:${region}:${accountPart}:${ctx.pseudonym('RESOURCE', resource)}`;
                }
                const type = resource.slice(0, separatorIndex + 1);
                const name = resource.slice(separatorIndex + 1);
                return `arn:${partition}:${service}:${region}:${accountPart}:${type}${ctx.pseudonym('RESOURCE', name)}`;
              }
            );
          },
        });
        break;

      case 'hostname':
        matchers.push({
          id: rule.id,
          label: rule.label,
          strategy: rule.strategy,
          placeholder: 'HOST',
          apply(value, ctx) {
            return value.replace(HOSTNAME_PATTERN, (match) => {
              if (isPreservedHost(match)) return match;
              // Don't mangle things that merely look dotted, like file names.
              if (/\.(json|txt|log|zip|gz|tar|yaml|yml|js|ts|py)$/i.test(match)) return match;
              ctx.count(this.id);
              return this.strategy === 'pseudonymize' ? ctx.pseudonym('HOST', match) : '<HOST>';
            });
          },
        });
        break;

      case 'resource-identifier':
        matchers.push({
          id: rule.id,
          label: rule.label,
          strategy: rule.strategy,
          placeholder: 'RESOURCE',
          apply(value, ctx) {
            return value.replace(RESOURCE_ID_PATTERN, (match) => {
              ctx.count(this.id);
              return this.strategy === 'redact' ? '<RESOURCE>' : ctx.pseudonym('RESOURCE', match);
            });
          },
        });
        break;

      default: {
        if (!rule.pattern) break;
        let regex: RegExp;
        try {
          regex = new RegExp(
            rule.pattern,
            rule.flags?.includes('g') ? rule.flags : `${rule.flags ?? ''}g`
          );
        } catch {
          break;
        }
        const placeholder = rule.placeholder ?? 'CUSTOM';
        matchers.push({
          id: rule.id,
          label: rule.label,
          strategy: rule.strategy,
          placeholder,
          apply(value, ctx) {
            return value.replace(new RegExp(regex.source, regex.flags), (match) => {
              ctx.count(this.id);
              return this.strategy === 'pseudonymize'
                ? ctx.pseudonym(placeholder, match)
                : `<${placeholder}>`;
            });
          },
        });
      }
    }
  }

  return matchers;
}

/**
 * Values that identify a person or principal but cannot be recognised from
 * their text alone (an IAM user called `jane.doe` looks like any other string).
 * They are discovered from the keys and ARNs that do identify them, then
 * replaced everywhere else in the payload — including inside free-text titles
 * and descriptions such as "IAM user jane.doe has an old access key".
 */
interface DiscoveredEntity {
  value: string;
  category: 'USER' | 'ROLE';
}

/** Generic principal names that are concepts rather than identities. */
const GENERIC_PRINCIPALS = new Set([
  'root',
  'admin',
  'administrator',
  'user',
  'users',
  'role',
  'roles',
  'test',
  'guest',
  'system',
  'default',
  'service',
  'unknown',
  'anonymous',
]);

const ARN_PRINCIPAL_PATTERN = /:(user|role|assumed-role)\/([^\s"'/]+)/g;

function isReplaceableName(value: string): boolean {
  // Too short to match safely, or a generic concept rather than an identity.
  return value.length >= 4 && !GENERIC_PRINCIPALS.has(value.toLowerCase());
}

function discoverEntities(
  value: unknown,
  found: Map<string, DiscoveredEntity>,
  key?: string,
  depth = 0
): void {
  if (depth > 12) return;
  if (typeof value === 'string') {
    if (key && USER_KEY_PATTERN.test(key) && isReplaceableName(value)) {
      found.set(value, { value, category: 'USER' });
    }
    if (key && ROLE_KEY_PATTERN.test(key) && isReplaceableName(value)) {
      found.set(value, { value, category: 'ROLE' });
    }
    for (const match of value.matchAll(ARN_PRINCIPAL_PATTERN)) {
      const name = match[2];
      if (name && isReplaceableName(name)) {
        found.set(name, { value: name, category: match[1] === 'user' ? 'USER' : 'ROLE' });
      }
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) discoverEntities(item, found, key, depth + 1);
    return;
  }
  if (value && typeof value === 'object') {
    for (const [childKey, childValue] of Object.entries(value as Record<string, unknown>)) {
      discoverEntities(childValue, found, childKey, depth + 1);
    }
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Replaces discovered principal names wherever they appear in the payload. */
function entityMatcher(
  entities: DiscoveredEntity[],
  strategy: SanitizationRule['strategy'],
  ruleId: string,
  label: string
): Matcher | undefined {
  if (entities.length === 0) return undefined;
  // Longest first, so `deploy-role-prod` is not partly replaced by `deploy-role`.
  const ordered = [...entities].sort((a, b) => b.value.length - a.value.length);
  const pattern = new RegExp(
    `(?<![A-Za-z0-9_-])(${ordered.map((entity) => escapeRegExp(entity.value)).join('|')})(?![A-Za-z0-9_-])`,
    'g'
  );
  const byValue = new Map(ordered.map((entity) => [entity.value, entity.category]));

  return {
    id: ruleId,
    label,
    strategy,
    placeholder: 'USER',
    apply(value, ctx) {
      return value.replace(pattern, (match) => {
        const category = byValue.get(match) ?? 'USER';
        ctx.count(this.id);
        return strategy === 'redact' ? `<${category}>` : ctx.pseudonym(category, match);
      });
    },
  };
}

function sanitizeString(
  value: string,
  matchers: Matcher[],
  ctx: SanitizerContext,
  key?: string
): string {
  let output = value;
  for (const matcher of matchers) output = matcher.apply(output, ctx, key);
  return output;
}

function walk(
  value: unknown,
  matchers: Matcher[],
  ctx: SanitizerContext,
  key?: string,
  depth = 0
): unknown {
  if (depth > 12) return '[depth-limit]';
  if (typeof value === 'string') return sanitizeString(value, matchers, ctx, key);
  if (Array.isArray(value)) return value.map((item) => walk(item, matchers, ctx, key, depth + 1));
  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {};
    for (const [childKey, childValue] of Object.entries(value as Record<string, unknown>)) {
      output[childKey] = walk(childValue, matchers, ctx, childKey, depth + 1);
    }
    return output;
  }
  return value;
}

/**
 * Sanitizes an arbitrary JSON-serialisable value according to the configured
 * rules. Locked rules are always applied even when the document says otherwise.
 */
export function sanitize<T = unknown>(
  value: T,
  rules: readonly SanitizationRule[]
): SanitizationResult<T> {
  const ctx = new SanitizerContext();
  const matchers = buildMatchers(rules);

  // Discovery pass: find principal names from the keys and ARNs that identify
  // them, so they can also be removed from free text elsewhere in the payload.
  const userRule = rules.find((rule) => rule.id === 'iam-username');
  const roleRule = rules.find((rule) => rule.id === 'iam-role');
  const discovered = new Map<string, DiscoveredEntity>();
  if (userRule?.enabled || roleRule?.enabled) {
    discoverEntities(value, discovered);
  }
  const applicable = [...discovered.values()].filter((entity) =>
    entity.category === 'USER' ? userRule?.enabled : roleRule?.enabled
  );
  const extra = entityMatcher(
    applicable,
    userRule?.strategy ?? 'pseudonymize',
    'iam-username',
    userRule?.label ?? 'IAM user names'
  );
  if (extra) matchers.push(extra);

  const sanitized = walk(value, matchers, ctx) as T;

  const report: SanitizationReport = {
    rules: rules.map((rule) => ({
      id: rule.id,
      label: rule.label,
      strategy: rule.strategy,
      enabled: rule.enabled || Boolean(rule.locked),
      matches: ctx.counts.get(rule.id) ?? 0,
    })),
    placeholders: [...ctx.mapping.keys()].map((placeholder) => ({
      placeholder,
      category: placeholder.replace(/^<|_\d+>$|>$/g, ''),
    })),
    totalReplacements: [...ctx.counts.values()].reduce((sum, count) => sum + count, 0),
    disabledRules: rules
      .filter((rule) => !rule.enabled && !rule.locked)
      .map((rule) => ({ id: rule.id, label: rule.label })),
  };

  return { value: sanitized, report, mapping: Object.fromEntries(ctx.mapping) };
}
