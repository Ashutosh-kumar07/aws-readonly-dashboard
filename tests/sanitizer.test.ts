/** PII sanitization and pseudonymization. */

import { describe, expect, it } from 'vitest';

import { sanitize } from '../src/ai/sanitizer.js';
import {
  defaultConfig,
  DEFAULT_SANITIZATION_RULES,
  type SanitizationRule,
} from '../src/config/schema.js';

const rules = defaultConfig().ai.sanitization.rules;

function sanitized(value: unknown, override?: SanitizationRule[]): string {
  return JSON.stringify(sanitize(value, override ?? rules).value);
}

describe('default sanitization', () => {
  it('redacts email addresses', () => {
    const output = sanitized({ owner: 'alice@example.com' });
    expect(output).not.toContain('alice@example.com');
    expect(output).toContain('<EMAIL>');
  });

  it('redacts IP addresses', () => {
    const output = sanitized({ sourceIp: '203.0.113.10' });
    expect(output).not.toContain('203.0.113.10');
    expect(output).toContain('<IP>');
  });

  it('preserves 0.0.0.0/0 because it is a policy value, not an identifier', () => {
    const output = sanitized({ cidr: '0.0.0.0/0', ipv6: '::/0' });
    expect(output).toContain('0.0.0.0/0');
    expect(output).toContain('::/0');
  });

  it('pseudonymises AWS account IDs consistently', () => {
    const result = sanitize({ a: '111122223333', b: '111122223333', c: '444455556666' }, rules);
    const output = result.value as Record<string, string>;
    expect(output.a).toBe(output.b);
    expect(output.a).not.toBe(output.c);
    expect(output.a).toMatch(/^<ACCOUNT_\d+>$/);
    expect(result.mapping[output.a as string]).toBe('111122223333');
  });

  it('pseudonymises IAM user names by key and by ARN', () => {
    const result = sanitize(
      { userName: 'alice', arn: 'arn:aws:iam::111122223333:user/alice' },
      rules
    );
    const output = result.value as Record<string, string>;
    expect(output.userName).toMatch(/^<USER_\d+>$/);
    expect(output.arn).not.toContain('alice');
  });

  it('gives the same entity the same placeholder within one request', () => {
    const result = sanitize({ first: { userName: 'bob' }, second: { userName: 'bob' } }, rules);
    const output = result.value as { first: { userName: string }; second: { userName: string } };
    expect(output.first.userName).toBe(output.second.userName);
  });

  it('partially anonymises ARNs while keeping the service and region', () => {
    const output = sanitized({
      arn: 'arn:aws:ec2:eu-west-1:111122223333:instance/i-0abc123def456789a',
    });
    expect(output).toContain('arn:aws:ec2:eu-west-1');
    expect(output).not.toContain('111122223333');
    expect(output).not.toContain('i-0abc123def456789a');
  });

  it('preserves bucket, Lambda and security group identifiers that carry meaning', () => {
    const output = sanitized({
      bucket: 'my-production-logs',
      lambda: 'order-processor',
      securityGroup: 'sg-0123456789abcdef0',
    });
    expect(output).toContain('my-production-logs');
    expect(output).toContain('order-processor');
    expect(output).toContain('sg-0123456789abcdef0');
  });

  it('pseudonymises instance and volume identifiers', () => {
    const output = sanitized({ instance: 'i-0abc123def456789a', volume: 'vol-0abc123def456789a' });
    expect(output).not.toContain('i-0abc123def456789a');
    expect(output).toMatch(/<RESOURCE_\d+>/);
  });

  it('redacts hostnames but keeps AWS service endpoints', () => {
    const output = sanitized({ host: 'db.internal.corp.example', source: 'ec2.amazonaws.com' });
    expect(output).not.toContain('db.internal.corp.example');
    expect(output).toContain('ec2.amazonaws.com');
  });

  it('never sends credential material, even when a key looks innocuous', () => {
    const output = sanitized({
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      authorization: 'Bearer abcdefghijklmnopqrstuvwxyz123456',
    });
    expect(output).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(output).not.toContain('wJalrXUtnFEMI');
    expect(output).not.toContain('abcdefghijklmnopqrstuvwxyz123456');
  });

  it('walks nested objects and arrays', () => {
    const output = sanitized({
      findings: [{ evidence: { contact: 'ops@example.com', ip: '10.1.2.3' } }],
    });
    expect(output).not.toContain('ops@example.com');
    expect(output).not.toContain('10.1.2.3');
  });

  it('leaves numbers and booleans untouched', () => {
    const result = sanitize({ cost: 1234.56, enabled: true, count: 12 }, rules);
    expect(result.value).toEqual({ cost: 1234.56, enabled: true, count: 12 });
  });
});

describe('sanitization reporting', () => {
  it('counts replacements per rule', () => {
    const result = sanitize({ a: 'alice@example.com', b: 'bob@example.com' }, rules);
    const email = result.report.rules.find((rule) => rule.id === 'email');
    expect(email?.matches).toBe(2);
    expect(result.report.totalReplacements).toBeGreaterThanOrEqual(2);
  });

  it('lists placeholders without revealing the originals', () => {
    const result = sanitize({ userName: 'alice' }, rules);
    expect(result.report.placeholders[0]?.placeholder).toMatch(/^<USER_\d+>$/);
    expect(JSON.stringify(result.report)).not.toContain('alice');
  });

  it('names the rules the user disabled so the UI can warn', () => {
    const custom = rules.map((rule) =>
      rule.id === 'hostname' ? { ...rule, enabled: false } : rule
    );
    const result = sanitize({ host: 'db.internal.example' }, custom);
    expect(result.report.disabledRules.map((rule) => rule.id)).toContain('hostname');
    expect(JSON.stringify(result.value)).toContain('db.internal.example');
  });
});

describe('user-configured rules', () => {
  it('applies a custom pattern', () => {
    const custom: SanitizationRule[] = [
      ...rules,
      {
        id: 'ticket',
        label: 'Ticket IDs',
        strategy: 'redact',
        enabled: true,
        builtin: false,
        pattern: 'TICKET-\\d+',
        flags: 'g',
        placeholder: 'TICKET',
      },
    ];
    const output = sanitized({ note: 'see TICKET-4421 for context' }, custom);
    expect(output).not.toContain('TICKET-4421');
    expect(output).toContain('<TICKET>');
  });

  it('pseudonymises with a custom rule consistently', () => {
    const custom: SanitizationRule[] = [
      ...rules,
      {
        id: 'team',
        label: 'Team names',
        strategy: 'pseudonymize',
        enabled: true,
        builtin: false,
        pattern: 'team-[a-z]+',
        flags: 'g',
        placeholder: 'TEAM',
      },
    ];
    const result = sanitize({ a: 'team-payments', b: 'team-payments', c: 'team-search' }, custom);
    const output = result.value as Record<string, string>;
    expect(output.a).toBe(output.b);
    expect(output.a).not.toBe(output.c);
  });

  it('applies the locked credential rule even when the document disables it', () => {
    const tampered = rules.map((rule) =>
      rule.id === 'aws-credentials' ? { ...rule, enabled: false } : rule
    );
    const output = sanitized({ key: 'AKIAIOSFODNN7EXAMPLE' }, tampered);
    expect(output).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('exposes the documented default rule set', () => {
    const ids = DEFAULT_SANITIZATION_RULES.map((rule) => rule.id);
    expect(ids).toEqual(
      expect.arrayContaining([
        'aws-credentials',
        'email',
        'ip-address',
        'aws-account-id',
        'iam-username',
        'iam-role',
        'arn',
        'hostname',
        'resource-identifier',
      ])
    );
    expect(DEFAULT_SANITIZATION_RULES.find((rule) => rule.id === 'aws-credentials')?.locked).toBe(
      true
    );
  });
});
