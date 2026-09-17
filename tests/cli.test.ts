/** CLI argument parsing and help output. */

import { describe, expect, it } from 'vitest';

import { parseArgs, HELP_TEXT } from '../src/cli.js';

describe('CLI options', () => {
  it('defaults to opening a browser and no overrides', () => {
    const options = parseArgs([]);
    expect(options).toEqual({ open: true, help: false, version: false });
  });

  it('parses the port', () => {
    expect(parseArgs(['--port', '8080']).port).toBe(8080);
    expect(parseArgs(['-p', '9001']).port).toBe(9001);
  });

  it('rejects an invalid port', () => {
    expect(() => parseArgs(['--port', '0'])).toThrow(/between 1 and 65535/);
    expect(() => parseArgs(['--port', 'abc'])).toThrow();
    expect(() => parseArgs(['--port', '70000'])).toThrow();
  });

  it('parses host, profile and config directory', () => {
    const options = parseArgs(['--host', '0.0.0.0', '--profile', 'prd', '--config-dir', '/tmp/x']);
    expect(options.host).toBe('0.0.0.0');
    expect(options.profile).toBe('prd');
    expect(options.configDir).toBe('/tmp/x');
  });

  it('parses and validates a region list', () => {
    expect(parseArgs(['--region', 'us-east-1,eu-west-1']).regions).toEqual([
      'us-east-1',
      'eu-west-1',
    ]);
    expect(parseArgs(['--regions', 'us-east-1,nonsense']).regions).toEqual(['us-east-1']);
  });

  it('supports --no-open', () => {
    expect(parseArgs(['--no-open']).open).toBe(false);
    expect(parseArgs(['--open']).open).toBe(true);
  });

  it('validates the log level', () => {
    expect(parseArgs(['--log-level', 'debug']).logLevel).toBe('debug');
    expect(() => parseArgs(['--log-level', 'chatty'])).toThrow(/log-level/);
  });

  it('supports help and version flags', () => {
    expect(parseArgs(['--help']).help).toBe(true);
    expect(parseArgs(['-h']).help).toBe(true);
    expect(parseArgs(['--version']).version).toBe(true);
    expect(parseArgs(['-v']).version).toBe(true);
  });

  it('rejects an unknown option', () => {
    expect(() => parseArgs(['--wat'])).toThrow(/Unknown option/);
  });

  it('requires a value for options that take one', () => {
    expect(() => parseArgs(['--profile'])).toThrow(/requires a value/);
    expect(() => parseArgs(['--host', '--no-open'])).toThrow(/requires a value/);
  });

  it('documents the read-only guarantee and the port behaviour in --help', () => {
    expect(HELP_TEXT).toContain('never creates, updates or deletes AWS resources');
    expect(HELP_TEXT).toContain('9001');
    expect(HELP_TEXT).toContain('npx aws-readonly-dashboard');
  });
});
