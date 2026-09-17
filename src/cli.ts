#!/usr/bin/env node
/**
 * aws-readonly-dashboard CLI.
 *
 * Starts the local dashboard server, reports exactly which port and profiles it
 * found, and opens a browser unless asked not to.
 */

import { normaliseRegions } from './aws/regions.js';
import { logger, type LogLevel } from './util/logger.js';
import { startServer } from './server/index.js';
import { openBrowser } from './server/browser.js';
import { PACKAGE_VERSION } from './server/routes.js';
import { DEFAULT_PORT } from './server/port.js';

export interface CliOptions {
  port?: number;
  host?: string;
  profile?: string;
  regions?: string[];
  open: boolean;
  configDir?: string;
  logLevel?: LogLevel;
  help: boolean;
  version: boolean;
}

export const HELP_TEXT = `aws-readonly-dashboard ${PACKAGE_VERSION}

A local, strictly read-only AWS dashboard for cost, security, CloudWatch,
CloudTrail and Compute Optimizer insights, with optional user-triggered AI
analysis. This tool never creates, updates or deletes AWS resources.

Usage:
  aws-readonly-dashboard [options]
  npx aws-readonly-dashboard [options]

Options:
  -p, --port <number>      Preferred port (default: ${DEFAULT_PORT}). If it is busy, the
                           next free port is used automatically.
      --host <address>     Interface to bind (default: 127.0.0.1). Binding to a
                           non-loopback address exposes the dashboard on your network.
      --profile <name>     Pre-select an AWS profile for this session.
      --region <list>      Pre-select regions for this session (comma separated).
      --no-open            Do not open a browser automatically.
      --config-dir <path>  Directory for local configuration
                           (default: ~/.aws-readonly-dashboard).
      --log-level <level>  debug | info | warn | error | silent (default: info).
  -v, --version            Print the version and exit.
  -h, --help               Print this help and exit.

Examples:
  aws-readonly-dashboard
  aws-readonly-dashboard --port 8080 --profile prd --region us-east-1,eu-west-1
  aws-readonly-dashboard --no-open --log-level debug
`;

export function parseArgs(argv: readonly string[]): CliOptions {
  const options: CliOptions = { open: true, help: false, version: false };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index] as string;
    const next = (): string => {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith('-')) {
        throw new Error(`Option ${arg} requires a value.`);
      }
      index += 1;
      return value;
    };

    switch (arg) {
      case '-p':
      case '--port': {
        const value = Number(next());
        if (!Number.isInteger(value) || value < 1 || value > 65535) {
          throw new Error('--port must be an integer between 1 and 65535.');
        }
        options.port = value;
        break;
      }
      case '--host':
        options.host = next();
        break;
      case '--profile':
        options.profile = next();
        break;
      case '--region':
      case '--regions':
        options.regions = normaliseRegions(next().split(','));
        break;
      case '--open':
        options.open = true;
        break;
      case '--no-open':
        options.open = false;
        break;
      case '--config-dir':
        options.configDir = next();
        break;
      case '--log-level': {
        const value = next() as LogLevel;
        if (!['debug', 'info', 'warn', 'error', 'silent'].includes(value)) {
          throw new Error('--log-level must be one of: debug, info, warn, error, silent.');
        }
        options.logLevel = value;
        break;
      }
      case '-h':
      case '--help':
        options.help = true;
        break;
      case '-v':
      case '--version':
        options.version = true;
        break;
      default:
        if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    }
  }

  return options;
}

export async function run(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  let options: CliOptions;
  try {
    options = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`${(error as Error).message}\n\nRun with --help for usage.\n`);
    return 1;
  }

  if (options.help) {
    process.stdout.write(HELP_TEXT);
    return 0;
  }
  if (options.version) {
    process.stdout.write(`${PACKAGE_VERSION}\n`);
    return 0;
  }

  const out = (line: string): void => {
    process.stdout.write(`${line}\n`);
  };

  out('AWS Read-Only Dashboard');
  out('Starting local server...');

  let started: Awaited<ReturnType<typeof startServer>>;
  try {
    started = await startServer({
      ...(options.port !== undefined ? { port: options.port } : {}),
      ...(options.host ? { host: options.host } : {}),
      ...(options.configDir ? { configDir: options.configDir } : {}),
      ...(options.logLevel ? { logLevel: options.logLevel } : {}),
      ...(options.profile ? { profile: options.profile } : {}),
      ...(options.regions?.length ? { regions: options.regions } : {}),
    });
  } catch (error) {
    process.stderr.write(`Could not start the dashboard: ${(error as Error).message}\n`);
    return 1;
  }

  if (started.portSelection.changed) {
    out(`Port ${started.portSelection.requestedPort} is occupied.`);
    out(`Using port ${started.port}.`);
  } else {
    out(`Port: ${started.port}`);
  }

  out(`AWS profiles discovered: ${started.profilesDiscovered}`);
  const gemini = started.aiStatus.providers.find((provider) => provider.id === 'gemini');
  out(gemini?.available ? 'Gemini CLI: Available' : 'Gemini CLI: Not available (non-LLM mode)');
  const custom = started.aiStatus.providers.find((provider) => provider.id === 'custom');
  if (custom?.configured) out(custom.label);
  out('AWS access: read-only (mutating API calls are refused by design)');
  out(`Dashboard: ${started.url}`);

  if (started.host !== '127.0.0.1' && started.host !== 'localhost') {
    out(
      `Warning: bound to ${started.host}, so the dashboard is reachable from other machines on this network.`
    );
  }

  if (options.open) {
    openBrowser(started.url);
  }

  const shutdown = (signal: string): void => {
    out(`\nReceived ${signal}; shutting down.`);
    void started.close().then(() => process.exit(0));
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  return new Promise<number>(() => {
    // The process stays alive until a signal arrives.
  });
}

const isDirectRun =
  process.argv[1] !== undefined &&
  (import.meta.url === `file://${process.argv[1]}` ||
    import.meta.url.endsWith('/cli.js') ||
    import.meta.url.endsWith('\\cli.js'));

if (isDirectRun) {
  run().then(
    (code) => {
      if (code !== 0) process.exit(code);
    },
    (error) => {
      logger.error('Fatal error', { reason: (error as Error).message });
      process.exit(1);
    }
  );
}
