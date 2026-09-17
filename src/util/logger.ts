/**
 * Minimal structured logger.
 *
 * The logger deliberately refuses to print values that look like credentials.
 * Nothing in this application should ever log an AWS secret, a session token,
 * an API key, or an AI payload body.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

const LEVEL_ORDER: Record<Exclude<LogLevel, 'silent'>, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

/** Keys whose values are never printed, at any log level. */
const SECRET_KEY_PATTERN =
  /(secret|password|token|credential|apikey|api_key|authorization|sessiontoken|accesskey|private)/i;

const SECRET_VALUE_PATTERNS: RegExp[] = [
  /\bASIA[0-9A-Z]{16}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bAIza[0-9A-Za-z_-]{20,}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi,
];

export function redactSecrets(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[depth-limit]';
  if (typeof value === 'string') {
    let out = value;
    for (const pattern of SECRET_VALUE_PATTERNS) out = out.replace(pattern, '[REDACTED]');
    return out;
  }
  if (Array.isArray(value)) return value.map((item) => redactSecrets(item, depth + 1));
  if (value && typeof value === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      result[key] = SECRET_KEY_PATTERN.test(key) ? '[REDACTED]' : redactSecrets(item, depth + 1);
    }
    return result;
  }
  return value;
}

export class Logger {
  constructor(
    private level: LogLevel = 'info',
    private readonly sink: (line: string) => void = (line) => process.stderr.write(`${line}\n`)
  ) {}

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  getLevel(): LogLevel {
    return this.level;
  }

  private enabled(level: Exclude<LogLevel, 'silent'>): boolean {
    if (this.level === 'silent') return false;
    return LEVEL_ORDER[level] >= LEVEL_ORDER[this.level];
  }

  private write(level: Exclude<LogLevel, 'silent'>, message: string, meta?: unknown): void {
    if (!this.enabled(level)) return;
    const stamp = new Date().toISOString();
    const suffix = meta === undefined ? '' : ` ${JSON.stringify(redactSecrets(meta))}`;
    this.sink(`${stamp} ${level.toUpperCase().padEnd(5)} ${message}${suffix}`);
  }

  debug(message: string, meta?: unknown): void {
    this.write('debug', message, meta);
  }
  info(message: string, meta?: unknown): void {
    this.write('info', message, meta);
  }
  warn(message: string, meta?: unknown): void {
    this.write('warn', message, meta);
  }
  error(message: string, meta?: unknown): void {
    this.write('error', message, meta);
  }
}

export const logger = new Logger(
  (process.env.AWS_READONLY_DASHBOARD_LOG_LEVEL as LogLevel | undefined) ?? 'info'
);
