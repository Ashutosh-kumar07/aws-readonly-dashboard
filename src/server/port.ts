/**
 * Port selection.
 *
 * The dashboard defaults to 9001 and, when that port is busy, walks forward to
 * the next free port. A user should never have to kill another process just to
 * open this dashboard.
 */

import { createServer } from 'node:net';

export const DEFAULT_PORT = 9001;

export async function isPortAvailable(port: number, host: string): Promise<boolean> {
  return new Promise((resolve) => {
    const server = createServer();
    server.once('error', () => resolve(false));
    server.once('listening', () => {
      server.close(() => resolve(true));
    });
    server.listen({ port, host, exclusive: true });
  });
}

export interface PortSelection {
  port: number;
  /** The originally requested port, when it had to be changed. */
  requestedPort: number;
  changed: boolean;
}

/** Finds the first free port at or after `preferred`. */
export async function findAvailablePort(
  preferred = DEFAULT_PORT,
  host = '127.0.0.1',
  maxAttempts = 50
): Promise<PortSelection> {
  for (let offset = 0; offset < maxAttempts; offset += 1) {
    const candidate = preferred + offset;
    if (candidate > 65535) break;
    if (await isPortAvailable(candidate, host)) {
      return { port: candidate, requestedPort: preferred, changed: offset > 0 };
    }
  }
  throw new Error(
    `No free port found between ${preferred} and ${Math.min(preferred + maxAttempts - 1, 65535)}. ` +
      'Pass --port to choose a different starting point.'
  );
}
