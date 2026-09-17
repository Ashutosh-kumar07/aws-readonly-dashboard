/** Best-effort browser launch, with no third-party dependency. */

import { spawn } from 'node:child_process';

import { logger } from '../util/logger.js';

export interface OpenBrowserOptions {
  platform?: NodeJS.Platform;
  spawnFn?: typeof spawn;
}

/**
 * Opens `url` in the default browser. Failure is never fatal — the CLI always
 * prints the URL as well.
 */
export function openBrowser(url: string, options: OpenBrowserOptions = {}): boolean {
  const platform = options.platform ?? process.platform;
  const spawnFn = options.spawnFn ?? spawn;

  // Only ever open our own localhost URL.
  if (!/^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/.test(url)) {
    logger.debug('Refusing to open a non-local URL in the browser', { url });
    return false;
  }

  const command = platform === 'darwin' ? 'open' : platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = platform === 'win32' ? ['/c', 'start', '', url] : [url];

  try {
    const child = spawnFn(command, args, { stdio: 'ignore', detached: true });
    child.on('error', (error) => {
      logger.debug('Could not open a browser automatically', { reason: error.message });
    });
    child.unref();
    return true;
  } catch (error) {
    logger.debug('Could not open a browser automatically', { reason: (error as Error).message });
    return false;
  }
}
