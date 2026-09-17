/** Resolution of the on-disk configuration location. */

import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

export const APP_DIR_NAME = '.aws-readonly-dashboard';

export interface ConfigPaths {
  dir: string;
  configFile: string;
  findingsFile: string;
  aiHistoryFile: string;
}

/**
 * Resolution order:
 *   1. explicit `--config-dir` (passed through as `override`)
 *   2. `AWS_READONLY_DASHBOARD_HOME`
 *   3. `~/.aws-readonly-dashboard`
 */
export function resolveConfigPaths(
  override?: string,
  env: NodeJS.ProcessEnv = process.env
): ConfigPaths {
  const base = override
    ? resolve(override)
    : env.AWS_READONLY_DASHBOARD_HOME
      ? resolve(env.AWS_READONLY_DASHBOARD_HOME)
      : join(homedir(), APP_DIR_NAME);

  return {
    dir: base,
    configFile: join(base, 'config.json'),
    findingsFile: join(base, 'security-findings.json'),
    aiHistoryFile: join(base, 'ai-history.json'),
  };
}
