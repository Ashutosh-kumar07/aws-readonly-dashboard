/**
 * Local server bootstrap.
 *
 * The server binds to the loopback interface by default and serves the
 * dashboard's static assets plus the JSON API. Nothing here listens on a public
 * interface unless the operator explicitly asks for it.
 */

import { createServer, type Server } from 'node:http';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { AwsAccessLayer } from '../aws/access-layer.js';
import type { ApiCategory } from '../aws/allowlist.js';
import { ConfigService } from '../config/config-service.js';
import type { AppConfig } from '../config/schema.js';
import { ensureDir } from '../config/json-store.js';
import { AiHistoryStore } from '../ai/history.js';
import { AiOrchestrator, type AiStatus } from '../ai/orchestrator.js';
import { FindingStore } from '../services/security/index.js';
import { HttpError } from '../util/errors.js';
import { logger, type LogLevel } from '../util/logger.js';
import { DashboardService } from './dashboard-service.js';
import { createApiRouter, PACKAGE_VERSION } from './routes.js';
import { JobRunner } from './job-runner.js';
import { readJsonBody, sendJson, serveStatic } from './http.js';
import { findAvailablePort, DEFAULT_PORT, type PortSelection } from './port.js';

const here = dirname(fileURLToPath(import.meta.url));

/** Locates `public/` for both the compiled package and a dev checkout. */
export function resolvePublicDir(): string {
  const candidates = [
    resolve(here, '..', '..', 'public'),
    resolve(here, '..', '..', '..', 'public'),
    resolve(process.cwd(), 'public'),
  ];
  return candidates[0] as string;
}

export interface StartServerOptions {
  port?: number;
  host?: string;
  configDir?: string;
  logLevel?: LogLevel;
  /** Pre-select a profile for this session (does not overwrite saved config). */
  profile?: string;
  /** Pre-select regions for this session. */
  regions?: string[];
  publicDir?: string;
}

export interface StartedServer {
  server: Server;
  /** The effective configuration this session started with. */
  config: AppConfig;
  url: string;
  port: number;
  host: string;
  portSelection: PortSelection;
  service: DashboardService;
  ai: AiOrchestrator;
  aiStatus: AiStatus;
  profilesDiscovered: number;
  close(): Promise<void>;
}

export async function startServer(options: StartServerOptions = {}): Promise<StartedServer> {
  if (options.logLevel) logger.setLevel(options.logLevel);

  const host = options.host ?? '127.0.0.1';
  const configService = new ConfigService(
    options.configDir ? { configDir: options.configDir } : {}
  );
  await ensureDir(configService.paths.dir);
  const config = await configService.load();

  // Session-only overrides from CLI flags; the saved configuration is untouched.
  if (options.profile) config.profiles.selected = [options.profile];
  if (options.regions?.length) config.regions.selected = options.regions;

  const access = new AwsAccessLayer({
    disabledCategories: config.disabledApiCategories as ApiCategory[],
  });

  const findings = new FindingStore(configService.paths.findingsFile);
  await findings.load();

  const history = new AiHistoryStore(configService.paths.aiHistoryFile);
  if (config.ai.history.enabled) {
    await history.load(config.ai.history.retentionDays);
  }

  const service = new DashboardService(access, configService, findings);
  const ai = new AiOrchestrator(config, history);
  configService.onChange((next) => ai.setConfig(next));

  // Provider availability is probed once at startup. This is a capability probe,
  // not an AI call: no prompt and no data leave the machine.
  const aiStatus = await ai.status(true);

  const publicDir = options.publicDir ?? resolvePublicDir();
  const startedAt = new Date().toISOString();
  const portSelection = await findAvailablePort(options.port ?? DEFAULT_PORT, host);
  const url = `http://${host === '0.0.0.0' ? 'localhost' : host}:${portSelection.port}`;

  const jobs = new JobRunner();
  const router = createApiRouter({
    service,
    ai,
    jobs,
    serverInfo: () => ({ port: portSelection.port, host, url, startedAt }),
  });

  const server = createServer((request, response) => {
    void (async () => {
      const requestUrl = new URL(
        request.url ?? '/',
        `http://${request.headers.host ?? 'localhost'}`
      );

      try {
        if (requestUrl.pathname.startsWith('/api/')) {
          const match = router.match(request.method ?? 'GET', requestUrl.pathname);
          if (!match) throw new HttpError(404, `No such API route: ${requestUrl.pathname}`);

          const body =
            request.method === 'GET' || request.method === 'HEAD'
              ? undefined
              : await readJsonBody(request);

          const result = await match.handler({
            request,
            response,
            url: requestUrl,
            params: match.params,
            body,
          });
          if (!response.writableEnded) sendJson(response, 200, result);
          return;
        }

        const served = await serveStatic(publicDir, requestUrl.pathname, response);
        if (served) return;

        // Unknown non-API path: fall back to the single-page shell.
        const fallback = await serveStatic(publicDir, '/index.html', response);
        if (!fallback) throw new HttpError(404, 'Not found');
      } catch (error) {
        const status = error instanceof HttpError ? error.status : 500;
        const message =
          error instanceof HttpError ? error.message : 'The dashboard hit an unexpected error.';
        if (status >= 500) {
          logger.error('Request failed', {
            path: requestUrl.pathname,
            reason: (error as Error).message,
          });
        }
        if (!response.writableEnded) {
          sendJson(response, status, {
            error: message,
            ...(error instanceof HttpError && error.details ? { details: error.details } : {}),
          });
        }
      }
    })();
  });

  await new Promise<void>((resolvePromise, reject) => {
    server.once('error', reject);
    server.listen(portSelection.port, host, () => {
      server.removeListener('error', reject);
      resolvePromise();
    });
  });

  const profiles = await service.listProfiles();

  return {
    server,
    config,
    url,
    port: portSelection.port,
    host,
    portSelection,
    service,
    ai,
    aiStatus,
    profilesDiscovered: profiles.length,
    async close() {
      await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
      jobs.clear();
      access.reset();
    },
  };
}

export { PACKAGE_VERSION, join };
