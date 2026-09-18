/**
 * Dashboard HTTP API.
 *
 * Every route is a thin adapter over the application services. Two properties
 * are enforced here and visible in one place:
 *
 *   - no route can trigger an AWS mutation (the access layer refuses them), and
 *   - no route triggers an AI call except `/api/ai/analyze` and `/api/ai/preview`,
 *     which exist only to serve an explicit user action.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { allAllowedOperations, API_CATEGORY_LABELS, requiredIamActions } from '../aws/allowlist.js';
import { REGIONS, GLOBAL_SCOPE, normaliseRegions } from '../aws/regions.js';
import { HttpError } from '../util/errors.js';
import { describeChecks } from '../services/security/index.js';
import { isSectionId, type SectionId } from '../services/types.js';
import {
  buildSectionPayload,
  compactBilling,
  compactCloudTrail,
  compactCloudWatch,
  compactComputeOptimizer,
  compactSecurity,
  type CompactSectionPayload,
} from '../ai/payload.js';
import { AiUnavailableError, type AiOrchestrator } from '../ai/orchestrator.js';
import { AiProviderError } from '../ai/providers/types.js';
import { AiResponseError } from '../ai/response.js';
import type { CloudTrailSearchFilters, NormalisedEvent } from '../services/cloudtrail.js';
import type { DashboardService, SectionPartial } from './dashboard-service.js';
import { JobRunner } from './job-runner.js';
import { Router, type RequestContext } from './http.js';

const here = dirname(fileURLToPath(import.meta.url));

function readVersion(): string {
  for (const candidate of [
    join(here, '..', '..', 'package.json'),
    join(here, '..', '..', '..', 'package.json'),
  ]) {
    try {
      return JSON.parse(readFileSync(candidate, 'utf8')).version as string;
    } catch {
      continue;
    }
  }
  return '0.0.0';
}

export const PACKAGE_VERSION = readVersion();

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string');
}

function requireBody(context: RequestContext): Record<string, unknown> {
  if (!context.body || typeof context.body !== 'object' || Array.isArray(context.body)) {
    throw new HttpError(400, 'A JSON object body is required.');
  }
  return context.body as Record<string, unknown>;
}

export interface RouteDependencies {
  service: DashboardService;
  ai: AiOrchestrator;
  jobs?: JobRunner;
  serverInfo: () => { port: number; host: string; url: string; startedAt: string };
}

export function createApiRouter(deps: RouteDependencies): Router {
  const { service, ai } = deps;
  const jobs = deps.jobs ?? new JobRunner();
  const router = new Router();

  router.get('/api/status', async () => {
    const aiStatus = await ai.status();
    return {
      name: 'aws-readonly-dashboard',
      version: PACKAGE_VERSION,
      readOnly: true,
      server: deps.serverInfo(),
      ai: aiStatus,
      apiCalls: service.access.tracker.totalCalls,
      configDir: service.configService.paths.dir,
      dataInMemory: service.data.stats(),
    };
  });

  router.get('/api/config', () => service.config);

  router.put('/api/config', async (context) => {
    const body = requireBody(context);
    return service.configService.update(body as never);
  });

  router.delete('/api/config', async () => {
    const result = await service.configService.deleteAll();
    service.data.invalidateAll();
    service.access.reset();
    return { deleted: true, ...result };
  });

  router.get('/api/profiles', async () => ({ profiles: await service.listProfiles() }));

  router.post('/api/profiles/validate', async (context) => {
    const body = requireBody(context);
    const profiles = asStringArray(body.profiles);
    if (profiles.length === 0) throw new HttpError(400, 'Provide at least one profile name.');
    return { profiles: await service.validateProfiles(profiles) };
  });

  router.get('/api/regions', () => ({
    regions: REGIONS,
    global: {
      id: GLOBAL_SCOPE,
      label: 'Global (IAM, S3 inventory, Cost Explorer, Trusted Advisor)',
      alwaysIncluded: true,
    },
  }));

  router.get('/api/security/checks', () => ({ checks: describeChecks() }));

  router.get('/api/permissions', () => ({
    iamActions: requiredIamActions(),
    operations: allAllowedOperations(),
    categories: API_CATEGORY_LABELS,
  }));

  // ---- AWS sections ----------------------------------------------------

  function fetchSection(
    section: SectionId,
    options: Parameters<DashboardService['getBilling']>[0]
  ): Promise<unknown> {
    switch (section) {
      case 'billing':
        return service.getBilling(options);
      case 'security':
        return service.getSecurity(options);
      case 'cloudwatch':
        return service.getCloudWatch(options);
      case 'compute-optimizer':
        return service.getComputeOptimizer(options);
      default:
        throw new HttpError(400, `Section ${section} does not support this route.`);
    }
  }

  const sectionHandler =
    (section: SectionId) =>
    async (context: RequestContext): Promise<unknown> => {
      const body = (context.body ?? {}) as Record<string, unknown>;
      const force = body.refresh === true || context.url.searchParams.get('refresh') === 'true';
      const stream = body.stream === true || context.url.searchParams.get('stream') === 'true';
      const options = {
        profiles: asStringArray(body.profiles),
        regions: normaliseRegions(asStringArray(body.regions)),
        ...(force ? { force: true } : {}),
      };

      if (!stream) return fetchSection(section, options);

      // Streaming mode: start a job, return its first snapshot straight away,
      // and let the client poll for results as each unit of work completes.
      const selection = service.resolveSelection(options);
      return jobs.start<{ envelope: unknown; partial: SectionPartial | null }>({
        section,
        key: `${section}|${selection.profiles.join(',')}|${selection.regions.join(',')}|${
          force ? 'force' : 'cached'
        }`,
        initial: { envelope: null, partial: null },
        run: async (job) => {
          // A provisional total of one unit per profile, refined by the first
          // update once the section knows how many units it will run.
          job.setTotal(Math.max(selection.profiles.length, 1));
          const envelope = await fetchSection(section, {
            ...options,
            // Cancelling the job stops the scan at the next unit boundary.
            shouldStop: () => job.cancelled,
            // The section counts its own units, so its position is adopted
            // verbatim rather than incremented here.
            onPartial: (update) => {
              job.report(
                { envelope: null, partial: update },
                {
                  completed: update.completed,
                  total: update.total,
                  ...(update.label ? { label: update.label } : {}),
                }
              );
            },
          });
          return { envelope, partial: null };
        },
      });
    };

  router.post('/api/sections/billing', sectionHandler('billing'));
  router.post('/api/sections/security', sectionHandler('security'));
  router.post('/api/sections/cloudwatch', sectionHandler('cloudwatch'));
  router.post('/api/sections/compute-optimizer', sectionHandler('compute-optimizer'));

  router.post('/api/sections/refresh-all', async (context) => {
    const body = (context.body ?? {}) as Record<string, unknown>;
    const profiles = asStringArray(body.profiles);
    const regions = normaliseRegions(asStringArray(body.regions));
    const sections = asStringArray(body.sections).filter(isSectionId) as SectionId[];
    const requested = sections.length
      ? sections
      : (['billing', 'security', 'cloudwatch', 'compute-optimizer'] as SectionId[]);

    service.refreshAll();

    const results: Record<string, { status: 'ok' | 'error'; message?: string }> = {};
    for (const section of requested) {
      try {
        await sectionHandler(section)({
          ...context,
          body: { profiles, regions, refresh: true },
        });
        results[section] = { status: 'ok' };
      } catch (error) {
        results[section] = { status: 'error', message: (error as Error).message };
      }
    }
    return { refreshed: requested, results };
  });

  router.get('/api/jobs/:id', (context) => {
    const job = jobs.get(context.params.id as string);
    if (!job) throw new HttpError(404, 'No such job. It may have finished and been discarded.');
    return job;
  });

  router.delete('/api/jobs/:id', (context) => ({
    cancelled: jobs.cancel(context.params.id as string),
  }));

  router.post('/api/cloudtrail/search', async (context) => {
    const body = requireBody(context);
    const filters = (body.filters ?? {}) as CloudTrailSearchFilters;
    return service.searchCloudTrail({
      profiles: asStringArray(body.profiles),
      regions: normaliseRegions(asStringArray(body.regions)),
      filters,
      ...(typeof body.page === 'number' ? { page: body.page } : {}),
      ...(typeof body.pageSize === 'number' ? { pageSize: body.pageSize } : {}),
      ...(body.refresh === true ? { force: true } : {}),
    });
  });

  // ---- Security finding status ----------------------------------------

  router.patch('/api/security/findings/:id', async (context) => {
    const body = requireBody(context);
    const status = body.status;
    if (
      typeof status !== 'string' ||
      !['open', 'acknowledged', 'ignored', 'resolved'].includes(status)
    ) {
      throw new HttpError(400, 'status must be one of: open, acknowledged, ignored, resolved.');
    }
    const updated = await service.findings.setStatus(
      context.params.id as string,
      status as 'open' | 'acknowledged' | 'ignored' | 'resolved',
      typeof body.note === 'string' ? body.note : undefined
    );
    if (!updated) throw new HttpError(404, 'No such finding is tracked locally.');
    // Status is a local decision, so the cached scan result is now stale.
    service.data.invalidateSection('security');
    return { finding: updated };
  });

  router.get('/api/security/findings', () => ({ findings: service.findings.all() }));

  router.delete('/api/security/findings/resolved', async () => {
    const removed = await service.findings.deleteResolved();
    service.data.invalidateSection('security');
    return { removed };
  });

  router.delete('/api/security/findings/:id', async (context) => {
    const removed = await service.findings.delete(context.params.id as string);
    if (!removed) throw new HttpError(404, 'No such finding is tracked locally.');
    service.data.invalidateSection('security');
    return { removed: 1 };
  });

  // ---- AWS API usage ---------------------------------------------------

  router.get('/api/aws-usage', (context) => {
    const limit = Number(context.url.searchParams.get('limit') ?? 500);
    return service.access.tracker.snapshot(Number.isFinite(limit) ? limit : 500);
  });

  // ---- AI --------------------------------------------------------------

  router.get('/api/ai/status', async (context) => {
    const force = context.url.searchParams.get('refresh') === 'true';
    return ai.status(force);
  });

  /**
   * Builds the compact, section-scoped payloads for an AI request from data
   * already in memory. Sections with no data in memory are fetched, because the
   * user asked for an analysis of them.
   */
  async function collectPayloads(input: {
    sections: SectionId[];
    profiles: string[];
    regions: string[];
    selectedEvents?: NormalisedEvent[];
    /** The filters the user currently has applied in the CloudTrail view. */
    cloudtrailFilters?: CloudTrailSearchFilters;
  }): Promise<CompactSectionPayload[]> {
    const payloads: CompactSectionPayload[] = [];
    const options = { profiles: input.profiles, regions: input.regions };

    for (const section of input.sections) {
      if (section === 'billing') {
        const result = await service.getBilling(options);
        for (const profile of result.profiles) {
          if (!profile.data) continue;
          payloads.push(
            buildSectionPayload({
              section,
              profile: profile.profile,
              ...(profile.accountId ? { accountId: profile.accountId } : {}),
              regions: [GLOBAL_SCOPE],
              data: compactBilling(profile.data),
              issues: profile.issues,
            })
          );
        }
      } else if (section === 'security') {
        const result = await service.getSecurity(options);
        for (const profile of result.profiles) {
          if (!profile.data) continue;
          payloads.push(
            buildSectionPayload({
              section,
              profile: profile.profile,
              ...(profile.accountId ? { accountId: profile.accountId } : {}),
              regions: input.regions,
              data: compactSecurity(profile.data),
              issues: profile.issues,
            })
          );
        }
      } else if (section === 'cloudwatch') {
        const result = await service.getCloudWatch(options);
        for (const profile of result.profiles) {
          if (!profile.data) continue;
          payloads.push(
            buildSectionPayload({
              section,
              profile: profile.profile,
              ...(profile.accountId ? { accountId: profile.accountId } : {}),
              regions: input.regions,
              data: compactCloudWatch(profile.data),
              issues: profile.issues,
            })
          );
        }
      } else if (section === 'compute-optimizer') {
        const result = await service.getComputeOptimizer(options);
        for (const profile of result.profiles) {
          if (!profile.data) continue;
          payloads.push(
            buildSectionPayload({
              section,
              profile: profile.profile,
              ...(profile.accountId ? { accountId: profile.accountId } : {}),
              regions: input.regions,
              data: compactComputeOptimizer(profile.data),
              issues: profile.issues,
            })
          );
        }
      } else if (section === 'cloudtrail') {
        const selected = input.selectedEvents ?? [];
        if (selected.length > 0) {
          // Only the events the user picked are sent.
          const byProfile = new Map<string, NormalisedEvent[]>();
          for (const event of selected) {
            const list = byProfile.get(event.profile) ?? [];
            list.push(event);
            byProfile.set(event.profile, list);
          }
          for (const [profile, events] of byProfile) {
            if (!input.profiles.includes(profile)) continue;
            payloads.push(
              buildSectionPayload({
                section,
                profile,
                ...(events[0]?.accountId ? { accountId: events[0].accountId } : {}),
                regions: input.regions,
                data: compactCloudTrail({
                  aggregates: {},
                  total: events.length,
                  truncated: false,
                  events,
                  userSelected: true,
                }),
                issues: [],
              })
            );
          }
        } else {
          // Analyse what the user is actually looking at, not a fresh
          // unfiltered search.
          const result = await service.searchCloudTrail({
            profiles: input.profiles,
            regions: input.regions,
            filters: input.cloudtrailFilters ?? {},
          });
          const byProfile = new Map<string, NormalisedEvent[]>();
          for (const event of result.events) {
            const list = byProfile.get(event.profile) ?? [];
            list.push(event);
            byProfile.set(event.profile, list);
          }
          for (const [profile, events] of byProfile) {
            payloads.push(
              buildSectionPayload({
                section,
                profile,
                ...(events[0]?.accountId ? { accountId: events[0].accountId } : {}),
                regions: input.regions,
                data: compactCloudTrail({
                  aggregates: result.aggregates,
                  total: result.total,
                  truncated: result.truncated,
                  events,
                  userSelected: false,
                }),
                issues: result.issues.filter((issue) => issue.profile === profile),
              })
            );
          }
        }
      }
    }

    return payloads;
  }

  function parseAnalyzeRequest(context: RequestContext): {
    kind: 'section' | 'cross-section';
    sections: SectionId[];
    profiles: string[];
    regions: string[];
    selectedEvents: NormalisedEvent[];
    cloudtrailFilters: CloudTrailSearchFilters;
    userQuestion?: string;
  } {
    const body = requireBody(context);
    const sections = asStringArray(body.sections).filter(isSectionId) as SectionId[];
    if (sections.length === 0) throw new HttpError(400, 'Select at least one section to analyse.');

    const selection = service.resolveSelection({
      profiles: asStringArray(body.profiles),
      regions: normaliseRegions(asStringArray(body.regions)),
    });
    if (selection.profiles.length === 0) {
      throw new HttpError(400, 'Select at least one AWS profile to analyse.');
    }

    return {
      kind: sections.length > 1 ? 'cross-section' : 'section',
      sections,
      profiles: selection.profiles,
      regions: selection.regions,
      selectedEvents: Array.isArray(body.selectedEvents)
        ? (body.selectedEvents as NormalisedEvent[])
        : [],
      cloudtrailFilters:
        body.cloudtrailFilters && typeof body.cloudtrailFilters === 'object'
          ? (body.cloudtrailFilters as CloudTrailSearchFilters)
          : {},
      ...(typeof body.question === 'string' && body.question.trim()
        ? { userQuestion: body.question.trim() }
        : {}),
    };
  }

  router.post('/api/ai/preview', async (context) => {
    const request = parseAnalyzeRequest(context);
    const payloads = await collectPayloads(request);
    return ai.preview({
      kind: request.kind,
      sections: request.sections,
      profiles: request.profiles,
      regions: request.regions,
      payloads,
      ...(request.userQuestion ? { userQuestion: request.userQuestion } : {}),
    });
  });

  router.post('/api/ai/analyze', async (context) => {
    const request = parseAnalyzeRequest(context);
    const payloads = await collectPayloads(request);
    try {
      return await ai.analyze({
        kind: request.kind,
        sections: request.sections,
        profiles: request.profiles,
        regions: request.regions,
        payloads,
        ...(request.userQuestion ? { userQuestion: request.userQuestion } : {}),
      });
    } catch (error) {
      // AI failures must never destroy the underlying AWS data or dashboard state.
      if (error instanceof AiUnavailableError) throw new HttpError(409, error.message);
      if (error instanceof AiProviderError) {
        throw new HttpError(502, error.message, { provider: error.provider, kind: error.kind });
      }
      if (error instanceof AiResponseError) {
        throw new HttpError(502, error.message, {
          kind: 'invalid-response',
          rawResponse: error.rawResponse.slice(0, 2000),
        });
      }
      throw error;
    }
  });

  router.get('/api/ai/history', (context) => {
    const profiles = asStringArray(context.url.searchParams.getAll('profile'));
    return {
      enabled: service.config.ai.history.enabled,
      retentionDays: service.config.ai.history.retentionDays,
      entries: ai.history.list(profiles.length ? { profiles } : undefined),
    };
  });

  router.delete('/api/ai/history', async () => ({ removed: await ai.history.clear() }));

  router.delete('/api/ai/history/:id', async (context) => {
    const removed = await ai.history.delete(context.params.id as string);
    if (!removed) throw new HttpError(404, 'No such AI history entry.');
    return { removed: 1 };
  });

  return router;
}
