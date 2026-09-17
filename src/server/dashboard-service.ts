/**
 * Application service layer.
 *
 * Sits between the HTTP API and the AWS access layer. It owns the in-memory AWS
 * data lifecycle, fans work out per profile, and keeps profile/account/region
 * context attached to every result.
 */

import { createHash } from 'node:crypto';

import { AwsAccessLayer } from '../aws/access-layer.js';
import { discoverProfiles, type DiscoveredProfile } from '../aws/profiles.js';
import { GLOBAL_SCOPE, normaliseRegions } from '../aws/regions.js';
import type { ApiCategory } from '../aws/allowlist.js';
import { ConfigService } from '../config/config-service.js';
import type { AppConfig } from '../config/schema.js';
import { mapWithConcurrency } from '../util/async.js';
import { logger } from '../util/logger.js';
import { AwsDataStore } from '../services/data-store.js';
import { fetchBillingForProfile, type BillingData } from '../services/billing.js';
import { fetchCloudWatchInsights, type CloudWatchData } from '../services/cloudwatch.js';
import { fetchComputeOptimizer, type ComputeOptimizerData } from '../services/compute-optimizer.js';
import {
  runSecurityAnalysis,
  FindingStore,
  type SecurityData,
} from '../services/security/index.js';
import {
  searchCloudTrail,
  type CloudTrailSearchFilters,
  type CloudTrailSearchResult,
} from '../services/cloudtrail.js';
import type { ProfileScoped, SectionResult, Selection } from '../services/types.js';

export interface ProfileSummary extends DiscoveredProfile {
  validated: boolean;
  accountId?: string;
  arn?: string;
  error?: { kind: string; message: string };
}

export interface SectionFetchOptions {
  profiles: string[];
  regions: string[];
  force?: boolean;
}

export interface SectionEnvelope<T> extends SectionResult<T> {
  fromCache: boolean;
}

function configSignature(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 12);
}

export class DashboardService {
  readonly data = new AwsDataStore();

  constructor(
    readonly access: AwsAccessLayer,
    readonly configService: ConfigService,
    readonly findings: FindingStore
  ) {
    configService.onChange((config) => {
      this.access.setDisabledCategories(config.disabledApiCategories as ApiCategory[]);
    });
  }

  get config(): AppConfig {
    return this.configService.current;
  }

  /** Lightweight discovery: reads local config files, makes no AWS calls. */
  async listProfiles(): Promise<ProfileSummary[]> {
    const discovered = await discoverProfiles();
    return discovered.map((profile) => {
      const accountId = this.access.accountIdFor(profile.name);
      return {
        ...profile,
        validated: Boolean(accountId),
        ...(accountId ? { accountId } : {}),
      };
    });
  }

  /** Full validation: one sts:GetCallerIdentity per profile. */
  async validateProfiles(profiles: string[]): Promise<ProfileSummary[]> {
    const discovered = await discoverProfiles();
    const byName = new Map(discovered.map((profile) => [profile.name, profile]));
    const identities = await this.access.validateProfiles(profiles);

    return identities.map((identity) => {
      const base = byName.get(identity.profile) ?? {
        name: identity.profile,
        label: identity.profile,
        kind: 'unknown' as const,
        source: 'config' as const,
      };
      return {
        ...base,
        validated: identity.status === 'ok',
        ...(identity.accountId ? { accountId: identity.accountId } : {}),
        ...(identity.arn ? { arn: identity.arn } : {}),
        ...(identity.error
          ? { error: { kind: identity.error.kind, message: identity.error.message } }
          : {}),
      };
    });
  }

  /** Normalises a selection, falling back to persisted configuration. */
  resolveSelection(options: Partial<SectionFetchOptions>): Selection {
    const config = this.config;
    const profiles = options.profiles?.length ? options.profiles : config.profiles.selected;
    const regions = normaliseRegions(
      options.regions?.length ? options.regions : config.regions.selected
    );
    return { profiles: [...new Set(profiles)], regions };
  }

  private async accountFor(profile: string): Promise<string | undefined> {
    const cached = this.access.accountIdFor(profile);
    if (cached) return cached;
    const identity = await this.access.validateProfile(profile);
    return identity.accountId;
  }

  private async fanOut<T>(
    selection: Selection,
    worker: (profile: string, accountId: string | undefined) => Promise<ProfileScoped<T>>
  ): Promise<Array<ProfileScoped<T>>> {
    return mapWithConcurrency(selection.profiles, 3, async (profile) => {
      const accountId = await this.accountFor(profile);
      try {
        return await worker(profile, accountId);
      } catch (error) {
        logger.warn('Section fetch failed for profile', {
          profile,
          reason: (error as Error).message,
        });
        return {
          profile,
          ...(accountId ? { accountId } : {}),
          status: 'failed' as const,
          issues: [
            {
              profile,
              ...(accountId ? { accountId } : {}),
              region: GLOBAL_SCOPE,
              service: 'dashboard',
              kind: 'unknown' as const,
              label: 'Unable to evaluate — unexpected error',
              message: (error as Error).message,
            },
          ],
        };
      }
    });
  }

  async getBilling(options: SectionFetchOptions): Promise<SectionEnvelope<BillingData>> {
    const selection = this.resolveSelection(options);
    const config = this.config.billing;
    const variant = configSignature(config);

    const result = await this.data.resolve<Array<ProfileScoped<BillingData>>>(
      'billing',
      selection,
      () =>
        this.fanOut<BillingData>(selection, (profile, accountId) =>
          fetchBillingForProfile(this.access, {
            profile,
            ...(accountId ? { accountId } : {}),
            config,
          })
        ),
      { ...(options.force ? { force: true } : {}), variant }
    );

    return {
      section: 'billing',
      fetchedAt: result.fetchedAt,
      fromCache: result.fromCache,
      profiles: result.value,
      regions: [GLOBAL_SCOPE],
      categories: ['billing'],
    };
  }

  async getSecurity(options: SectionFetchOptions): Promise<SectionEnvelope<SecurityData>> {
    const selection = this.resolveSelection(options);
    const variant = configSignature(this.config.security);

    const result = await this.data.resolve<Array<ProfileScoped<SecurityData>>>(
      'security',
      selection,
      () =>
        this.fanOut<SecurityData>(selection, (profile, accountId) =>
          runSecurityAnalysis({
            access: this.access,
            config: this.config,
            store: this.findings,
            profile,
            ...(accountId ? { accountId } : {}),
            regions: selection.regions,
          })
        ),
      { ...(options.force ? { force: true } : {}), variant }
    );

    return {
      section: 'security',
      fetchedAt: result.fetchedAt,
      fromCache: result.fromCache,
      profiles: result.value,
      regions: selection.regions,
      categories: [
        'security-hub',
        'guardduty',
        'inspector',
        'access-analyzer',
        'trusted-advisor',
        'config',
        'cloudtrail',
        's3',
        'lambda',
        'security-groups',
        'iam',
      ],
    };
  }

  async getCloudWatch(options: SectionFetchOptions): Promise<SectionEnvelope<CloudWatchData>> {
    const selection = this.resolveSelection(options);
    const config = this.config.cloudwatch;
    const variant = configSignature(config);

    const result = await this.data.resolve<Array<ProfileScoped<CloudWatchData>>>(
      'cloudwatch',
      selection,
      () =>
        this.fanOut<CloudWatchData>(selection, (profile, accountId) =>
          fetchCloudWatchInsights(this.access, {
            profile,
            ...(accountId ? { accountId } : {}),
            regions: selection.regions,
            config,
          })
        ),
      { ...(options.force ? { force: true } : {}), variant }
    );

    return {
      section: 'cloudwatch',
      fetchedAt: result.fetchedAt,
      fromCache: result.fromCache,
      profiles: result.value,
      regions: selection.regions,
      categories: ['cloudwatch'],
    };
  }

  async getComputeOptimizer(
    options: SectionFetchOptions
  ): Promise<SectionEnvelope<ComputeOptimizerData>> {
    const selection = this.resolveSelection(options);

    const result = await this.data.resolve<Array<ProfileScoped<ComputeOptimizerData>>>(
      'compute-optimizer',
      selection,
      () =>
        this.fanOut<ComputeOptimizerData>(selection, (profile, accountId) =>
          fetchComputeOptimizer(this.access, {
            profile,
            ...(accountId ? { accountId } : {}),
            regions: selection.regions,
          })
        ),
      options.force ? { force: true } : {}
    );

    return {
      section: 'compute-optimizer',
      fetchedAt: result.fetchedAt,
      fromCache: result.fromCache,
      profiles: result.value,
      regions: selection.regions,
      categories: ['compute-optimizer'],
    };
  }

  /**
   * CloudTrail search is parameterised by the user's filters, so results are
   * keyed by the filter signature and reused while the query is unchanged.
   */
  async searchCloudTrail(options: {
    profiles: string[];
    regions: string[];
    filters: CloudTrailSearchFilters;
    page?: number;
    pageSize?: number;
    force?: boolean;
  }): Promise<
    Omit<CloudTrailSearchResult, 'events'> & {
      events: CloudTrailSearchResult['events'];
      page: number;
      pageSize: number;
      totalPages: number;
      fetchedAt: string;
      fromCache: boolean;
    }
  > {
    const selection = this.resolveSelection(options);
    const variant = configSignature({ filters: options.filters, config: this.config.cloudtrail });

    const profiles = await mapWithConcurrency(selection.profiles, 3, async (profile) => ({
      profile,
      accountId: await this.accountFor(profile),
    }));

    const result = await this.data.resolve<CloudTrailSearchResult>(
      'cloudtrail',
      selection,
      () =>
        searchCloudTrail(this.access, {
          profiles: profiles.map((entry) => ({
            profile: entry.profile,
            ...(entry.accountId ? { accountId: entry.accountId } : {}),
          })),
          regions: selection.regions,
          filters: options.filters,
          config: this.config.cloudtrail,
        }),
      { ...(options.force ? { force: true } : {}), variant }
    );

    // Pagination is applied to the in-memory result, so paging never re-queries AWS.
    const pageSize = Math.min(
      Math.max(options.pageSize ?? this.config.cloudtrail.pageSize, 10),
      200
    );
    const totalPages = Math.max(1, Math.ceil(result.value.total / pageSize));
    const page = Math.min(Math.max(options.page ?? 1, 1), totalPages);

    return {
      ...result.value,
      events: result.value.events.slice((page - 1) * pageSize, page * pageSize),
      page,
      pageSize,
      totalPages,
      fetchedAt: result.fetchedAt,
      fromCache: result.fromCache,
    };
  }

  refreshAll(): void {
    this.data.invalidateAll();
  }
}
