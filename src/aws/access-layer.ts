/**
 * The centralised AWS read-only access layer.
 *
 * Architecture:
 *
 *   Dashboard → AWS Access Layer → Read-Only Enforcement → API Call Tracker
 *             → AWS SDK → AWS
 *
 * No other module in this package is permitted to call `client.send(...)`
 * directly; service modules receive a `GuardedClient` from here. That makes the
 * read-only guarantee a property of the architecture rather than of the UI.
 */

import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { fromIni, fromNodeProviderChain } from '@aws-sdk/credential-providers';
import type { AwsCredentialIdentityProvider } from '@smithy/types';

import {
  classifyAwsError,
  ReadOnlyViolationError,
  type ClassifiedAwsError,
} from '../util/errors.js';
import { logger } from '../util/logger.js';
import { mapWithConcurrency, withRetry, withTimeout } from '../util/async.js';
import { ApiCallTracker } from './tracker.js';
import { assertReadOnly, operationNameOf } from './readonly-guard.js';
import type { ApiCategory, ServiceKey } from './allowlist.js';
import { ENVIRONMENT_PROFILE } from './profiles.js';
import { GLOBAL_ENDPOINT_REGION, GLOBAL_SCOPE } from './regions.js';

/** Minimal shape shared by every AWS SDK v3 client. */
export interface SdkClientLike {
  send(command: any, options?: unknown): Promise<any>;
  destroy(): void;
}

export type SdkClientConstructor<T extends SdkClientLike> = new (config: {
  region: string;
  credentials?: AwsCredentialIdentityProvider;
  maxAttempts?: number;
  retryMode?: string;
}) => T;

export interface CallContext {
  /** Dashboard section or action that caused the call, e.g. `security:s3`. */
  section: string;
  /** Override the derived operation name (defensive; normally inferred). */
  operation?: string;
}

export interface AccessLayerOptions {
  tracker?: ApiCallTracker;
  /** Per-request timeout in milliseconds. */
  requestTimeoutMs?: number;
  /** Retries for throttling/transient failures. */
  maxRetries?: number;
  /** Categories the user has disabled. Can only narrow, never widen. */
  disabledCategories?: readonly ApiCategory[];
  /** Injected for tests so no real AWS traffic is required. */
  clientFactory?: <T extends SdkClientLike>(
    ctor: SdkClientConstructor<T>,
    config: { region: string; credentials?: AwsCredentialIdentityProvider }
  ) => T;
}

export interface ProfileIdentity {
  profile: string;
  accountId?: string;
  arn?: string;
  userId?: string;
  status: 'ok' | 'error';
  error?: ClassifiedAwsError;
}

/**
 * A read-only-enforced, accounted wrapper around an AWS SDK client.
 *
 * Call sites annotate the expected output type:
 *
 * ```ts
 * const out = await client.send<DescribeSecurityGroupsCommandOutput>(
 *   new DescribeSecurityGroupsCommand({}),
 *   { section: 'security:security-groups' }
 * );
 * ```
 */
export class GuardedClient {
  constructor(
    private readonly layer: AwsAccessLayer,
    private readonly service: ServiceKey,
    private readonly client: SdkClientLike,
    private readonly profile: string,
    private readonly region: string
  ) {}

  async send<TOutput>(command: unknown, context: CallContext): Promise<TOutput> {
    return this.layer.dispatch<TOutput>({
      service: this.service,
      client: this.client,
      command,
      profile: this.profile,
      region: this.region,
      context,
    });
  }

  get regionId(): string {
    return this.region;
  }

  get profileName(): string {
    return this.profile;
  }
}

interface DispatchArgs {
  service: ServiceKey;
  client: SdkClientLike;
  command: unknown;
  profile: string;
  region: string;
  context: CallContext;
}

export class AwsAccessLayer {
  readonly tracker: ApiCallTracker;
  private readonly requestTimeoutMs: number;
  private readonly maxRetries: number;
  private disabledCategories: Set<ApiCategory>;
  private readonly clients = new Map<string, SdkClientLike>();
  private readonly credentialProviders = new Map<string, AwsCredentialIdentityProvider>();
  private readonly identities = new Map<string, Promise<ProfileIdentity>>();
  private readonly clientFactory: NonNullable<AccessLayerOptions['clientFactory']>;

  constructor(options: AccessLayerOptions = {}) {
    this.tracker = options.tracker ?? new ApiCallTracker();
    this.requestTimeoutMs = options.requestTimeoutMs ?? 30_000;
    this.maxRetries = options.maxRetries ?? 3;
    this.disabledCategories = new Set(options.disabledCategories ?? []);
    this.clientFactory =
      options.clientFactory ??
      (<T extends SdkClientLike>(
        ctor: SdkClientConstructor<T>,
        config: { region: string; credentials?: AwsCredentialIdentityProvider }
      ) =>
        new ctor({
          ...config,
          // The access layer handles its own retry policy; keep the SDK's
          // internal retries low so the API-call counter stays meaningful.
          maxAttempts: 1,
        }));
  }

  /**
   * Restricts which categories may be called. Only ever narrows: categories not
   * in the compile-time allowlist cannot be re-enabled by this call because the
   * allowlist itself is never consulted from configuration.
   */
  setDisabledCategories(categories: readonly ApiCategory[]): void {
    this.disabledCategories = new Set(categories);
  }

  isCategoryEnabled(category: ApiCategory): boolean {
    return !this.disabledCategories.has(category);
  }

  private credentialsFor(profile: string): AwsCredentialIdentityProvider | undefined {
    if (profile === ENVIRONMENT_PROFILE) {
      let provider = this.credentialProviders.get(profile);
      if (!provider) {
        provider = fromNodeProviderChain();
        this.credentialProviders.set(profile, provider);
      }
      return provider;
    }
    let provider = this.credentialProviders.get(profile);
    if (!provider) {
      provider = fromIni({ profile });
      this.credentialProviders.set(profile, provider);
    }
    return provider;
  }

  /** Builds (or reuses) a guarded client for a service/profile/region triple. */
  client<T extends SdkClientLike>(
    service: ServiceKey,
    ctor: SdkClientConstructor<T>,
    options: { profile: string; region: string }
  ): GuardedClient {
    const region = options.region === GLOBAL_SCOPE ? GLOBAL_ENDPOINT_REGION : options.region;
    const key = `${options.profile}::${service}::${region}`;
    let client = this.clients.get(key);
    if (!client) {
      client = this.clientFactory(ctor, {
        region,
        credentials: this.credentialsFor(options.profile),
      });
      this.clients.set(key, client);
    }
    return new GuardedClient(this, service, client, options.profile, options.region);
  }

  /**
   * The single choke point through which all AWS traffic flows: enforce, then
   * count, then send.
   */
  async dispatch<TOutput>(args: DispatchArgs): Promise<TOutput> {
    const operation = args.context.operation ?? operationNameOf(args.command);

    // Barrier 1-3: read-only enforcement. Throws before any network activity.
    const entry = assertReadOnly(args.service, operation);

    if (this.disabledCategories.has(entry.category)) {
      throw new ReadOnlyViolationError(
        args.service,
        operation,
        `category "${entry.category}" is disabled in local configuration`
      );
    }

    const accountId = this.cachedAccountId(args.profile);
    const startedAt = Date.now();

    try {
      const output = await withRetry(
        () =>
          withTimeout(
            args.client.send(args.command),
            this.requestTimeoutMs,
            `AWS request timed out after ${this.requestTimeoutMs}ms (${args.service}:${operation})`
          ),
        {
          retries: this.maxRetries,
          baseDelayMs: 250,
          maxDelayMs: 5_000,
          shouldRetry: (error) => classifyAwsError(error).retryable,
        }
      );

      this.tracker.record({
        category: entry.category,
        service: args.service,
        operation,
        profile: args.profile,
        ...(accountId ? { accountId } : {}),
        region: args.region,
        section: args.context.section,
        status: 'success',
        durationMs: Date.now() - startedAt,
      });

      return output as TOutput;
    } catch (error) {
      const classified = classifyAwsError(error);
      this.tracker.record({
        category: entry.category,
        service: args.service,
        operation,
        profile: args.profile,
        ...(accountId ? { accountId } : {}),
        region: args.region,
        section: args.context.section,
        status: 'error',
        durationMs: Date.now() - startedAt,
        ...(classified.code ? { errorCode: classified.code } : {}),
        errorKind: classified.kind,
      });
      logger.debug('AWS call failed', {
        service: args.service,
        operation,
        region: args.region,
        kind: classified.kind,
        code: classified.code,
      });
      throw error;
    }
  }

  private readonly accountIds = new Map<string, string>();

  private cachedAccountId(profile: string): string | undefined {
    return this.accountIds.get(profile);
  }

  /**
   * Full validation of a profile. Costs one `sts:GetCallerIdentity` call, which
   * is itself routed through the guarded path and therefore counted.
   */
  async validateProfile(profile: string, region?: string): Promise<ProfileIdentity> {
    const cached = this.identities.get(profile);
    if (cached) return cached;

    const promise = (async (): Promise<ProfileIdentity> => {
      const client = this.client('sts', STSClient, {
        profile,
        region: region ?? GLOBAL_ENDPOINT_REGION,
      });
      try {
        const output = await client.send<{ Account?: string; Arn?: string; UserId?: string }>(
          new GetCallerIdentityCommand({}),
          { section: 'profiles:validate' }
        );
        if (output.Account) this.accountIds.set(profile, output.Account);
        return {
          profile,
          status: 'ok',
          ...(output.Account ? { accountId: output.Account } : {}),
          ...(output.Arn ? { arn: output.Arn } : {}),
          ...(output.UserId ? { userId: output.UserId } : {}),
        };
      } catch (error) {
        return { profile, status: 'error', error: classifyAwsError(error) };
      }
    })();

    this.identities.set(profile, promise);
    const result = await promise;
    // Failed validations are not cached: the user may refresh SSO and retry.
    if (result.status === 'error') this.identities.delete(profile);
    return result;
  }

  async validateProfiles(profiles: readonly string[]): Promise<ProfileIdentity[]> {
    return mapWithConcurrency(profiles, 4, (profile) => this.validateProfile(profile));
  }

  accountIdFor(profile: string): string | undefined {
    return this.accountIds.get(profile);
  }

  /** Drops cached clients and identities; used when configuration changes. */
  reset(): void {
    for (const client of this.clients.values()) {
      try {
        client.destroy();
      } catch {
        // A client that refuses to close should not break a config change.
      }
    }
    this.clients.clear();
    this.credentialProviders.clear();
    this.identities.clear();
    this.accountIds.clear();
  }
}
