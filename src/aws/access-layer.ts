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
import { mapWithConcurrency, timeoutError, withRetry, withTimeout } from '../util/async.js';
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
  /**
   * Where the caller had got to, e.g. "page 2, 1000 buckets so far". It is
   * carried into the deadline message, so a timeout says how much work had been
   * done rather than only that time ran out.
   */
  detail?: string;
}

export interface AccessLayerOptions {
  tracker?: ApiCallTracker;
  /** Per-request timeout in milliseconds. */
  requestTimeoutMs?: number;
  /** How many times a timed-out request may be tried again. */
  timeoutRetries?: number;
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

/** A call slower than this is worth mentioning without turning on debug logs. */
const SLOW_CALL_MS = 10_000;

export class AwsAccessLayer {
  readonly tracker: ApiCallTracker;
  private requestTimeoutMs: number;
  private readonly maxRetries: number;
  private readonly timeoutRetries: number;
  private disabledCategories: Set<ApiCategory>;
  private readonly clients = new Map<string, SdkClientLike>();
  private readonly credentialProviders = new Map<string, AwsCredentialIdentityProvider>();
  private readonly identities = new Map<string, Promise<ProfileIdentity>>();
  private readonly clientFactory: NonNullable<AccessLayerOptions['clientFactory']>;

  constructor(options: AccessLayerOptions = {}) {
    this.tracker = options.tracker ?? new ApiCallTracker();
    this.requestTimeoutMs = options.requestTimeoutMs ?? 30_000;
    this.maxRetries = options.maxRetries ?? 3;
    // A timeout has already cost `requestTimeoutMs`; retrying it three times
    // turns one slow call into two minutes of waiting, and a check that is
    // merely slow into a check that looks broken.
    this.timeoutRetries = options.timeoutRetries ?? 1;
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

  /** Applies a new per-request deadline, e.g. after the user changes Settings. */
  setRequestTimeout(milliseconds: number): void {
    if (Number.isFinite(milliseconds) && milliseconds > 0) this.requestTimeoutMs = milliseconds;
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

    let timeouts = 0;

    try {
      const output = await withRetry(() => this.sendOnce(args, operation), {
        retries: this.maxRetries,
        baseDelayMs: 250,
        maxDelayMs: 5_000,
        shouldRetry: (error) => {
          const classified = classifyAwsError(error);
          if (!classified.retryable) return false;
          if (classified.kind !== 'timeout') return true;
          timeouts += 1;
          return timeouts <= this.timeoutRetries;
        },
      });

      const durationMs = Date.now() - startedAt;
      this.tracker.record({
        category: entry.category,
        service: args.service,
        operation,
        profile: args.profile,
        ...(accountId ? { accountId } : {}),
        region: args.region,
        section: args.context.section,
        status: 'success',
        durationMs,
      });

      const call = {
        service: args.service,
        operation,
        region: args.region,
        profile: args.profile,
        durationMs,
        ...(args.context.detail ? { detail: args.context.detail } : {}),
      };
      // A call that is merely slow is invisible until it becomes a timeout, so
      // it is reported once it passes the threshold without needing debug logs.
      if (durationMs >= SLOW_CALL_MS) logger.warn('Slow AWS call', call);
      else logger.debug('AWS call', call);

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
        profile: args.profile,
        durationMs: Date.now() - startedAt,
        kind: classified.kind,
        code: classified.code,
        ...(args.context.detail ? { detail: args.context.detail } : {}),
      });
      throw error;
    }
  }

  /**
   * One attempt at a single AWS call, with a deadline that actually cancels.
   *
   * Racing a promise against a timer leaves the HTTP request running: the
   * socket stays checked out of the SDK's connection pool (50 per client by
   * default) until the server answers. Enough abandoned requests and every
   * later call waits for a free socket and times out too, so one slow call
   * turns into a section-wide outbreak of timeouts that looks like a
   * permissions problem. Aborting hands the socket back immediately.
   */
  private async sendOnce<TOutput>(args: DispatchArgs, operation: string): Promise<TOutput> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    // The operation is written without a colon so it cannot be mistaken for an
    // IAM action when the message is read back.
    const message =
      `AWS request timed out after ${this.requestTimeoutMs}ms ` +
      `(${operation} on ${args.service} in ${args.region}` +
      `${args.context.detail ? `; ${args.context.detail}` : ''})`;

    try {
      return (await withTimeout(
        args.client
          .send(args.command, {
            abortSignal: controller.signal,
            requestTimeout: this.requestTimeoutMs,
          })
          .catch((error: unknown) => {
            if (controller.signal.aborted) throw timeoutError(message);
            throw error;
          }),
        // A slightly later hard deadline, so a handler that ignores the abort
        // signal still cannot hold the scan open indefinitely.
        this.requestTimeoutMs + 1_000,
        message
      )) as TOutput;
    } finally {
      clearTimeout(timer);
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
