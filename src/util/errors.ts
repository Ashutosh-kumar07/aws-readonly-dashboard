/**
 * AWS error classification.
 *
 * The dashboard must never turn "I could not check this" into "this is secure",
 * so every AWS failure is classified into a small, explicit taxonomy that the
 * UI renders differently.
 */

export type AwsErrorKind =
  | 'access-denied'
  | 'authentication'
  | 'not-subscribed'
  | 'service-unavailable'
  | 'unsupported-region'
  | 'throttling'
  | 'timeout'
  | 'network'
  | 'refused-by-policy'
  | 'not-found'
  | 'invalid-request'
  | 'unknown';

export interface ClassifiedAwsError {
  kind: AwsErrorKind;
  /** Short, user-facing message with no credential material in it. */
  message: string;
  /** AWS error code when the SDK provided one. */
  code?: string;
  /** The IAM action that appears to be missing, when AWS told us. */
  missingPermission?: string;
  /** HTTP status code when available. */
  statusCode?: number;
  retryable: boolean;
}

const ACCESS_DENIED_CODES = new Set([
  'AccessDenied',
  'AccessDeniedException',
  'UnauthorizedOperation',
  'AuthorizationError',
  'AccessDeniedError',
  'NotAuthorized',
  'UnauthorizedException',
  'MissingAuthenticationToken',
  'SubscriptionRequiredException',
  'OptInRequired',
  'InsufficientPrivilegesException',
]);

const AUTH_CODES = new Set([
  'ExpiredToken',
  'ExpiredTokenException',
  'InvalidClientTokenId',
  'UnrecognizedClientException',
  'InvalidAccessKeyId',
  'SignatureDoesNotMatch',
  'CredentialsError',
  'CredentialsProviderError',
  'TokenRefreshRequired',
  'SSOTokenProviderFailure',
  'InvalidGrantException',
]);

const THROTTLE_CODES = new Set([
  'Throttling',
  'ThrottlingException',
  'ThrottledException',
  'RequestLimitExceeded',
  'TooManyRequestsException',
  'LimitExceededException',
  'RequestThrottled',
  'RequestThrottledException',
  'SlowDown',
  'ProvisionedThroughputExceededException',
]);

const NOT_FOUND_CODES = new Set([
  'ResourceNotFoundException',
  'NoSuchEntity',
  'NoSuchBucket',
  'NoSuchBucketPolicy',
  'NoSuchPublicAccessBlockConfiguration',
  'NotFoundException',
  'TrailNotFoundException',
  'DetectorNotFoundException',
  'ResourceNotFoundFault',
  'NoSuchConfigurationRecorderException',
  'ServerSideEncryptionConfigurationNotFoundError',
]);

const NOT_SUBSCRIBED_CODES = new Set([
  'InvalidAccessException',
  'SubscriptionRequiredException',
  'OptInRequired',
  'AccountNotFoundException',
  'AccessDeniedForDependencyException',
  'ServiceQuotaExceededException',
  'DataUnavailableException',
  'OptInRequiredException',
]);

const UNAVAILABLE_CODES = new Set([
  'ServiceUnavailable',
  'ServiceUnavailableException',
  'InternalServerError',
  'InternalError',
  'InternalFailure',
  'ServiceFailureException',
  'InternalServiceErrorException',
  'InternalServerErrorException',
]);

/**
 * The bucket (or resource) lives in a different region than the client used.
 * S3 answers a cross-region request with a 301 and no body, which is a routing
 * problem, not a permission one.
 */
const REGION_MISMATCH_CODES = new Set([
  'PermanentRedirect',
  'AuthorizationHeaderMalformed',
  'IllegalLocationConstraintException',
]);

/**
 * Failures below the API: TLS interception by a corporate proxy, a refused or
 * broken connection, an unreachable host. The AWS CLI reads `HTTPS_PROXY` by
 * itself and the AWS SDK for JavaScript does not, which is why these show up
 * here for people whose CLI works fine.
 */
const NETWORK_CODES = new Set([
  'SELF_SIGNED_CERT_IN_CHAIN',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'CERT_HAS_EXPIRED',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'EPROTO',
  'ECONNABORTED',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EPIPE',
  'ERR_SOCKET_CONNECTION_TIMEOUT',
  'ERR_PROXY_CONNECTION_FAILED',
]);

const TIMEOUT_CODES = new Set([
  'TimeoutError',
  'RequestTimeout',
  'RequestTimeoutException',
  'ETIMEDOUT',
  'ECONNRESET',
  'ENOTFOUND',
  'EAI_AGAIN',
  'ECONNREFUSED',
  'NetworkingError',
]);

/**
 * Codes that carry no information: every plain Node error is named `Error`, so
 * preferring `name` hides the specific `code` beside it and turns a nameable
 * network or TLS failure into "unexpected error".
 */
const GENERIC_ERROR_NAMES = new Set(['Error', 'TypeError', 'Exception', '']);

function extractCode(error: any): string | undefined {
  const candidates = [
    error?.name,
    error?.Code,
    error?.code,
    error?.__type,
    error?.$metadata?.code,
  ].filter((value): value is string => typeof value === 'string' && value !== '');

  const specific = candidates.find((value) => !GENERIC_ERROR_NAMES.has(value));
  return specific ?? candidates[0];
}

/** Pulls `iam:PassRole`-style action names out of an AWS access-denied message. */
export function extractMissingPermission(message: string | undefined): string | undefined {
  if (!message) return undefined;
  const explicit = message.match(/perform(?::)?\s*:?\s*["'`]?([a-z0-9-]+:[A-Za-z0-9*]+)["'`]?/);
  if (explicit?.[1]) return explicit[1];
  const generic = message.match(/\b([a-z][a-z0-9-]{1,63}:[A-Z][A-Za-z0-9]{2,63})\b/);
  return generic?.[1];
}

export function classifyAwsError(error: unknown): ClassifiedAwsError {
  const err = error as any;
  const code = extractCode(err);
  const rawMessage: string = err?.message ?? String(error);
  const statusCode: number | undefined = err?.$metadata?.httpStatusCode;

  // A missing IAM action is only ever read out of a message AWS sent us about
  // permissions. Mining every message for an `service:Action` pattern turned
  // timeouts and internal diagnostics into invented "needs s3:GetBucketLocation"
  // advice, which sent people to fix an IAM policy that was already correct.
  const looksLikePermissionFailure =
    (code !== undefined && (ACCESS_DENIED_CODES.has(code) || AUTH_CODES.has(code))) ||
    statusCode === 403;
  const missingPermission = looksLikePermissionFailure
    ? extractMissingPermission(rawMessage)
    : undefined;

  const base = { code, statusCode, ...(missingPermission ? { missingPermission } : {}) };

  // The access layer's own refusal. Matched by name so the taxonomy does not
  // have to import the error class it is declared alongside.
  if (code === 'ReadOnlyViolationError') {
    return { ...base, kind: 'refused-by-policy', retryable: false, message: rawMessage };
  }
  if (code && ACCESS_DENIED_CODES.has(code)) {
    return {
      ...base,
      kind: 'access-denied',
      retryable: false,
      message: rawMessage || 'The credentials used are not permitted to perform this operation.',
    };
  }
  if (code && AUTH_CODES.has(code)) {
    return {
      ...base,
      kind: 'authentication',
      retryable: false,
      message:
        rawMessage ||
        'AWS credentials are missing, expired, or invalid. Refresh your session and try again.',
    };
  }
  if (code && THROTTLE_CODES.has(code)) {
    return { ...base, kind: 'throttling', retryable: true, message: rawMessage };
  }
  if (code && NOT_SUBSCRIBED_CODES.has(code)) {
    return {
      ...base,
      kind: 'not-subscribed',
      retryable: false,
      message: rawMessage || 'This AWS service is not enabled for the account.',
    };
  }
  if (code && NOT_FOUND_CODES.has(code)) {
    return { ...base, kind: 'not-found', retryable: false, message: rawMessage };
  }
  if (code && UNAVAILABLE_CODES.has(code)) {
    return { ...base, kind: 'service-unavailable', retryable: true, message: rawMessage };
  }
  if (code && TIMEOUT_CODES.has(code)) {
    return { ...base, kind: 'timeout', retryable: true, message: rawMessage };
  }
  if (code && NETWORK_CODES.has(code)) {
    return {
      ...base,
      kind: 'network',
      retryable: false,
      message:
        `${rawMessage} (${code}). ` +
        'The request did not reach AWS. If you are behind a corporate proxy, note that the AWS CLI reads HTTPS_PROXY automatically but the AWS SDK for JavaScript does not.',
    };
  }
  if (code && REGION_MISMATCH_CODES.has(code)) {
    return {
      ...base,
      kind: 'unsupported-region',
      retryable: false,
      message:
        rawMessage ||
        'AWS answered that this resource must be addressed in the region it actually lives in.',
    };
  }
  if (statusCode === 403) {
    return { ...base, kind: 'access-denied', retryable: false, message: rawMessage };
  }
  if (statusCode === 401) {
    return { ...base, kind: 'authentication', retryable: false, message: rawMessage };
  }
  if (statusCode === 429) {
    return { ...base, kind: 'throttling', retryable: true, message: rawMessage };
  }
  if (statusCode !== undefined && statusCode >= 500) {
    return { ...base, kind: 'service-unavailable', retryable: true, message: rawMessage };
  }
  if (/could not be found|is not supported in this region|endpoint/i.test(rawMessage)) {
    return { ...base, kind: 'unsupported-region', retryable: false, message: rawMessage };
  }
  if (/credential/i.test(rawMessage) && /not|unable|fail/i.test(rawMessage)) {
    return { ...base, kind: 'authentication', retryable: false, message: rawMessage };
  }
  if (statusCode !== undefined && statusCode >= 400) {
    return { ...base, kind: 'invalid-request', retryable: false, message: rawMessage };
  }
  return { ...base, kind: 'unknown', retryable: false, message: rawMessage };
}

/** Human-readable label used by the dashboard for each failure class. */
export const ERROR_KIND_LABEL: Record<AwsErrorKind, string> = {
  'access-denied': 'Unable to evaluate — insufficient permissions',
  authentication: 'Unable to evaluate — authentication failure',
  'not-subscribed': 'Unable to evaluate — AWS service not enabled',
  'service-unavailable': 'Unable to evaluate — AWS service unavailable',
  'unsupported-region': 'Unable to evaluate — not supported in this region',
  throttling: 'Unable to evaluate — AWS throttled the request',
  timeout: 'Unable to evaluate — request timed out',
  network: 'Unable to evaluate — network or TLS failure',
  'refused-by-policy': 'Unable to evaluate — refused by the read-only policy',
  'not-found': 'Unable to evaluate — resource or configuration not found',
  'invalid-request': 'Unable to evaluate — request rejected by AWS',
  unknown: 'Unable to evaluate — unexpected error',
};

/** Error thrown by the read-only access layer when an operation is refused. */
export class ReadOnlyViolationError extends Error {
  override readonly name = 'ReadOnlyViolationError';
  constructor(
    readonly service: string,
    readonly operation: string,
    readonly reason: string
  ) {
    super(
      `Read-only policy violation: ${service}:${operation} was refused by the AWS access layer (${reason}). ` +
        'aws-readonly-dashboard never performs AWS mutations.'
    );
  }
}

/** Error used for HTTP-facing failures raised by the dashboard API. */
export class HttpError extends Error {
  override readonly name = 'HttpError';
  constructor(
    readonly status: number,
    message: string,
    readonly details?: unknown
  ) {
    super(message);
  }
}

/**
 * Thrown by long-running work when the job driving it has been cancelled.
 *
 * It is control flow, not a failure: the runner ends the job as `cancelled`
 * rather than `failed`, and because the fetch rejects, a half-finished scan is
 * never stored in the section cache and never rendered as a complete result.
 */
export class JobCancelledError extends Error {
  override readonly name = 'JobCancelledError';

  constructor(message = 'Cancelled before the scan finished.') {
    super(message);
  }
}
