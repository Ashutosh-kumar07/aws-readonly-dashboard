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

function extractCode(error: any): string | undefined {
  return (
    error?.name ??
    error?.Code ??
    error?.code ??
    error?.__type ??
    error?.$metadata?.code ??
    undefined
  );
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
  const missingPermission = extractMissingPermission(rawMessage);

  const base = { code, statusCode, missingPermission };

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
