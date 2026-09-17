/**
 * Public API.
 *
 * The package is primarily a CLI, but the pieces that make the read-only
 * guarantee verifiable are exported so they can be embedded and tested.
 */

export { startServer, type StartServerOptions, type StartedServer } from './server/index.js';
export { parseArgs, run, HELP_TEXT, type CliOptions } from './cli.js';

export { AwsAccessLayer, GuardedClient } from './aws/access-layer.js';
export { ApiCallTracker, type ApiCallRecord, type ApiUsageSnapshot } from './aws/tracker.js';
export {
  assertReadOnly,
  evaluateReadOnly,
  operationNameOf,
  MUTATING_VERB_PREFIXES,
  READ_ONLY_VERB_PREFIXES,
} from './aws/readonly-guard.js';
export {
  ALLOWLIST,
  API_CATEGORIES,
  API_CATEGORY_LABELS,
  allAllowedOperations,
  requiredIamActions,
  type ApiCategory,
  type ServiceKey,
} from './aws/allowlist.js';
export { discoverProfiles, type DiscoveredProfile } from './aws/profiles.js';
export { REGIONS, GLOBAL_SCOPE, normaliseRegions } from './aws/regions.js';

export { ConfigService } from './config/config-service.js';
export {
  defaultConfig,
  normaliseConfig,
  migrateConfig,
  CONFIG_VERSION,
  type AppConfig,
} from './config/schema.js';

export { DashboardService } from './server/dashboard-service.js';
export { SECURITY_CHECKS, describeChecks, runSecurityAnalysis } from './services/security/index.js';
export { sanitize, type SanitizationResult } from './ai/sanitizer.js';
export { AiOrchestrator } from './ai/orchestrator.js';
export { parseAiAnalysis, AiResponseError, type AiAnalysis } from './ai/response.js';
export { ReadOnlyViolationError, classifyAwsError } from './util/errors.js';
