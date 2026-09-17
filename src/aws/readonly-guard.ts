/**
 * Read-only enforcement.
 *
 * Every AWS request made by this application passes through `assertReadOnly`
 * before an SDK command is dispatched. The check applies three independent
 * barriers, so a mistake in any one of them is not enough to let a mutation
 * through:
 *
 *   1. Verb denylist  — operation names beginning with a mutating verb are
 *                       rejected outright.
 *   2. Verb allowlist — the operation must begin with a known read-only verb.
 *   3. Operation allowlist — the operation must be present in the compile-time
 *                       allowlist for that specific service.
 *
 * None of these barriers consult user configuration, environment variables, or
 * on-disk state. Configuration can disable categories (narrowing what the
 * application calls) but there is no code path by which configuration can add
 * an operation.
 */

import { ReadOnlyViolationError } from '../util/errors.js';
import { lookupAllowedOperation, type AllowedOperation, type ServiceKey } from './allowlist.js';

/**
 * Verb prefixes that indicate an AWS mutation. Checked first and with priority
 * over everything else — an operation matching one of these can never run, even
 * if it were somehow present in the allowlist.
 */
export const MUTATING_VERB_PREFIXES: readonly string[] = Object.freeze([
  'Accept',
  'Activate',
  'Add',
  'Allocate',
  'Apply',
  'Assign',
  'Associate',
  'Attach',
  'Authorize',
  'Cancel',
  'Change',
  'Claim',
  'Clone',
  'Complete',
  'Configure',
  'Confirm',
  'Connect',
  'Copy',
  'Create',
  'Deactivate',
  'Decrypt',
  'Delete',
  'Deprecate',
  'Deregister',
  'Detach',
  'Disable',
  'Disassociate',
  'Discard',
  'Disconnect',
  'Enable',
  'Encrypt',
  'Execute',
  'Grant',
  'Import',
  'Initiate',
  'Invite',
  'Invoke',
  'Issue',
  'Modify',
  'Move',
  'Post',
  'Provision',
  'Publish',
  'Purchase',
  'Put',
  'Reboot',
  'Rebuild',
  'Record',
  'Register',
  'Reject',
  'Release',
  'Remediate',
  'Remove',
  'Rename',
  'Replace',
  'Reset',
  'Resize',
  'Restore',
  'Resume',
  'Revoke',
  'Rotate',
  'Run',
  'Send',
  'Set',
  'Start',
  'Stop',
  'Submit',
  'Subscribe',
  'Suspend',
  'Switch',
  'Tag',
  'Terminate',
  'Transfer',
  'Unassign',
  'Unsubscribe',
  'Untag',
  'Update',
  'Upgrade',
  'Upload',
  'Write',
]);

/**
 * Verb prefixes that denote a read. An operation must start with one of these
 * *and* be present in the service allowlist.
 */
export const READ_ONLY_VERB_PREFIXES: readonly string[] = Object.freeze([
  'BatchGet',
  'Describe',
  'Filter',
  'Get',
  'Head',
  'List',
  'Lookup',
  'Query',
  'Scan',
  'Search',
  'Select',
  'View',
]);

export interface ReadOnlyDecision {
  allowed: boolean;
  reason?: string;
  entry?: AllowedOperation;
}

/**
 * Derives the AWS operation name from an SDK command instance.
 *
 * Every AWS SDK v3 command class is named `<Operation>Command`. Anything else
 * yields an empty name, which the guard then refuses — failing closed.
 */
export function operationNameOf(command: unknown): string {
  const name = (command as { constructor?: { name?: string } })?.constructor?.name ?? '';
  return name.endsWith('Command') ? name.slice(0, -'Command'.length) : '';
}

/** Pure evaluation of the read-only policy. Never throws. */
export function evaluateReadOnly(
  service: ServiceKey | string,
  operation: string
): ReadOnlyDecision {
  if (!operation || typeof operation !== 'string') {
    return { allowed: false, reason: 'operation name could not be determined' };
  }

  const mutating = MUTATING_VERB_PREFIXES.find((prefix) => operation.startsWith(prefix));
  if (mutating) {
    return { allowed: false, reason: `operation uses the mutating verb "${mutating}"` };
  }

  const readVerb = READ_ONLY_VERB_PREFIXES.find((prefix) => operation.startsWith(prefix));
  if (!readVerb) {
    return { allowed: false, reason: 'operation does not begin with a recognised read-only verb' };
  }

  const entry = lookupAllowedOperation(service, operation);
  if (!entry) {
    return {
      allowed: false,
      reason: 'operation is not in the read-only allowlist for this service',
    };
  }

  return { allowed: true, entry };
}

/**
 * Enforces the read-only policy, throwing `ReadOnlyViolationError` when the
 * operation is refused. Returns the allowlist entry on success.
 */
export function assertReadOnly(service: ServiceKey | string, operation: string): AllowedOperation {
  const decision = evaluateReadOnly(service, operation);
  if (!decision.allowed || !decision.entry) {
    throw new ReadOnlyViolationError(String(service), operation, decision.reason ?? 'refused');
  }
  return decision.entry;
}
