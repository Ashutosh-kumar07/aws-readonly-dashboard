/**
 * AWS region catalogue.
 *
 * Global resources (IAM, S3 bucket listing, Cost Explorer, Trusted Advisor,
 * account-level S3 public access block) are modelled as a distinct pseudo
 * region so the dashboard never presents them as if they belonged to whichever
 * regions the user happened to tick.
 */

export const GLOBAL_SCOPE = 'global' as const;

/** Endpoint used for AWS services that are only reachable globally. */
export const GLOBAL_ENDPOINT_REGION = 'us-east-1';

export interface RegionInfo {
  id: string;
  label: string;
  group: string;
}

export const REGIONS: readonly RegionInfo[] = Object.freeze([
  { id: 'us-east-1', label: 'US East (N. Virginia)', group: 'North America' },
  { id: 'us-east-2', label: 'US East (Ohio)', group: 'North America' },
  { id: 'us-west-1', label: 'US West (N. California)', group: 'North America' },
  { id: 'us-west-2', label: 'US West (Oregon)', group: 'North America' },
  { id: 'ca-central-1', label: 'Canada (Central)', group: 'North America' },
  { id: 'ca-west-1', label: 'Canada West (Calgary)', group: 'North America' },
  { id: 'sa-east-1', label: 'South America (São Paulo)', group: 'South America' },
  { id: 'eu-west-1', label: 'Europe (Ireland)', group: 'Europe' },
  { id: 'eu-west-2', label: 'Europe (London)', group: 'Europe' },
  { id: 'eu-west-3', label: 'Europe (Paris)', group: 'Europe' },
  { id: 'eu-central-1', label: 'Europe (Frankfurt)', group: 'Europe' },
  { id: 'eu-central-2', label: 'Europe (Zurich)', group: 'Europe' },
  { id: 'eu-north-1', label: 'Europe (Stockholm)', group: 'Europe' },
  { id: 'eu-south-1', label: 'Europe (Milan)', group: 'Europe' },
  { id: 'eu-south-2', label: 'Europe (Spain)', group: 'Europe' },
  { id: 'ap-south-1', label: 'Asia Pacific (Mumbai)', group: 'Asia Pacific' },
  { id: 'ap-south-2', label: 'Asia Pacific (Hyderabad)', group: 'Asia Pacific' },
  { id: 'ap-southeast-1', label: 'Asia Pacific (Singapore)', group: 'Asia Pacific' },
  { id: 'ap-southeast-2', label: 'Asia Pacific (Sydney)', group: 'Asia Pacific' },
  { id: 'ap-southeast-3', label: 'Asia Pacific (Jakarta)', group: 'Asia Pacific' },
  { id: 'ap-southeast-4', label: 'Asia Pacific (Melbourne)', group: 'Asia Pacific' },
  { id: 'ap-northeast-1', label: 'Asia Pacific (Tokyo)', group: 'Asia Pacific' },
  { id: 'ap-northeast-2', label: 'Asia Pacific (Seoul)', group: 'Asia Pacific' },
  { id: 'ap-northeast-3', label: 'Asia Pacific (Osaka)', group: 'Asia Pacific' },
  { id: 'ap-east-1', label: 'Asia Pacific (Hong Kong)', group: 'Asia Pacific' },
  { id: 'me-south-1', label: 'Middle East (Bahrain)', group: 'Middle East & Africa' },
  { id: 'me-central-1', label: 'Middle East (UAE)', group: 'Middle East & Africa' },
  { id: 'il-central-1', label: 'Israel (Tel Aviv)', group: 'Middle East & Africa' },
  { id: 'af-south-1', label: 'Africa (Cape Town)', group: 'Middle East & Africa' },
]);

export const DEFAULT_REGIONS: readonly string[] = Object.freeze(['us-east-1']);

const REGION_IDS = new Set(REGIONS.map((region) => region.id));

export function isKnownRegion(id: string): boolean {
  return REGION_IDS.has(id);
}

export function regionLabel(id: string): string {
  if (id === GLOBAL_SCOPE) return 'Global (non-regional resources)';
  return REGIONS.find((region) => region.id === id)?.label ?? id;
}

/**
 * Validates a user-supplied region list. Unknown identifiers are kept only when
 * they look like AWS region identifiers, so new regions work before this
 * catalogue is updated, while obvious junk is dropped.
 */
export function normaliseRegions(regions: readonly string[]): string[] {
  const pattern = /^[a-z]{2}(-[a-z]+)+-\d$/;
  const seen = new Set<string>();
  const result: string[] = [];
  for (const region of regions) {
    const value = String(region).trim();
    if (value === GLOBAL_SCOPE) continue; // global is always implicit
    if (!REGION_IDS.has(value) && !pattern.test(value)) continue;
    if (seen.has(value)) continue;
    seen.add(value);
    result.push(value);
  }
  return result;
}

/** Matches an AWS region identifier such as `eu-west-1` or `ap-southeast-3`. */
export const REGION_ID_PATTERN = /^[a-z]{2}(-[a-z]+)+-\d$/;

/**
 * Turns an S3 `LocationConstraint` into a usable region identifier.
 *
 * S3 predates the modern region names and still answers with the values it
 * used at the time: `null` or an empty string for us-east-1, and the legacy
 * aliases `EU` (eu-west-1) and `US` (us-east-1) for buckets old enough to have
 * been created with them. Passing those through to an SDK client builds an
 * endpoint like `s3.EU.amazonaws.com`, which resolves nowhere and shows up as
 * a timeout rather than as the routing mistake it is.
 *
 * Returns undefined when the value cannot be turned into a real region, so the
 * caller reports that honestly instead of guessing a region.
 */
export function regionFromLocationConstraint(
  constraint: string | null | undefined
): string | undefined {
  const value = (constraint ?? '').trim();
  if (value === '') return GLOBAL_ENDPOINT_REGION;
  if (value === 'EU') return 'eu-west-1';
  if (value === 'US') return GLOBAL_ENDPOINT_REGION;
  if (REGION_IDS.has(value) || REGION_ID_PATTERN.test(value)) return value;
  return undefined;
}
