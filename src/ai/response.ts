/**
 * AI response parsing and validation.
 *
 * A model response is untrusted input. It is parsed, shape-checked and
 * severity-constrained before the dashboard renders any of it. Malformed output
 * produces a clear error; it is never displayed as if it were a verified fact.
 */

import { isSeverity, type Severity } from '../services/security/types.js';

export interface AiFinding {
  title: string;
  severity: Severity;
  evidence: string;
  sections: string[];
  resource: string | null;
  /** Id of the dashboard security finding this replaces, when the model matched one. */
  findingId: string | null;
}

export interface AiRecommendation {
  title: string;
  detail: string;
  impact: 'cost' | 'security' | 'operations';
  evidence: string;
}

export interface AiCostOpportunity {
  title: string;
  estimatedMonthlySavings: number | null;
  evidence: string;
}

export interface AiSecurityOpportunity {
  title: string;
  severity: Severity;
  evidence: string;
}

export interface AiCorrelation {
  observation: string;
  sections: string[];
  confidence: 'high' | 'medium' | 'low';
  evidence: string;
}

export interface AiAnalysis {
  summary: string;
  findings: AiFinding[];
  recommendations: AiRecommendation[];
  costOpportunities: AiCostOpportunity[];
  securityOpportunities: AiSecurityOpportunity[];
  correlations: AiCorrelation[];
  limitations: string[];
}

export class AiResponseError extends Error {
  override readonly name = 'AiResponseError';
  constructor(
    message: string,
    readonly rawResponse: string
  ) {
    super(message);
  }
}

/** Extracts the JSON object from a response that may carry fences or prose. */
export function extractJson(raw: string): string {
  const trimmed = raw.trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced?.[1]?.trim() ?? trimmed;
  const start = candidate.indexOf('{');
  const end = candidate.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) {
    throw new AiResponseError('The AI response did not contain a JSON object.', raw);
  }
  return candidate.slice(start, end + 1);
}

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string')
    : [];
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/** Parses and normalises a model response. Throws `AiResponseError` on garbage. */
export function parseAiAnalysis(raw: string): AiAnalysis {
  let parsed: unknown;
  try {
    parsed = JSON.parse(extractJson(raw));
  } catch (error) {
    if (error instanceof AiResponseError) throw error;
    throw new AiResponseError(
      `The AI response was not valid JSON: ${(error as Error).message}`,
      raw
    );
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new AiResponseError('The AI response was not a JSON object.', raw);
  }

  const document = parsed as Record<string, unknown>;
  const summary = asString(document.summary).trim();

  const findings: AiFinding[] = asArray(document.findings)
    .map((item) => {
      const entry = item as Record<string, unknown>;
      const severity = entry.severity;
      return {
        title: asString(entry.title).trim(),
        severity: (isSeverity(severity) ? severity : 'medium') as Severity,
        evidence: asString(entry.evidence).trim(),
        sections: asStringArray(entry.sections),
        resource: typeof entry.resource === 'string' ? entry.resource : null,
        findingId: typeof entry.findingId === 'string' && entry.findingId ? entry.findingId : null,
      };
    })
    .filter((finding) => finding.title.length > 0);

  const recommendations: AiRecommendation[] = asArray(document.recommendations)
    .map((item) => {
      const entry = item as Record<string, unknown>;
      const impact = asString(entry.impact, 'operations');
      return {
        title: asString(entry.title).trim(),
        detail: asString(entry.detail).trim(),
        impact: (['cost', 'security', 'operations'].includes(impact) ? impact : 'operations') as
          'cost' | 'security' | 'operations',
        evidence: asString(entry.evidence).trim(),
      };
    })
    .filter((recommendation) => recommendation.title.length > 0);

  const costOpportunities: AiCostOpportunity[] = asArray(document.costOpportunities)
    .map((item) => {
      const entry = item as Record<string, unknown>;
      const savings = entry.estimatedMonthlySavings;
      return {
        title: asString(entry.title).trim(),
        estimatedMonthlySavings:
          typeof savings === 'number' && Number.isFinite(savings) ? savings : null,
        evidence: asString(entry.evidence).trim(),
      };
    })
    .filter((opportunity) => opportunity.title.length > 0);

  const securityOpportunities: AiSecurityOpportunity[] = asArray(document.securityOpportunities)
    .map((item) => {
      const entry = item as Record<string, unknown>;
      const severity = entry.severity;
      return {
        title: asString(entry.title).trim(),
        severity: (isSeverity(severity) ? severity : 'medium') as Severity,
        evidence: asString(entry.evidence).trim(),
      };
    })
    .filter((opportunity) => opportunity.title.length > 0);

  const correlations: AiCorrelation[] = asArray(document.correlations)
    .map((item) => {
      const entry = item as Record<string, unknown>;
      const confidence = asString(entry.confidence, 'low');
      return {
        observation: asString(entry.observation).trim(),
        sections: asStringArray(entry.sections),
        confidence: (['high', 'medium', 'low'].includes(confidence) ? confidence : 'low') as
          'high' | 'medium' | 'low',
        evidence: asString(entry.evidence).trim(),
      };
    })
    .filter((correlation) => correlation.observation.length > 0);

  const limitations = asStringArray(document.limitations);

  if (
    !summary &&
    findings.length === 0 &&
    recommendations.length === 0 &&
    costOpportunities.length === 0 &&
    securityOpportunities.length === 0 &&
    correlations.length === 0
  ) {
    throw new AiResponseError('The AI response did not contain any usable analysis.', raw);
  }

  return {
    summary,
    findings,
    recommendations,
    costOpportunities,
    securityOpportunities,
    correlations,
    limitations,
  };
}
