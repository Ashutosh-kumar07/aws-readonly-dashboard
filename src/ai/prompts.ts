/**
 * Versioned AI prompts.
 *
 * Prompts are short, structured and evidence-bound. The instruction block is
 * emitted once per request — never repeated per section — and the payload is
 * supplied as compact JSON.
 */

import type { SectionId } from '../services/types.js';

export const PROMPT_VERSION = '1.0.0';

const SECTION_FOCUS: Record<SectionId, string> = {
  billing:
    'Explain what changed in spend between the two periods, which services or regions drive the change, and which changes are worth acting on given the configured thresholds.',
  security:
    'Assess the security findings, assign a severity to each finding you report, and say plainly which areas could not be evaluated.',
  cloudwatch:
    'Identify log groups that are large, growing quickly, or retained for too long or forever, and what that implies operationally.',
  cloudtrail:
    'Characterise the activity in the supplied events: who did what, which actions failed, and anything anomalous the evidence supports.',
  'compute-optimizer':
    'Summarise the rightsizing and idle-resource opportunities AWS reported, ordered by the savings AWS itself estimated.',
};

export const RESPONSE_SCHEMA = `{
  "summary": string,
  "findings": [
    {
      "title": string,
      "severity": "critical" | "high" | "medium" | "low",
      "evidence": string,
      "sections": string[],
      "resource": string | null
    }
  ],
  "recommendations": [
    { "title": string, "detail": string, "impact": "cost" | "security" | "operations", "evidence": string }
  ],
  "costOpportunities": [ { "title": string, "estimatedMonthlySavings": number | null, "evidence": string } ],
  "securityOpportunities": [ { "title": string, "severity": "critical" | "high" | "medium" | "low", "evidence": string } ],
  "correlations": [ { "observation": string, "sections": string[], "confidence": "high" | "medium" | "low", "evidence": string } ],
  "limitations": string[]
}`;

const BASE_INSTRUCTIONS = `You are an AWS cost, security and operations analyst embedded in a read-only dashboard.

Rules you must follow:
1. Use only the JSON evidence supplied in this request. Never invent resources, events, costs, findings, permissions or API results.
2. If the evidence is insufficient to answer something, say so in "limitations" instead of guessing.
3. Every finding and recommendation must be traceable to a specific value in the supplied evidence; quote the value in "evidence".
4. Entries under "notEvaluated" mean a check could not run. Never treat them as evidence that the environment is secure or healthy.
5. Severity must be exactly one of: critical, high, medium, low. Your severity replaces the dashboard's own severity, so choose it from the evidence.
6. Do not assert that one thing caused another unless the supplied evidence supports it; use the "correlations" confidence field honestly.
7. Recommendations are advisory only. This dashboard cannot and will not perform AWS changes; write recommendations as steps a human would take in the AWS console.
8. Placeholders such as <USER_1>, <ACCOUNT_2> or <IP> are redacted or pseudonymised values. Treat identical placeholders as the same entity; never try to guess the real value.
9. Be concise. Provide reasoning as short evidence statements, not as an internal monologue.
10. Reply with a single JSON object matching the schema. No markdown fences, no commentary outside the JSON.`;

export interface PromptInput {
  kind: 'section' | 'cross-section';
  sections: SectionId[];
  profiles: string[];
  regions: string[];
  historyIncluded: boolean;
  userQuestion?: string;
  payloadJson: string;
}

export function buildPrompt(input: PromptInput): string {
  const focus = input.sections
    .map((section) => `- ${section}: ${SECTION_FOCUS[section] ?? 'Analyse the supplied evidence.'}`)
    .join('\n');

  const scope =
    input.kind === 'cross-section'
      ? `Task: analyse the selected sections together and look for relationships between them (for example a cost change that lines up with a configuration change visible in CloudTrail). Only claim a relationship the evidence supports.`
      : `Task: analyse the ${input.sections[0]} section.`;

  const history = input.historyIncluded
    ? '\nPrior analyses are included under "history". They are sanitised summaries of earlier runs; use them for trend context only, never as new evidence.'
    : '';

  const question = input.userQuestion
    ? `\nThe user additionally asks: ${input.userQuestion.slice(0, 500)}`
    : '';

  return `${BASE_INSTRUCTIONS}

${scope}
Profiles in scope: ${input.profiles.join(', ') || 'none'}
Regions in scope: ${input.regions.join(', ') || 'global only'}

Focus per section:
${focus}${history}${question}

Respond with JSON matching exactly this schema:
${RESPONSE_SCHEMA}

Evidence:
${input.payloadJson}`;
}
