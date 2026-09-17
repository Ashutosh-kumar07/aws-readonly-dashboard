/**
 * AI orchestrator.
 *
 * Responsibilities, in order:
 *   1. Accept only explicit, user-initiated analysis requests.
 *   2. Select only the sections and profiles the user chose.
 *   3. Compact the data (data minimization).
 *   4. Sanitize and pseudonymize.
 *   5. Hand the sanitized payload to exactly one provider — never a silent fallback.
 *   6. Validate the response before anything is rendered.
 *   7. Record sanitized history when, and only when, history is enabled.
 *
 * There is no automatic invocation anywhere in this class: it exposes `analyze`
 * and `preview`, and both are only reachable from an explicit API route.
 */

import { randomUUID } from 'node:crypto';

import type { AppConfig } from '../config/schema.js';
import type { SectionId } from '../services/types.js';
import { logger } from '../util/logger.js';
import { sanitize, type SanitizationReport } from './sanitizer.js';
import { buildPrompt, PROMPT_VERSION } from './prompts.js';
import { parseAiAnalysis, AiResponseError, type AiAnalysis } from './response.js';
import { AiHistoryStore, type AiHistoryEntry } from './history.js';
import { GeminiCliProvider } from './providers/gemini-cli.js';
import { CustomRestProvider } from './providers/custom-rest.js';
import { AiProviderError, type AiProvider, type AiProviderStatus } from './providers/types.js';
import type { AiPayload, CompactSectionPayload } from './payload.js';

export interface AiStatus {
  /** Provider that an analysis would use right now. */
  activeProvider: 'gemini' | 'custom' | null;
  /** True when no provider can currently be used. */
  nonLlmMode: boolean;
  providers: AiProviderStatus[];
  history: { enabled: boolean; retentionDays: number; entries: number; includeInRequests: boolean };
  promptVersion: string;
}

export interface AnalyzeRequest {
  kind: 'section' | 'cross-section';
  sections: SectionId[];
  profiles: string[];
  regions: string[];
  payloads: CompactSectionPayload[];
  userQuestion?: string;
}

export interface AnalyzePreview {
  prompt: string;
  payload: AiPayload;
  sanitizationReport: SanitizationReport;
  /** Local-only placeholder decoder; never sent anywhere. */
  mapping: Record<string, string>;
  estimatedCharacters: number;
  provider: AiProviderStatus | null;
}

export interface AnalyzeResult {
  id: string;
  analysis: AiAnalysis;
  provider: string;
  promptVersion: string;
  createdAt: string;
  durationMs: number;
  sanitizationReport: SanitizationReport;
  mapping: Record<string, string>;
  historyRecorded: boolean;
  sections: SectionId[];
  profiles: string[];
  regions: string[];
}

export class AiUnavailableError extends Error {
  override readonly name = 'AiUnavailableError';
}

export class AiOrchestrator {
  private readonly gemini: GeminiCliProvider;
  private readonly custom: CustomRestProvider;

  constructor(
    private config: AppConfig,
    readonly history: AiHistoryStore,
    providers?: { gemini?: GeminiCliProvider; custom?: CustomRestProvider }
  ) {
    this.gemini = providers?.gemini ?? new GeminiCliProvider(config.ai.gemini);
    this.custom = providers?.custom ?? new CustomRestProvider(config.ai.custom);
  }

  setConfig(config: AppConfig): void {
    this.config = config;
    this.gemini.setConfig(config.ai.gemini);
    this.custom.setConfig(config.ai.custom);
  }

  /** Probes provider availability. Called at startup and by the status route. */
  async status(force = false): Promise<AiStatus> {
    const [geminiStatus, customStatus] = await Promise.all([
      this.gemini.status(force),
      this.custom.status(),
    ]);

    const preferred = this.config.ai.provider;
    const active =
      preferred === 'custom' && customStatus.available
        ? 'custom'
        : preferred === 'gemini' && geminiStatus.available
          ? 'gemini'
          : null;

    return {
      activeProvider: active,
      nonLlmMode: active === null,
      providers: [geminiStatus, customStatus],
      history: {
        enabled: this.config.ai.history.enabled,
        retentionDays: this.config.ai.history.retentionDays,
        entries: this.history.size,
        includeInRequests: this.config.ai.history.includeInRequests,
      },
      promptVersion: PROMPT_VERSION,
    };
  }

  /**
   * Resolves the single provider to use. There is deliberately no fallback:
   * if the configured provider is unavailable the request fails and the user is
   * told, rather than data being silently routed elsewhere.
   */
  private async resolveProvider(): Promise<AiProvider> {
    const preferred = this.config.ai.provider;
    const provider: AiProvider = preferred === 'custom' ? this.custom : this.gemini;
    const status = await provider.status();
    if (!status.available) {
      throw new AiUnavailableError(
        status.detail
          ? `${status.label}. ${status.detail}`
          : `${status.label}. Configure an AI provider in Settings before requesting analysis.`
      );
    }
    return provider;
  }

  /** Builds the sanitized payload and prompt without contacting any provider. */
  async preview(request: AnalyzeRequest): Promise<AnalyzePreview> {
    const { prompt, payload, sanitization } = this.build(request);
    const [geminiStatus, customStatus] = await Promise.all([
      this.gemini.status(),
      this.custom.status(),
    ]);
    const active = this.config.ai.provider === 'custom' ? customStatus : geminiStatus;

    return {
      prompt,
      payload,
      sanitizationReport: sanitization.report,
      mapping: sanitization.mapping,
      estimatedCharacters: prompt.length,
      provider: active,
    };
  }

  private build(request: AnalyzeRequest): {
    prompt: string;
    payload: AiPayload;
    sanitization: ReturnType<typeof sanitize<AiPayload>>;
  } {
    // Profile isolation: only payloads for the selected profiles are included.
    const selectedProfiles = new Set(request.profiles);
    const sections = request.payloads.filter((payload) => selectedProfiles.has(payload.profile));

    const payload: AiPayload = {
      promptVersion: PROMPT_VERSION,
      generatedAt: new Date().toISOString(),
      analysis: {
        kind: request.kind,
        sections: request.sections,
        profiles: request.profiles,
        regions: request.regions,
      },
      sections,
      ...(request.userQuestion ? { userQuestion: request.userQuestion } : {}),
    };

    const historyEnabled =
      this.config.ai.history.enabled && this.config.ai.history.includeInRequests;
    if (historyEnabled) {
      const relevant = this.history.relevant({
        profiles: request.profiles,
        sections: request.sections,
      });
      if (relevant.length > 0) {
        payload.history = relevant.map((entry) => ({
          analysedAt: entry.createdAt,
          sections: entry.sections,
          summary: entry.analysis?.summary ?? '(previous analysis produced no summary)',
        }));
      }
    }

    const sanitization = sanitize<AiPayload>(payload, this.config.ai.sanitization.rules);
    const payloadJson = JSON.stringify(sanitization.value);
    const prompt = buildPrompt({
      kind: request.kind,
      sections: request.sections,
      profiles: request.profiles,
      regions: request.regions,
      historyIncluded: Boolean(sanitization.value.history?.length),
      ...(request.userQuestion ? { userQuestion: request.userQuestion } : {}),
      payloadJson,
    });

    return { prompt, payload: sanitization.value, sanitization };
  }

  /** Runs an analysis. Only ever called from an explicit user action. */
  async analyze(request: AnalyzeRequest): Promise<AnalyzeResult> {
    if (request.sections.length === 0) {
      throw new AiUnavailableError('Select at least one section to analyse.');
    }
    if (request.profiles.length === 0) {
      throw new AiUnavailableError('Select at least one AWS profile to analyse.');
    }

    const provider = await this.resolveProvider();
    const { prompt, sanitization } = this.build(request);
    const payloadJson = JSON.stringify(sanitization.value);
    const timeoutMs =
      this.config.ai.provider === 'custom'
        ? this.config.ai.custom.timeoutMs
        : this.config.ai.gemini.timeoutMs;

    const startedAt = Date.now();
    logger.info('Running AI analysis', {
      provider: provider.name,
      sections: request.sections,
      profiles: request.profiles.length,
      // The payload itself is never logged.
      payloadChars: payloadJson.length,
    });

    let responseText: string;
    try {
      const response = await provider.generate({ prompt, payloadJson, timeoutMs });
      responseText = response.text;
    } catch (error) {
      if (error instanceof AiProviderError) {
        await this.recordHistory(
          request,
          prompt,
          sanitization.value,
          '',
          undefined,
          error.message,
          provider.name
        );
        throw error;
      }
      throw error;
    }

    let analysis: AiAnalysis;
    try {
      analysis = parseAiAnalysis(responseText);
    } catch (error) {
      const message =
        error instanceof AiResponseError
          ? error.message
          : `The AI response could not be parsed: ${(error as Error).message}`;
      await this.recordHistory(
        request,
        prompt,
        sanitization.value,
        responseText,
        undefined,
        message,
        provider.name
      );
      throw error;
    }

    const id = randomUUID();
    const historyRecorded = await this.recordHistory(
      request,
      prompt,
      sanitization.value,
      responseText,
      analysis,
      undefined,
      provider.name,
      id
    );

    return {
      id,
      analysis,
      provider: provider.name,
      promptVersion: PROMPT_VERSION,
      createdAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      sanitizationReport: sanitization.report,
      mapping: sanitization.mapping,
      historyRecorded,
      sections: request.sections,
      profiles: request.profiles,
      regions: request.regions,
    };
  }

  /**
   * Persists a sanitized record when history is enabled. The placeholder
   * mapping is deliberately not part of the record.
   */
  private async recordHistory(
    request: AnalyzeRequest,
    prompt: string,
    sanitizedPayload: AiPayload,
    response: string,
    analysis?: AiAnalysis,
    error?: string,
    provider = 'unknown',
    id = randomUUID()
  ): Promise<boolean> {
    if (!this.config.ai.history.enabled) return false;
    const entry: AiHistoryEntry = {
      id,
      createdAt: new Date().toISOString(),
      provider,
      promptVersion: PROMPT_VERSION,
      profiles: request.profiles,
      regions: request.regions,
      sections: request.sections,
      kind: request.kind,
      sanitizedPrompt: prompt,
      sanitizedPayload,
      response,
      ...(analysis ? { analysis } : {}),
      ...(error ? { error } : {}),
    };
    try {
      await this.history.append(entry, this.config.ai.history.retentionDays);
      return true;
    } catch (historyError) {
      logger.warn('Could not write AI history', { reason: (historyError as Error).message });
      return false;
    }
  }
}
