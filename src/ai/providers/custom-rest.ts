/**
 * Custom LLM REST provider.
 *
 * Intended for teams that already run an internal LLM gateway. The request shape
 * is fully user-defined (URL, method, headers, body template, response path), so
 * it does not assume an OpenAI- or Gemini-compatible API.
 *
 * It obeys exactly the same rules as the Gemini provider: explicit user action
 * only, sanitized payloads only, selected data only, and no automatic fallback.
 */

import {
  AiProviderError,
  type AiProvider,
  type AiProviderRequest,
  type AiProviderResponse,
  type AiProviderStatus,
} from './types.js';
import type { CustomLlmConfig } from '../../config/schema.js';

export type FetchLike = (
  input: string,
  init: { method: string; headers: Record<string, string>; body?: string; signal?: AbortSignal }
) => Promise<{ ok: boolean; status: number; statusText: string; text(): Promise<string> }>;

/** Substitutes `{{prompt}}` / `{{payload}}` as valid JSON literals. */
export function renderBodyTemplate(
  template: string,
  values: { prompt: string; payload: string }
): string {
  return template
    .replaceAll('{{prompt}}', JSON.stringify(values.prompt))
    .replaceAll('{{payload}}', values.payload)
    .replaceAll('{{promptRaw}}', values.prompt.replace(/"/g, '\\"'));
}

/** Reads a dot/bracket path such as `choices.0.message.content` out of a value. */
export function readPath(value: unknown, path: string): unknown {
  if (!path.trim()) return value;
  const segments = path
    .replace(/\[(\d+)\]/g, '.$1')
    .split('.')
    .filter(Boolean);
  let cursor: unknown = value;
  for (const segment of segments) {
    if (cursor === null || cursor === undefined) return undefined;
    if (Array.isArray(cursor)) {
      const index = Number(segment);
      if (!Number.isInteger(index)) return undefined;
      cursor = cursor[index];
    } else if (typeof cursor === 'object') {
      cursor = (cursor as Record<string, unknown>)[segment];
    } else {
      return undefined;
    }
  }
  return cursor;
}

export class CustomRestProvider implements AiProvider {
  readonly id = 'custom' as const;

  constructor(
    private config: CustomLlmConfig,
    private readonly fetchImpl: FetchLike = globalThis.fetch as unknown as FetchLike
  ) {}

  get name(): string {
    return this.config.name || 'Custom LLM';
  }

  setConfig(config: CustomLlmConfig): void {
    this.config = config;
  }

  async status(): Promise<AiProviderStatus> {
    const configured = Boolean(this.config.endpoint);
    if (!configured) {
      return {
        id: this.id,
        name: this.name,
        available: false,
        configured: false,
        enabled: this.config.enabled,
        label: 'Custom LLM: Not configured',
        detail: 'Add an endpoint URL in Settings to use a custom LLM provider.',
      };
    }
    if (!this.config.enabled) {
      return {
        id: this.id,
        name: this.name,
        available: false,
        configured: true,
        enabled: false,
        label: 'Custom LLM: Disabled',
        detail: 'The custom provider is configured but switched off.',
      };
    }
    if (!this.config.acknowledgedDataEgress) {
      return {
        id: this.id,
        name: this.name,
        available: false,
        configured: true,
        enabled: true,
        label: 'Custom LLM: Awaiting confirmation',
        detail:
          'Confirm in Settings that you understand the sanitized payload will be sent to this endpoint.',
      };
    }
    return {
      id: this.id,
      name: this.name,
      available: true,
      configured: true,
      enabled: true,
      label: 'Custom LLM: Configured',
      detail: `Requests go to ${this.config.endpoint}`,
    };
  }

  async generate(request: AiProviderRequest): Promise<AiProviderResponse> {
    const status = await this.status();
    if (!status.available) {
      throw new AiProviderError(
        status.detail ?? 'The custom LLM provider is not usable.',
        this.name,
        'configuration'
      );
    }

    const headers: Record<string, string> = {};
    for (const header of this.config.headers) {
      if (header.key.trim()) headers[header.key.trim()] = header.value;
    }
    if (
      this.config.method !== 'GET' &&
      !Object.keys(headers).some((key) => key.toLowerCase() === 'content-type')
    ) {
      headers['Content-Type'] = 'application/json';
    }

    const body =
      this.config.method === 'GET'
        ? undefined
        : renderBodyTemplate(this.config.bodyTemplate, {
            prompt: request.prompt,
            payload: request.payloadJson,
          });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), request.timeoutMs);
    const startedAt = Date.now();

    try {
      const response = await this.fetchImpl(this.config.endpoint, {
        method: this.config.method,
        headers,
        ...(body !== undefined ? { body } : {}),
        signal: controller.signal,
      });

      const text = await response.text();
      if (!response.ok) {
        throw new AiProviderError(
          `The custom LLM endpoint returned ${response.status} ${response.statusText}: ${text.slice(0, 300)}`,
          this.name,
          'transport'
        );
      }

      let output = text;
      if (this.config.responsePath) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(text);
        } catch {
          throw new AiProviderError(
            'A response path is configured but the endpoint did not return JSON.',
            this.name,
            'response'
          );
        }
        const extracted = readPath(parsed, this.config.responsePath);
        if (extracted === undefined || extracted === null) {
          throw new AiProviderError(
            `The configured response path "${this.config.responsePath}" was not present in the response.`,
            this.name,
            'response'
          );
        }
        output = typeof extracted === 'string' ? extracted : JSON.stringify(extracted);
      }

      if (!output.trim()) {
        throw new AiProviderError(
          'The custom LLM endpoint returned an empty response.',
          this.name,
          'response'
        );
      }

      return { text: output, provider: this.name, durationMs: Date.now() - startedAt };
    } catch (error) {
      if (error instanceof AiProviderError) throw error;
      if ((error as Error).name === 'AbortError') {
        throw new AiProviderError(
          `The custom LLM endpoint did not respond within ${Math.round(request.timeoutMs / 1000)}s.`,
          this.name,
          'timeout'
        );
      }
      throw new AiProviderError(
        `The custom LLM request failed: ${(error as Error).message}`,
        this.name,
        'transport'
      );
    } finally {
      clearTimeout(timer);
    }
  }
}
