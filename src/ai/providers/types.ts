/** AI provider contract. Providers only ever receive sanitized payloads. */

export interface AiProviderRequest {
  /** Fully-formed, sanitized prompt. */
  prompt: string;
  /** Sanitized payload JSON, supplied separately for template-based providers. */
  payloadJson: string;
  timeoutMs: number;
}

export interface AiProviderResponse {
  text: string;
  provider: string;
  model?: string;
  durationMs: number;
}

export interface AiProviderStatus {
  id: 'gemini' | 'custom';
  name: string;
  available: boolean;
  /** Short, user-facing state such as "Gemini CLI: Available". */
  label: string;
  detail?: string;
  version?: string;
  configured: boolean;
  enabled: boolean;
}

export interface AiProvider {
  readonly id: 'gemini' | 'custom';
  readonly name: string;
  status(): Promise<AiProviderStatus>;
  generate(request: AiProviderRequest): Promise<AiProviderResponse>;
}

export class AiProviderError extends Error {
  override readonly name = 'AiProviderError';
  constructor(
    message: string,
    readonly provider: string,
    readonly kind:
      'unavailable' | 'timeout' | 'transport' | 'response' | 'configuration' = 'transport'
  ) {
    super(message);
  }
}
