/** AI providers, orchestration, response validation and history. */

import { describe, expect, it, vi } from 'vitest';
import { join } from 'node:path';

import { GeminiCliProvider, type Spawner } from '../src/ai/providers/gemini-cli.js';
import {
  CustomRestProvider,
  renderBodyTemplate,
  readPath,
} from '../src/ai/providers/custom-rest.js';
import { AiProviderError } from '../src/ai/providers/types.js';
import { AiOrchestrator, AiUnavailableError } from '../src/ai/orchestrator.js';
import { AiHistoryStore } from '../src/ai/history.js';
import { parseAiAnalysis, AiResponseError, extractJson } from '../src/ai/response.js';
import { buildPrompt, PROMPT_VERSION } from '../src/ai/prompts.js';
import { defaultConfig, type AppConfig } from '../src/config/schema.js';
import { withTempDir } from './helpers.js';

const VALID_RESPONSE = JSON.stringify({
  summary: 'Spend rose because of EC2.',
  findings: [
    {
      title: 'EC2 spend doubled',
      severity: 'high',
      evidence: 'current 140 vs previous 70',
      sections: ['billing'],
      resource: null,
    },
  ],
  recommendations: [
    {
      title: 'Review instance sizing',
      detail: 'Check the new instances.',
      impact: 'cost',
      evidence: 'delta 70',
    },
  ],
  costOpportunities: [],
  securityOpportunities: [],
  correlations: [],
  limitations: ['Only 7 days of data were supplied.'],
});

function spawner(
  script: Partial<
    Record<
      'version' | 'generate',
      { code?: number; stdout?: string; stderr?: string; timedOut?: boolean }
    >
  >
): Spawner {
  return async (_command, args, options) => {
    const isVersion = args.includes('--version');
    const result = isVersion ? script.version : script.generate;
    if (!result) throw new Error('command not found');
    return {
      code: result.code ?? 0,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      timedOut: result.timedOut ?? false,
      input: options.input,
    } as never;
  };
}

function payload(profile = 'dev') {
  return [
    {
      section: 'billing' as const,
      profile,
      accountId: '111122223333',
      regions: ['global'],
      data: { total: 140, owner: 'alice@example.com' },
      notEvaluated: [],
    },
  ];
}

async function orchestrator(
  overrides: Partial<AppConfig> = {},
  spawn?: Spawner,
  dir?: string
): Promise<{ ai: AiOrchestrator; history: AiHistoryStore; config: AppConfig }> {
  const config = { ...defaultConfig(), ...overrides } as AppConfig;
  const history = new AiHistoryStore(join(dir ?? '/tmp', 'ai-history.json'));
  if (config.ai.history.enabled) await history.load(config.ai.history.retentionDays);
  const gemini = new GeminiCliProvider(config.ai.gemini, spawn ?? spawner({}));
  const ai = new AiOrchestrator(config, history, { gemini });
  return { ai, history, config };
}

describe('Gemini CLI provider', () => {
  it('reports availability when the CLI answers --version', async () => {
    const provider = new GeminiCliProvider(
      defaultConfig().ai.gemini,
      spawner({ version: { stdout: 'gemini 1.2.3' } })
    );
    const status = await provider.status(true);
    expect(status.available).toBe(true);
    expect(status.label).toBe('Gemini CLI: Available');
    expect(status.version).toBe('gemini 1.2.3');
  });

  it('falls back to non-LLM mode when the CLI is missing', async () => {
    const provider = new GeminiCliProvider(defaultConfig().ai.gemini, spawner({}));
    const status = await provider.status(true);
    expect(status.available).toBe(false);
    expect(status.label).toBe('Non-LLM mode');
  });

  it('refuses to generate when the CLI is unavailable', async () => {
    const provider = new GeminiCliProvider(defaultConfig().ai.gemini, spawner({}));
    await expect(
      provider.generate({ prompt: 'hello', payloadJson: '{}', timeoutMs: 1000 })
    ).rejects.toThrow(AiProviderError);
  });

  it('passes the prompt on stdin, never on the command line', async () => {
    let seenInput: string | undefined;
    const spy: Spawner = async (_command, args, options) => {
      if (args.includes('--version'))
        return { code: 0, stdout: 'gemini 1.0', stderr: '', timedOut: false };
      seenInput = options.input;
      return { code: 0, stdout: VALID_RESPONSE, stderr: '', timedOut: false };
    };
    const provider = new GeminiCliProvider(defaultConfig().ai.gemini, spy);
    await provider.generate({ prompt: 'analyse this', payloadJson: '{}', timeoutMs: 1000 });
    expect(seenInput).toBe('analyse this');
  });

  it('surfaces a timeout clearly', async () => {
    const provider = new GeminiCliProvider(
      defaultConfig().ai.gemini,
      spawner({ version: { stdout: 'gemini 1.0' }, generate: { timedOut: true } })
    );
    await expect(
      provider.generate({ prompt: 'x', payloadJson: '{}', timeoutMs: 1000 })
    ).rejects.toThrow(/did not respond/);
  });

  it('surfaces a non-zero exit code', async () => {
    const provider = new GeminiCliProvider(
      defaultConfig().ai.gemini,
      spawner({ version: { stdout: 'gemini 1.0' }, generate: { code: 2, stderr: 'auth required' } })
    );
    await expect(
      provider.generate({ prompt: 'x', payloadJson: '{}', timeoutMs: 1000 })
    ).rejects.toThrow(/auth required/);
  });
});

describe('custom REST provider', () => {
  const base = {
    ...defaultConfig().ai.custom,
    enabled: true,
    endpoint: 'https://llm.internal.example/v1',
    acknowledgedDataEgress: true,
  };

  it('renders the body template with the prompt and payload', () => {
    const body = renderBodyTemplate('{"p": {{prompt}}, "d": {{payload}}}', {
      prompt: 'hello "world"',
      payload: '{"a":1}',
    });
    expect(JSON.parse(body)).toEqual({ p: 'hello "world"', d: { a: 1 } });
  });

  it('reads a nested response path', () => {
    expect(
      readPath({ choices: [{ message: { content: 'text' } }] }, 'choices.0.message.content')
    ).toBe('text');
    expect(readPath({ a: 1 }, 'missing.path')).toBeUndefined();
    expect(readPath({ a: 1 }, '')).toEqual({ a: 1 });
  });

  it('is unavailable until it is configured, enabled and acknowledged', async () => {
    expect((await new CustomRestProvider(defaultConfig().ai.custom).status()).label).toBe(
      'Custom LLM: Not configured'
    );
    expect((await new CustomRestProvider({ ...base, enabled: false }).status()).label).toBe(
      'Custom LLM: Disabled'
    );
    expect(
      (await new CustomRestProvider({ ...base, acknowledgedDataEgress: false }).status()).label
    ).toBe('Custom LLM: Awaiting confirmation');
    expect((await new CustomRestProvider(base).status()).label).toBe('Custom LLM: Configured');
  });

  it('sends the configured request and extracts the response', async () => {
    const calls: Array<{ url: string; init: any }> = [];
    const provider = new CustomRestProvider(
      { ...base, responsePath: 'result.text', headers: [{ key: 'X-Api-Key', value: 'secret' }] },
      async (url, init) => {
        calls.push({ url, init });
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          text: async () => JSON.stringify({ result: { text: VALID_RESPONSE } }),
        };
      }
    );

    const response = await provider.generate({
      prompt: 'p',
      payloadJson: '{"a":1}',
      timeoutMs: 5000,
    });
    expect(response.text).toBe(VALID_RESPONSE);
    expect(calls[0]?.url).toBe('https://llm.internal.example/v1');
    expect(calls[0]?.init.headers['X-Api-Key']).toBe('secret');
  });

  it('reports a transport failure without inventing a response', async () => {
    const provider = new CustomRestProvider(base, async () => ({
      ok: false,
      status: 500,
      statusText: 'Server Error',
      text: async () => 'upstream exploded',
    }));
    await expect(
      provider.generate({ prompt: 'p', payloadJson: '{}', timeoutMs: 1000 })
    ).rejects.toThrow(/500/);
  });

  it('reports a missing response path instead of guessing', async () => {
    const provider = new CustomRestProvider({ ...base, responsePath: 'nope.here' }, async () => ({
      ok: true,
      status: 200,
      statusText: 'OK',
      text: async () => JSON.stringify({ other: 'value' }),
    }));
    await expect(
      provider.generate({ prompt: 'p', payloadJson: '{}', timeoutMs: 1000 })
    ).rejects.toThrow(/response path/);
  });
});

describe('AI response validation', () => {
  it('parses a well-formed response', () => {
    const analysis = parseAiAnalysis(VALID_RESPONSE);
    expect(analysis.summary).toContain('EC2');
    expect(analysis.findings[0]?.severity).toBe('high');
    expect(analysis.limitations).toHaveLength(1);
  });

  it('tolerates markdown fences and surrounding prose', () => {
    expect(extractJson('Here you go:\n```json\n{"summary":"ok"}\n```')).toBe('{"summary":"ok"}');
    expect(parseAiAnalysis('```\n{"summary":"fine"}\n```').summary).toBe('fine');
  });

  it('rejects a response that is not JSON', () => {
    expect(() => parseAiAnalysis('I think everything is fine!')).toThrow(AiResponseError);
  });

  it('rejects a JSON response with no usable analysis', () => {
    expect(() => parseAiAnalysis('{"unrelated": true}')).toThrow(AiResponseError);
  });

  it('constrains severity to the supported values', () => {
    const analysis = parseAiAnalysis(
      JSON.stringify({
        summary: 's',
        findings: [{ title: 't', severity: 'catastrophic', evidence: 'e' }],
      })
    );
    expect(analysis.findings[0]?.severity).toBe('medium');
  });

  it('drops malformed entries rather than rendering them', () => {
    const analysis = parseAiAnalysis(
      JSON.stringify({
        summary: 's',
        findings: [{ severity: 'high' }, { title: 'kept', severity: 'low' }],
      })
    );
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]?.title).toBe('kept');
  });

  it('keeps the raw response on the error for inspection', () => {
    try {
      parseAiAnalysis('not json');
      expect.unreachable();
    } catch (error) {
      expect((error as AiResponseError).rawResponse).toBe('not json');
    }
  });
});

describe('prompt construction', () => {
  it('states the evidence-only constraints and the schema once', () => {
    const prompt = buildPrompt({
      kind: 'section',
      sections: ['billing'],
      profiles: ['dev'],
      regions: ['us-east-1'],
      historyIncluded: false,
      payloadJson: '{"a":1}',
    });
    expect(prompt).toContain('Never invent resources');
    expect(prompt).toContain('"summary"');
    expect(prompt.match(/Never invent resources/g)).toHaveLength(1);
    expect(prompt).toContain('{"a":1}');
  });

  it('describes cross-section analysis differently', () => {
    const prompt = buildPrompt({
      kind: 'cross-section',
      sections: ['billing', 'cloudtrail'],
      profiles: ['dev'],
      regions: [],
      historyIncluded: true,
      payloadJson: '{}',
    });
    expect(prompt).toContain('look for relationships');
    expect(prompt).toContain('history');
  });

  it('is versioned', () => {
    expect(PROMPT_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

describe('AI orchestration', () => {
  it('refuses to analyse in non-LLM mode instead of falling back silently', async () => {
    const { ai } = await orchestrator();
    await expect(
      ai.analyze({
        kind: 'section',
        sections: ['billing'],
        profiles: ['dev'],
        regions: [],
        payloads: payload(),
      })
    ).rejects.toThrow(AiUnavailableError);
  });

  it('never calls the provider while building a preview', async () => {
    const generate = vi.fn();
    const { ai } = await orchestrator({}, spawner({ version: { stdout: 'gemini 1.0' } }));
    (ai as never as { gemini: { generate: unknown } }).gemini.generate = generate;

    await ai.preview({
      kind: 'section',
      sections: ['billing'],
      profiles: ['dev'],
      regions: [],
      payloads: payload(),
    });
    expect(generate).not.toHaveBeenCalled();
  });

  it('sanitizes the payload before it reaches the provider', async () => {
    let seenPrompt = '';
    const spy: Spawner = async (_command, args, options) => {
      if (args.includes('--version'))
        return { code: 0, stdout: 'gemini 1.0', stderr: '', timedOut: false };
      seenPrompt = options.input ?? '';
      return { code: 0, stdout: VALID_RESPONSE, stderr: '', timedOut: false };
    };
    const { ai } = await orchestrator({}, spy);

    const result = await ai.analyze({
      kind: 'section',
      sections: ['billing'],
      profiles: ['dev'],
      regions: [],
      payloads: payload(),
    });

    expect(seenPrompt).not.toContain('alice@example.com');
    expect(seenPrompt).not.toContain('111122223333');
    expect(seenPrompt).toContain('<EMAIL>');
    expect(result.analysis.summary).toContain('EC2');
    expect(result.sanitizationReport.totalReplacements).toBeGreaterThan(0);
  });

  it('keeps the placeholder mapping local, out of the prompt', async () => {
    let seenPrompt = '';
    const spy: Spawner = async (_command, args, options) => {
      if (args.includes('--version'))
        return { code: 0, stdout: 'gemini 1.0', stderr: '', timedOut: false };
      seenPrompt = options.input ?? '';
      return { code: 0, stdout: VALID_RESPONSE, stderr: '', timedOut: false };
    };
    const { ai } = await orchestrator({}, spy);
    const result = await ai.analyze({
      kind: 'section',
      sections: ['billing'],
      profiles: ['dev'],
      regions: [],
      payloads: payload(),
    });

    expect(Object.values(result.mapping)).toContain('111122223333');
    expect(seenPrompt).not.toContain('111122223333');
  });

  it('only sends payloads for the selected profiles', async () => {
    let seenPrompt = '';
    const spy: Spawner = async (_command, args, options) => {
      if (args.includes('--version'))
        return { code: 0, stdout: 'gemini 1.0', stderr: '', timedOut: false };
      seenPrompt = options.input ?? '';
      return { code: 0, stdout: VALID_RESPONSE, stderr: '', timedOut: false };
    };
    const { ai } = await orchestrator({}, spy);

    await ai.analyze({
      kind: 'section',
      sections: ['billing'],
      profiles: ['dev'],
      regions: [],
      payloads: [...payload('dev'), ...payload('prd')],
    });

    expect(seenPrompt).toContain('"profile":"dev"');
    expect(seenPrompt).not.toContain('"profile":"prd"');
  });

  it('rejects an empty section or profile selection', async () => {
    const { ai } = await orchestrator({}, spawner({ version: { stdout: 'gemini 1.0' } }));
    await expect(
      ai.analyze({ kind: 'section', sections: [], profiles: ['dev'], regions: [], payloads: [] })
    ).rejects.toThrow(AiUnavailableError);
    await expect(
      ai.analyze({
        kind: 'section',
        sections: ['billing'],
        profiles: [],
        regions: [],
        payloads: [],
      })
    ).rejects.toThrow(AiUnavailableError);
  });

  it('surfaces an invalid model response as an error, not as an analysis', async () => {
    const { ai } = await orchestrator(
      {},
      spawner({ version: { stdout: 'gemini 1.0' }, generate: { stdout: 'I am not JSON' } })
    );
    await expect(
      ai.analyze({
        kind: 'section',
        sections: ['billing'],
        profiles: ['dev'],
        regions: [],
        payloads: payload(),
      })
    ).rejects.toThrow(AiResponseError);
  });

  it('reports non-LLM mode in its status', async () => {
    const { ai } = await orchestrator();
    const status = await ai.status(true);
    expect(status.nonLlmMode).toBe(true);
    expect(status.activeProvider).toBeNull();
    expect(status.providers.map((provider) => provider.id)).toEqual(['gemini', 'custom']);
  });
});

describe('AI history', () => {
  it('is not written when history is disabled', async () => {
    await withTempDir(async (dir) => {
      const config = defaultConfig();
      const history = new AiHistoryStore(join(dir, 'ai-history.json'));
      const gemini = new GeminiCliProvider(
        config.ai.gemini,
        spawner({ version: { stdout: 'gemini 1.0' }, generate: { stdout: VALID_RESPONSE } })
      );
      const ai = new AiOrchestrator(config, history, { gemini });

      const result = await ai.analyze({
        kind: 'section',
        sections: ['billing'],
        profiles: ['dev'],
        regions: [],
        payloads: payload(),
      });

      expect(result.historyRecorded).toBe(false);
      expect(history.size).toBe(0);
    });
  });

  it('stores only the sanitized request when history is enabled', async () => {
    await withTempDir(async (dir) => {
      const config = defaultConfig();
      config.ai.history.enabled = true;
      const history = new AiHistoryStore(join(dir, 'ai-history.json'));
      await history.load(7);
      const gemini = new GeminiCliProvider(
        config.ai.gemini,
        spawner({ version: { stdout: 'gemini 1.0' }, generate: { stdout: VALID_RESPONSE } })
      );
      const ai = new AiOrchestrator(config, history, { gemini });

      await ai.analyze({
        kind: 'section',
        sections: ['billing'],
        profiles: ['dev'],
        regions: [],
        payloads: payload(),
      });

      const entries = history.list();
      expect(entries).toHaveLength(1);
      const serialised = JSON.stringify(entries[0]);
      expect(serialised).not.toContain('alice@example.com');
      expect(serialised).not.toContain('111122223333');
      expect(entries[0]?.promptVersion).toBe(PROMPT_VERSION);
    });
  });

  it('prunes entries beyond the retention window', async () => {
    await withTempDir(async (dir) => {
      const store = new AiHistoryStore(join(dir, 'ai-history.json'));
      await store.load(7);
      const old = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString();
      await store.append(
        {
          id: 'old',
          createdAt: old,
          provider: 'Gemini CLI',
          promptVersion: PROMPT_VERSION,
          profiles: ['dev'],
          regions: [],
          sections: ['billing'],
          kind: 'section',
          sanitizedPrompt: 'p',
          sanitizedPayload: {},
          response: '{}',
        },
        7
      );
      expect(store.size).toBe(0);
    });
  });

  it('isolates history by profile', async () => {
    await withTempDir(async (dir) => {
      const store = new AiHistoryStore(join(dir, 'ai-history.json'));
      await store.load(7);
      const base = {
        createdAt: new Date().toISOString(),
        provider: 'Gemini CLI',
        promptVersion: PROMPT_VERSION,
        regions: [],
        sections: ['billing' as const],
        kind: 'section' as const,
        sanitizedPrompt: 'p',
        sanitizedPayload: {},
        response: '{}',
      };
      await store.append({ ...base, id: 'dev-entry', profiles: ['dev'] }, 7);
      await store.append({ ...base, id: 'prd-entry', profiles: ['prd'] }, 7);

      const relevant = store.relevant({ profiles: ['dev'], sections: ['billing'] });
      expect(relevant.map((entry) => entry.id)).toEqual(['dev-entry']);
    });
  });

  it('does not leak another profile into a request', async () => {
    await withTempDir(async (dir) => {
      const config = defaultConfig();
      config.ai.history.enabled = true;
      const history = new AiHistoryStore(join(dir, 'ai-history.json'));
      await history.load(7);
      await history.append(
        {
          id: 'prd-entry',
          createdAt: new Date().toISOString(),
          provider: 'Gemini CLI',
          promptVersion: PROMPT_VERSION,
          profiles: ['prd'],
          regions: [],
          sections: ['billing'],
          kind: 'section',
          sanitizedPrompt: 'p',
          sanitizedPayload: {},
          response: '{}',
          analysis: {
            summary: 'PRODUCTION-ONLY-SUMMARY',
            findings: [],
            recommendations: [],
            costOpportunities: [],
            securityOpportunities: [],
            correlations: [],
            limitations: [],
          },
        },
        7
      );

      let seenPrompt = '';
      const spy: Spawner = async (_command, args, options) => {
        if (args.includes('--version'))
          return { code: 0, stdout: 'gemini 1.0', stderr: '', timedOut: false };
        seenPrompt = options.input ?? '';
        return { code: 0, stdout: VALID_RESPONSE, stderr: '', timedOut: false };
      };
      const ai = new AiOrchestrator(config, history, {
        gemini: new GeminiCliProvider(config.ai.gemini, spy),
      });

      await ai.analyze({
        kind: 'section',
        sections: ['billing'],
        profiles: ['dev'],
        regions: [],
        payloads: payload('dev'),
      });

      expect(seenPrompt).not.toContain('PRODUCTION-ONLY-SUMMARY');
    });
  });

  it('clears history on request', async () => {
    await withTempDir(async (dir) => {
      const store = new AiHistoryStore(join(dir, 'ai-history.json'));
      await store.load(7);
      await store.append(
        {
          id: 'a',
          createdAt: new Date().toISOString(),
          provider: 'Gemini CLI',
          promptVersion: PROMPT_VERSION,
          profiles: ['dev'],
          regions: [],
          sections: ['billing'],
          kind: 'section',
          sanitizedPrompt: 'p',
          sanitizedPayload: {},
          response: '{}',
        },
        7
      );
      expect(await store.clear()).toBe(1);
      expect(store.size).toBe(0);
    });
  });
});
