/** AI Insights: explicit analysis, payload preview and history. */

import {
  el,
  badge,
  sectionHeader,
  loadingState,
  codeBlock,
  dateTime,
  money,
  number,
  toast,
  confirmDestructive,
  openDetail,
  detailGrid,
} from '../ui.js';
import { api } from '../api.js';

const SECTIONS = [
  { id: 'billing', label: 'Billing / Cost' },
  { id: 'security', label: 'Security' },
  { id: 'cloudwatch', label: 'CloudWatch' },
  { id: 'cloudtrail', label: 'CloudTrail' },
  { id: 'compute-optimizer', label: 'Compute Optimizer' },
];

function providerCard(state) {
  const ai = state.ai;
  if (!ai) return el('div', { class: 'card' }, el('p', { text: 'AI status unknown.' }));

  return el('div', { class: 'card' }, [
    el('div', { class: 'card__header' }, [
      el('h3', { class: 'card__title', text: 'AI provider status' }),
      ai.nonLlmMode ? badge('Non-LLM mode', 'high') : badge('ready', 'ok'),
    ]),
    el(
      'ul',
      { class: 'list-reset stack' },
      ai.providers.map((provider) =>
        el('li', {}, [
          el('strong', { text: provider.label }),
          provider.detail ? el('div', { class: 'subtle', text: provider.detail }) : null,
        ])
      )
    ),
    ai.nonLlmMode
      ? el('div', { class: 'notice notice--warn' }, [
          el('strong', { text: 'No AI provider is available' }),
          el('span', {
            text:
              'Install and authenticate the Gemini CLI, or configure a custom LLM REST endpoint in Settings. ' +
              'Nothing is installed or called automatically, and no other provider is used without your configuration.',
          }),
        ])
      : null,
    ai.history.enabled
      ? el('div', { class: 'notice notice--info' }, [
          el('strong', { text: 'AI history is enabled' }),
          el('span', {
            text: `Sanitized analyses are kept for ${ai.history.retentionDays} days${
              ai.history.includeInRequests
                ? ' and relevant past analyses may be included in future AI requests.'
                : '.'
            }`,
          }),
        ])
      : null,
  ]);
}

function analysisView(result) {
  const analysis = result.analysis;
  const list = (title, items, render) =>
    items.length === 0
      ? null
      : el('div', { class: 'card' }, [
          el('h3', { class: 'card__title', text: title }),
          el('ul', { class: 'list-reset stack' }, items.map(render)),
        ]);

  return el('div', {}, [
    el('div', { class: 'card' }, [
      el('div', { class: 'card__header' }, [
        el('h3', { class: 'card__title', text: 'Summary' }),
        el('span', {
          class: 'subtle',
          text: `${result.provider} · prompt v${result.promptVersion} · ${dateTime(result.createdAt)}`,
        }),
      ]),
      el('p', { text: analysis.summary || 'The model returned no summary.' }),
      el('div', { class: 'pill-row' }, [
        badge(`${result.sections.join(', ')}`, 'neutral'),
        badge(`profiles: ${result.profiles.join(', ')}`, 'neutral'),
        badge(`${result.sanitizationReport.totalReplacements} values sanitized`, 'ok'),
        result.historyRecorded ? badge('recorded in AI history', 'neutral') : null,
      ]),
    ]),

    list('Findings', analysis.findings, (finding) =>
      el('li', {}, [
        el('div', { class: 'flex-between' }, [
          el('strong', { text: finding.title }),
          badge(finding.severity, finding.severity),
        ]),
        el('div', { class: 'subtle', text: finding.evidence }),
        finding.resource ? el('div', { class: 'mono subtle', text: finding.resource }) : null,
      ])
    ),

    list('Recommendations', analysis.recommendations, (recommendation) =>
      el('li', {}, [
        el('div', { class: 'flex-between' }, [
          el('strong', { text: recommendation.title }),
          badge(recommendation.impact, 'neutral'),
        ]),
        el('div', { text: recommendation.detail }),
        el('div', { class: 'subtle', text: `Evidence: ${recommendation.evidence}` }),
      ])
    ),

    list('Cost opportunities', analysis.costOpportunities, (opportunity) =>
      el('li', {}, [
        el('div', { class: 'flex-between' }, [
          el('strong', { text: opportunity.title }),
          opportunity.estimatedMonthlySavings === null
            ? badge('no estimate', 'neutral')
            : badge(money(opportunity.estimatedMonthlySavings), 'ok'),
        ]),
        el('div', { class: 'subtle', text: opportunity.evidence }),
      ])
    ),

    list('Security opportunities', analysis.securityOpportunities, (opportunity) =>
      el('li', {}, [
        el('div', { class: 'flex-between' }, [
          el('strong', { text: opportunity.title }),
          badge(opportunity.severity, opportunity.severity),
        ]),
        el('div', { class: 'subtle', text: opportunity.evidence }),
      ])
    ),

    list('Correlations', analysis.correlations, (correlation) =>
      el('li', {}, [
        el('div', { class: 'flex-between' }, [
          el('strong', { text: correlation.observation }),
          badge(
            `${correlation.confidence} confidence`,
            correlation.confidence === 'high' ? 'ok' : 'neutral'
          ),
        ]),
        el('div', {
          class: 'subtle',
          text: `${correlation.sections.join(', ')} — ${correlation.evidence}`,
        }),
      ])
    ),

    analysis.limitations.length > 0
      ? el('div', { class: 'card' }, [
          el('h3', { class: 'card__title', text: 'Limitations stated by the model' }),
          el(
            'ul',
            {},
            analysis.limitations.map((limitation) => el('li', { text: limitation }))
          ),
        ])
      : null,

    Object.keys(result.mapping ?? {}).length > 0
      ? el('div', { class: 'card' }, [
          el('div', { class: 'card__header' }, [
            el('h3', { class: 'card__title', text: 'Placeholder decoder' }),
            el('p', {
              class: 'card__hint',
              text: 'Local only — this mapping was never sent to the provider and is not stored in AI history.',
            }),
          ]),
          el(
            'ul',
            { class: 'list-reset mono' },
            Object.entries(result.mapping).map(([placeholder, value]) =>
              el('li', { text: `${placeholder} = ${value}` })
            )
          ),
        ])
      : null,

    el('p', {
      class: 'subtle',
      text: 'AI output is advisory. This dashboard never performs AWS changes, and the model is instructed to use only the evidence supplied.',
    }),
  ]);
}

export function renderAi({ state, actions }) {
  const container = el('div', {});
  const selection = state.aiSelection;

  container.append(
    sectionHeader({
      title: 'AI Insights',
      description:
        'AI analysis runs only when you press a button here or in a section. Only the sections you select are sent, after sanitization and pseudonymization.',
      actions: [
        el('button', {
          class: 'button',
          text: 'Re-check providers',
          onClick: async () => {
            state.ai = await api.aiStatus(true);
            actions.setView('ai');
          },
        }),
      ],
    })
  );

  container.append(providerCard(state));

  container.append(
    el('div', { class: 'card' }, [
      el('div', { class: 'card__header' }, [
        el('h3', { class: 'card__title', text: 'Analyze selected data' }),
        el('p', {
          class: 'card__hint',
          text: 'Pick one section for a focused analysis, or several to look for relationships between them.',
        }),
      ]),
      el(
        'div',
        { class: 'toggle-group' },
        SECTIONS.map((section) =>
          el('button', {
            class: 'toggle',
            type: 'button',
            'aria-pressed': String(selection.sections.includes(section.id)),
            text: section.label,
            onClick: () => {
              selection.sections = selection.sections.includes(section.id)
                ? selection.sections.filter((id) => id !== section.id)
                : [...selection.sections, section.id];
              actions.setView('ai');
            },
          })
        )
      ),
      el('div', { class: 'field', style: 'margin-top:0.8rem' }, [
        el('label', { for: 'ai-question', text: 'Optional question for the model' }),
        el('input', {
          class: 'input',
          id: 'ai-question',
          type: 'text',
          placeholder: 'e.g. what drove the increase in the last 7 days?',
          value: selection.question,
          onInput: (event) => {
            selection.question = event.target.value;
          },
        }),
      ]),
      el('div', { class: 'section-header__actions' }, [
        el('button', {
          class: 'button button--primary',
          text: state.aiBusy ? 'Analysing…' : 'Analyze Selected Data',
          disabled: state.ai?.nonLlmMode || state.aiBusy || selection.sections.length === 0,
          onClick: () =>
            void actions.runAi({ sections: selection.sections, question: selection.question }),
        }),
        el('button', {
          class: 'button',
          text: 'Preview payload',
          disabled: state.aiBusy || selection.sections.length === 0,
          onClick: () =>
            void actions.previewAi({ sections: selection.sections, question: selection.question }),
        }),
      ]),
      state.ai?.nonLlmMode
        ? el('p', {
            class: 'subtle',
            text: 'Analysis is disabled in non-LLM mode. Preview still works, so you can inspect exactly what would be sent.',
          })
        : null,
    ])
  );

  if (state.aiPreview) {
    const preview = state.aiPreview;
    container.append(
      el('div', { class: 'card' }, [
        el('div', { class: 'card__header' }, [
          el('h3', { class: 'card__title', text: 'Payload preview' }),
          el('span', {
            class: 'subtle',
            text: `${number(preview.estimatedCharacters)} characters`,
          }),
        ]),
        el('p', {
          class: 'card__hint',
          text: 'This is exactly what would be sent to the provider. Sensitive values have already been redacted or pseudonymised.',
        }),
        preview.sanitizationReport.disabledRules.length > 0
          ? el('div', { class: 'notice notice--warn' }, [
              el('strong', { text: 'You have disabled some sanitization rules' }),
              el('span', {
                text: `These categories will be sent as-is: ${preview.sanitizationReport.disabledRules
                  .map((rule) => rule.label)
                  .join(', ')}.`,
              }),
            ])
          : null,
        codeBlock(preview.prompt),
      ])
    );
  }

  if (state.aiError) {
    container.append(
      el('div', { class: 'notice notice--error' }, [
        el('strong', { text: 'AI analysis failed' }),
        el('span', { text: state.aiError.message }),
        el('p', {
          class: 'subtle',
          text: 'Your AWS data and dashboard state are unchanged. Nothing was fabricated and no alternative provider was used.',
        }),
        state.aiError.details?.rawResponse
          ? el('details', {}, [
              el('summary', { text: 'Show the raw provider response' }),
              codeBlock(state.aiError.details.rawResponse),
            ])
          : null,
      ])
    );
  }

  if (state.aiBusy) container.append(loadingState('Waiting for the AI provider…'));
  if (state.aiResult) container.append(analysisView(state.aiResult));

  container.append(historyCard(state, actions));

  return container;
}

function historyCard(state, actions) {
  const card = el('div', { class: 'card' }, [
    el('div', { class: 'card__header' }, [
      el('h3', { class: 'card__title', text: 'AI history' }),
      el('div', { class: 'section-header__actions' }, [
        el('button', {
          class: 'button button--small',
          text: 'Load history',
          onClick: async () => {
            try {
              const history = await api.aiHistory();
              openDetail(
                'AI history',
                history.entries.length === 0
                  ? el('p', { text: 'No AI history is stored.' })
                  : el(
                      'div',
                      { class: 'stack' },
                      history.entries.map((entry) =>
                        el('div', { class: 'card' }, [
                          detailGrid([
                            ['When', dateTime(entry.createdAt)],
                            ['Provider', entry.provider],
                            ['Sections', entry.sections.join(', ')],
                            ['Profiles', entry.profiles.join(', ')],
                            ['Regions', entry.regions.join(', ') || 'global only'],
                            ['Prompt version', entry.promptVersion],
                            ['Error', entry.error],
                          ]),
                          el('details', {}, [
                            el('summary', { text: 'Sanitized request payload' }),
                            codeBlock(entry.sanitizedPayload),
                          ]),
                          el('details', {}, [
                            el('summary', { text: 'Provider response' }),
                            codeBlock(entry.response || '(empty)'),
                          ]),
                        ])
                      )
                    )
              );
            } catch (error) {
              toast(`Could not load AI history: ${error.message}`, 'error');
            }
          },
        }),
        el('button', {
          class: 'button button--danger button--small',
          text: 'Delete AI history',
          onClick: async () => {
            if (!confirmDestructive('Delete all locally stored AI history? This cannot be undone.'))
              return;
            try {
              const result = await api.deleteAiHistory();
              toast(
                `Deleted ${result.removed} AI history entr${result.removed === 1 ? 'y' : 'ies'}.`,
                'success'
              );
              await actions.refreshStatus();
            } catch (error) {
              toast(`Could not delete AI history: ${error.message}`, 'error');
            }
          },
        }),
      ]),
    ]),
    el('p', {
      class: 'card__hint',
      text: state.ai?.history?.enabled
        ? `Enabled · retention ${state.ai.history.retentionDays} days · ${state.ai.history.entries} entries. Only sanitized requests and responses are stored — never raw AWS data.`
        : 'Disabled. AI insights are not persisted and disappear when the server restarts. Enable it in Settings if you want trend context across runs.',
    }),
  ]);
  return card;
}
