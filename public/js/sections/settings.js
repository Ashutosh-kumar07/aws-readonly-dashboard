/** Settings: AI providers, sanitization rules, history, and local data control. */

import {
  el,
  sectionHeader,
  badge,
  toast,
  confirmDestructive,
  codeBlock,
  openDetail,
  table,
  number,
} from '../ui.js';
import { api } from '../api.js';

function card(title, hint, children) {
  return el('div', { class: 'card' }, [
    el('div', { class: 'card__header' }, [
      el('h3', { class: 'card__title', text: title }),
      hint ? el('p', { class: 'card__hint', text: hint }) : null,
    ]),
    ...[].concat(children),
  ]);
}

function generalCard(state, actions) {
  const ui = state.config?.ui ?? {};
  return card('Appearance and startup', null, [
    el('div', { class: 'filters' }, [
      el('div', { class: 'field' }, [
        el('label', { for: 'theme', text: 'Theme' }),
        el(
          'select',
          {
            class: 'select',
            id: 'theme',
            onChange: (event) => void actions.persist({ ui: { theme: event.target.value } }),
          },
          ['system', 'light', 'dark'].map((theme) =>
            el('option', { value: theme, text: theme, selected: ui.theme === theme })
          )
        ),
      ]),
      el('div', { class: 'field' }, [
        el('label', { for: 'auto-open', text: 'Open a browser on startup' }),
        el('input', {
          type: 'checkbox',
          id: 'auto-open',
          checked: ui.autoOpenBrowser !== false,
          onChange: (event) =>
            void actions.persist({ ui: { autoOpenBrowser: event.target.checked } }),
        }),
      ]),
    ]),
  ]);
}

function geminiCard(state, actions) {
  const gemini = state.config?.ai?.gemini ?? {};
  const status = state.ai?.providers?.find((provider) => provider.id === 'gemini');

  return card(
    'Gemini CLI (default provider)',
    'The dashboard reuses your existing Gemini CLI authentication by running the CLI as a child process. It never stores Gemini credentials and never installs the CLI for you.',
    [
      el('div', { class: 'pill-row' }, [
        status?.available ? badge(status.label, 'ok') : badge(status?.label ?? 'unknown', 'high'),
        status?.version ? badge(status.version, 'neutral') : null,
      ]),
      status?.detail ? el('p', { class: 'subtle', text: status.detail }) : null,
      el('div', { class: 'filters' }, [
        el('div', { class: 'field' }, [
          el('label', { for: 'gemini-command', text: 'Command' }),
          el('input', {
            class: 'input',
            id: 'gemini-command',
            value: gemini.command ?? 'gemini',
            onChange: (event) =>
              void actions.persist({ ai: { gemini: { command: event.target.value } } }),
          }),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'gemini-model', text: 'Model (optional)' }),
          el('input', {
            class: 'input',
            id: 'gemini-model',
            value: gemini.model ?? '',
            placeholder: 'leave blank for the CLI default',
            onChange: (event) =>
              void actions.persist({ ai: { gemini: { model: event.target.value } } }),
          }),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'gemini-timeout', text: 'Timeout (seconds)' }),
          el('input', {
            class: 'input',
            id: 'gemini-timeout',
            type: 'number',
            min: '5',
            value: String(Math.round((gemini.timeoutMs ?? 120000) / 1000)),
            onChange: (event) =>
              void actions.persist({
                ai: { gemini: { timeoutMs: Number(event.target.value) * 1000 } },
              }),
          }),
        ]),
      ]),
      el('div', { class: 'field field--inline' }, [
        el('input', {
          type: 'radio',
          name: 'ai-provider',
          id: 'provider-gemini',
          checked: state.config?.ai?.provider === 'gemini',
          onChange: () => void actions.persist({ ai: { provider: 'gemini' } }),
        }),
        el('label', { for: 'provider-gemini', text: 'Use Gemini CLI for analysis' }),
      ]),
    ]
  );
}

function customProviderCard(state, actions) {
  const custom = state.config?.ai?.custom ?? {};
  const status = state.ai?.providers?.find((provider) => provider.id === 'custom');
  const headers = custom.headers ?? [];

  const headerRows = el(
    'div',
    { class: 'stack' },
    headers.map((header, index) =>
      el('div', { class: 'filters' }, [
        el('div', { class: 'field' }, [
          el('label', { text: 'Header' }),
          el('input', {
            class: 'input',
            value: header.key,
            onChange: (event) => {
              const next = headers.map((item, position) =>
                position === index ? { ...item, key: event.target.value } : item
              );
              void actions.persist({ ai: { custom: { headers: next } } });
            },
          }),
        ]),
        el('div', { class: 'field' }, [
          el('label', { text: 'Value' }),
          el('input', {
            class: 'input',
            value: header.value,
            placeholder: 'e.g. Bearer …',
            onChange: (event) => {
              const next = headers.map((item, position) =>
                position === index ? { ...item, value: event.target.value } : item
              );
              void actions.persist({ ai: { custom: { headers: next } } });
            },
          }),
        ]),
        el('div', { class: 'field' }, [
          el('label', { text: ' ' }),
          el('button', {
            class: 'button button--small button--danger',
            type: 'button',
            text: 'Remove',
            onClick: () =>
              void actions.persist({
                ai: { custom: { headers: headers.filter((_, position) => position !== index) } },
              }),
          }),
        ]),
      ])
    )
  );

  return card(
    'Custom LLM REST endpoint',
    'For teams with an internal LLM gateway. The request shape is entirely yours: URL, method, headers, body template and response path.',
    [
      el('div', { class: 'pill-row' }, [
        status?.available
          ? badge(status.label, 'ok')
          : badge(status?.label ?? 'Not configured', 'neutral'),
      ]),
      el('div', { class: 'notice notice--warn' }, [
        el('strong', { text: 'Data leaves your machine when you use this provider' }),
        el('span', {
          text: 'The sanitized, pseudonymised payload is sent to the endpoint you configure here. You are responsible for trusting that endpoint. Nothing is sent until you enable the provider, confirm below, and press an Analyze button.',
        }),
      ]),
      el('div', { class: 'filters' }, [
        el('div', { class: 'field', style: 'flex:1 1 320px' }, [
          el('label', { for: 'custom-endpoint', text: 'Endpoint URL' }),
          el('input', {
            class: 'input',
            id: 'custom-endpoint',
            type: 'url',
            placeholder: 'https://llm.internal.example.com/v1/analyze',
            value: custom.endpoint ?? '',
            onChange: (event) =>
              void actions.persist({ ai: { custom: { endpoint: event.target.value } } }),
          }),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'custom-name', text: 'Display name' }),
          el('input', {
            class: 'input',
            id: 'custom-name',
            value: custom.name ?? 'Custom LLM',
            onChange: (event) =>
              void actions.persist({ ai: { custom: { name: event.target.value } } }),
          }),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'custom-method', text: 'Method' }),
          el(
            'select',
            {
              class: 'select',
              id: 'custom-method',
              onChange: (event) =>
                void actions.persist({ ai: { custom: { method: event.target.value } } }),
            },
            ['POST', 'PUT', 'GET'].map((method) =>
              el('option', { value: method, text: method, selected: custom.method === method })
            )
          ),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'custom-timeout', text: 'Timeout (seconds)' }),
          el('input', {
            class: 'input',
            id: 'custom-timeout',
            type: 'number',
            min: '5',
            value: String(Math.round((custom.timeoutMs ?? 120000) / 1000)),
            onChange: (event) =>
              void actions.persist({
                ai: { custom: { timeoutMs: Number(event.target.value) * 1000 } },
              }),
          }),
        ]),
      ]),

      el('h4', { text: 'Headers' }),
      headerRows,
      el('button', {
        class: 'button button--small',
        type: 'button',
        text: 'Add header',
        onClick: () =>
          void actions.persist({
            ai: { custom: { headers: [...headers, { key: '', value: '' }] } },
          }),
      }),

      el('div', { class: 'field', style: 'margin-top:0.8rem' }, [
        el('label', { for: 'custom-body', text: 'Request body template' }),
        el('textarea', {
          class: 'textarea',
          id: 'custom-body',
          onChange: (event) =>
            void actions.persist({ ai: { custom: { bodyTemplate: event.target.value } } }),
          text: custom.bodyTemplate ?? '',
        }),
        el('p', {
          class: 'subtle',
          text: '{{prompt}} is replaced with the full sanitized prompt as a JSON string. {{payload}} is replaced with the sanitized payload as raw JSON.',
        }),
      ]),

      el('div', { class: 'field' }, [
        el('label', { for: 'custom-response-path', text: 'Response path (optional)' }),
        el('input', {
          class: 'input',
          id: 'custom-response-path',
          placeholder: 'choices.0.message.content',
          value: custom.responsePath ?? '',
          onChange: (event) =>
            void actions.persist({ ai: { custom: { responsePath: event.target.value } } }),
        }),
        el('p', {
          class: 'subtle',
          text: 'Leave blank if the endpoint returns the model text directly as the body.',
        }),
      ]),

      el('div', { class: 'field field--inline' }, [
        el('input', {
          type: 'checkbox',
          id: 'custom-enabled',
          checked: custom.enabled === true,
          onChange: (event) =>
            void actions.persist({ ai: { custom: { enabled: event.target.checked } } }),
        }),
        el('label', { for: 'custom-enabled', text: 'Enable this provider' }),
      ]),
      el('div', { class: 'field field--inline' }, [
        el('input', {
          type: 'checkbox',
          id: 'custom-ack',
          checked: custom.acknowledgedDataEgress === true,
          onChange: (event) =>
            void actions.persist({
              ai: { custom: { acknowledgedDataEgress: event.target.checked } },
            }),
        }),
        el('label', {
          for: 'custom-ack',
          text: 'I understand that the sanitized payload will be sent to this endpoint',
        }),
      ]),
      el('div', { class: 'field field--inline' }, [
        el('input', {
          type: 'radio',
          name: 'ai-provider',
          id: 'provider-custom',
          checked: state.config?.ai?.provider === 'custom',
          onChange: () => void actions.persist({ ai: { provider: 'custom' } }),
        }),
        el('label', { for: 'provider-custom', text: 'Use this custom endpoint for analysis' }),
      ]),
    ]
  );
}

function sanitizationCard(state, actions) {
  const rules = state.config?.ai?.sanitization?.rules ?? [];

  const updateRules = (next) => actions.persist({ ai: { sanitization: { rules: next } } });

  return card(
    'AI data privacy',
    'Applied to every AI request, for every provider. There is no path to a provider that skips this step.',
    [
      el('p', {
        text: 'By default the following are removed or pseudonymised before anything is sent: email addresses, IP addresses, AWS account IDs, IAM user and role names, ARNs, hostnames, and instance/volume identifiers. Bucket names, Lambda function names and security group IDs are preserved because they carry infrastructure meaning without identifying a person.',
      }),
      el(
        'div',
        { class: 'stack' },
        rules.map((rule, index) =>
          el('div', { class: 'checkbox-row' }, [
            el('input', {
              type: 'checkbox',
              id: `rule-${rule.id}`,
              checked: rule.enabled || rule.locked === true,
              disabled: rule.locked === true,
              onChange: (event) =>
                void updateRules(
                  rules.map((item, position) =>
                    position === index ? { ...item, enabled: event.target.checked } : item
                  )
                ),
            }),
            el('div', { style: 'flex:1' }, [
              el('label', { for: `rule-${rule.id}` }, [
                rule.label,
                ' ',
                badge(rule.strategy, rule.strategy === 'redact' ? 'neutral' : 'ok'),
                rule.locked ? badge('always on', 'ok') : null,
              ]),
              rule.description ? el('div', { class: 'hint', text: rule.description }) : null,
              rule.pattern ? el('div', { class: 'hint mono', text: rule.pattern }) : null,
              !rule.enabled && !rule.locked
                ? el('div', { class: 'hint', style: 'color:var(--high)' }, [
                    'Disabled — you have chosen to allow this category of data in AI requests.',
                  ])
                : null,
            ]),
            rule.builtin
              ? null
              : el('button', {
                  class: 'button button--small button--danger',
                  type: 'button',
                  text: 'Remove',
                  onClick: () =>
                    void updateRules(rules.filter((_, position) => position !== index)),
                }),
          ])
        )
      ),
      el('h4', { text: 'Add a custom rule' }),
      el('div', { class: 'filters' }, [
        el('div', { class: 'field' }, [
          el('label', { for: 'rule-label', text: 'Label' }),
          el('input', { class: 'input', id: 'rule-label', placeholder: 'Internal ticket IDs' }),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'rule-pattern', text: 'Regular expression' }),
          el('input', { class: 'input mono', id: 'rule-pattern', placeholder: 'TICKET-\\d+' }),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'rule-placeholder', text: 'Placeholder' }),
          el('input', { class: 'input', id: 'rule-placeholder', placeholder: 'TICKET' }),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'rule-strategy', text: 'Strategy' }),
          el(
            'select',
            { class: 'select', id: 'rule-strategy' },
            [
              { value: 'redact', label: 'Redact' },
              { value: 'pseudonymize', label: 'Pseudonymise (stable placeholder)' },
            ].map((option) => el('option', { value: option.value, text: option.label }))
          ),
        ]),
        el('div', { class: 'field' }, [
          el('label', { text: ' ' }),
          el('button', {
            class: 'button',
            type: 'button',
            text: 'Add rule',
            onClick: () => {
              const label = document.getElementById('rule-label').value.trim();
              const pattern = document.getElementById('rule-pattern').value.trim();
              const placeholder =
                document.getElementById('rule-placeholder').value.trim() || 'CUSTOM';
              const strategy = document.getElementById('rule-strategy').value;
              if (!label || !pattern) {
                toast('A label and a regular expression are required.', 'error');
                return;
              }
              try {
                new RegExp(pattern);
              } catch (error) {
                toast(`That is not a valid regular expression: ${error.message}`, 'error');
                return;
              }
              void updateRules([
                ...rules,
                {
                  id: `custom-${Date.now()}`,
                  label,
                  pattern,
                  flags: 'g',
                  placeholder,
                  strategy,
                  enabled: true,
                  builtin: false,
                },
              ]);
              toast('Custom sanitization rule added.', 'success');
            },
          }),
        ]),
      ]),
    ]
  );
}

function historyCard(state, actions) {
  const history = state.config?.ai?.history ?? {};
  return card(
    'AI history',
    'Off by default. When enabled, only the sanitized request and the provider response are stored — never raw AWS data.',
    [
      el('div', { class: 'field field--inline' }, [
        el('input', {
          type: 'checkbox',
          id: 'history-enabled',
          checked: history.enabled === true,
          onChange: (event) =>
            void actions.persist({ ai: { history: { enabled: event.target.checked } } }),
        }),
        el('label', { for: 'history-enabled', text: 'Store AI history locally' }),
      ]),
      el('div', { class: 'filters' }, [
        el('div', { class: 'field' }, [
          el('label', { for: 'history-retention', text: 'Retention (days, max 30)' }),
          el('input', {
            class: 'input',
            id: 'history-retention',
            type: 'number',
            min: '1',
            max: '30',
            value: String(history.retentionDays ?? 7),
            onChange: (event) =>
              void actions.persist({
                ai: { history: { retentionDays: Number(event.target.value) } },
              }),
          }),
        ]),
        el('div', { class: 'field field--inline' }, [
          el('input', {
            type: 'checkbox',
            id: 'history-include',
            checked: history.includeInRequests !== false,
            onChange: (event) =>
              void actions.persist({
                ai: { history: { includeInRequests: event.target.checked } },
              }),
          }),
          el('label', {
            for: 'history-include',
            text: 'Include relevant past analyses in future AI requests',
          }),
        ]),
      ]),
      history.enabled
        ? el('div', { class: 'notice notice--info' }, [
            el('strong', { text: 'AI history is enabled' }),
            el('span', {
              text:
                history.includeInRequests !== false
                  ? 'Future AI insights may use retained past analysis data for the same profiles.'
                  : 'History is stored but is not sent with future requests.',
            }),
          ])
        : null,
      el('button', {
        class: 'button button--danger',
        type: 'button',
        text: 'Delete AI history',
        onClick: async () => {
          if (!confirmDestructive('Delete all locally stored AI history? This cannot be undone.'))
            return;
          try {
            const result = await api.deleteAiHistory();
            toast(
              `Deleted ${result.removed} entr${result.removed === 1 ? 'y' : 'ies'}.`,
              'success'
            );
            await actions.refreshStatus();
          } catch (error) {
            toast(`Could not delete AI history: ${error.message}`, 'error');
          }
        },
      }),
    ]
  );
}

function scanLimitsCard(state, actions) {
  const security = state.config?.security ?? {};
  return card(
    'Scan limits and AWS requests',
    'These bound how many resources a scan inspects, which directly bounds how many AWS API calls it makes, and how long any single request may take. Anything not inspected is reported as partially evaluated — never as clean.',
    [
      el('div', { class: 'filters' }, [
        el('div', { class: 'field' }, [
          el('label', { for: 'limit-lambda', text: 'Lambda policy lookups per region' }),
          el('input', {
            class: 'input',
            id: 'limit-lambda',
            type: 'number',
            min: '0',
            max: '10000',
            step: '25',
            value: String(security.maxLambdaPolicyLookupsPerRegion ?? 100),
            onChange: async (event) => {
              await actions.persist({
                security: { maxLambdaPolicyLookupsPerRegion: Number(event.target.value) },
              });
              await actions.loadSection('security', { force: true });
            },
          }),
          el('p', {
            class: 'subtle',
            text: 'One lambda:GetPolicy call per function. 0 means no limit — every function is inspected. To switch this check off entirely, disable it under Security checks. The "outside a VPC" check always covers every function.',
          }),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'limit-buckets', text: 'S3 buckets per scan' }),
          el('input', {
            class: 'input',
            id: 'limit-buckets',
            type: 'number',
            min: '0',
            max: '10000',
            step: '25',
            value: String(security.maxBucketsPerScan ?? 250),
            onChange: async (event) => {
              await actions.persist({
                security: { maxBucketsPerScan: Number(event.target.value) },
              });
              await actions.loadSection('security', { force: true });
            },
          }),
          el('p', {
            class: 'subtle',
            text: 'Up to five read calls per bucket. 0 means no limit — every bucket is inspected. Anything beyond the limit is reported as partially evaluated, never as clean.',
          }),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'aws-timeout', text: 'AWS request timeout (seconds)' }),
          el('input', {
            class: 'input',
            id: 'aws-timeout',
            type: 'number',
            min: '5',
            max: '120',
            step: '5',
            value: String(Math.round((state.config?.awsRequestTimeoutMs ?? 30000) / 1000)),
            onChange: async (event) => {
              await actions.persist({
                awsRequestTimeoutMs: Math.round(Number(event.target.value) * 1000),
              });
            },
          }),
          el('p', {
            class: 'subtle',
            text: 'How long a single AWS request may take before it is cancelled. Raise it on a slow or proxied network; a cancelled request is reported, never counted as a pass.',
          }),
        ]),
        el('div', { class: 'field' }, [
          el('label', { for: 'limit-loggroups', text: 'Log groups per region' }),
          el('input', {
            class: 'input',
            id: 'limit-loggroups',
            type: 'number',
            min: '1',
            max: '5000',
            step: '25',
            value: String(state.config?.cloudwatch?.maxLogGroupsPerRegion ?? 200),
            onChange: async (event) => {
              await actions.persist({
                cloudwatch: { maxLogGroupsPerRegion: Number(event.target.value) },
              });
              await actions.loadSection('cloudwatch', { force: true });
            },
          }),
          el('p', {
            class: 'subtle',
            text: 'Largest log groups first. Growth metrics are batched 100 per call.',
          }),
        ]),
      ]),
    ]
  );
}

function readOnlyCard() {
  return card(
    'AWS read-only guarantee',
    'Every AWS call passes through one access layer that enforces this before a request is sent.',
    [
      el('ul', {}, [
        el('li', {
          text: 'Operations beginning with a mutating verb (Create, Delete, Update, Put, Modify, …) are refused outright.',
        }),
        el('li', { text: 'Operations must also begin with a recognised read-only verb.' }),
        el('li', {
          text: 'Operations must appear in a compile-time allowlist for that specific AWS service.',
        }),
        el('li', {
          text: 'Local configuration can only narrow what is called; there is no code path by which it can add an operation.',
        }),
      ]),
      el('button', {
        class: 'button',
        type: 'button',
        text: 'Show the allowlist and required IAM actions',
        onClick: async () => {
          try {
            const permissions = await api.permissions();
            openDetail(
              'Read-only allowlist',
              el('div', { class: 'stack' }, [
                el('p', {
                  text: `${permissions.operations.length} allowed operations across ${new Set(permissions.operations.map((operation) => operation.service)).size} AWS services.`,
                }),
                table({
                  columns: [
                    { label: 'Service', key: 'service' },
                    {
                      label: 'Operation',
                      render: (row) => el('span', { class: 'mono', text: row.operation }),
                    },
                    {
                      label: 'IAM action',
                      render: (row) => el('span', { class: 'mono', text: row.iamAction }),
                    },
                    { label: 'Category', key: 'category' },
                  ],
                  rows: permissions.operations,
                }),
                el('h4', { text: 'Least-privilege IAM actions' }),
                codeBlock(permissions.iamActions),
              ])
            );
          } catch (error) {
            toast(`Could not load the allowlist: ${error.message}`, 'error');
          }
        },
      }),
    ]
  );
}

function localDataCard(state, actions) {
  return card('Local data', `Configuration directory: ${state.status?.configDir ?? 'unknown'}`, [
    el('ul', {}, [
      el('li', {
        text: 'config.json — your preferences: profiles, regions, thresholds, AI provider settings and sanitization rules.',
      }),
      el('li', {
        text: 'security-findings.json — your decisions about findings (acknowledged, ignored, resolved) plus the minimum identity needed to keep them filterable.',
      }),
      el('li', { text: 'ai-history.json — sanitized AI history, only when you enable it.' }),
      el('li', {
        text: 'Raw AWS data is never written to disk. It lives in memory for this server session only.',
      }),
    ]),
    el('div', { class: 'section-header__actions' }, [
      el('button', {
        class: 'button',
        type: 'button',
        text: 'Show current configuration',
        onClick: () => openDetail('Local configuration', codeBlock(state.config)),
      }),
      el('button', {
        class: 'button button--danger',
        type: 'button',
        text: 'Delete All Local Configuration',
        onClick: async () => {
          if (
            !confirmDestructive(
              'Delete all local configuration, security finding decisions and AI history? This removes the application directory and cannot be undone.'
            )
          ) {
            return;
          }
          try {
            const result = await api.deleteConfig();
            toast(`Deleted ${result.removed.length} file(s) and reset to defaults.`, 'success');
            await actions.bootstrap();
          } catch (error) {
            toast(`Could not delete local configuration: ${error.message}`, 'error');
          }
        },
      }),
    ]),
  ]);
}

function memoryCard(state) {
  const stats = state.status?.dataInMemory;
  return card(
    'AWS data in memory',
    'Cleared when the server stops. Nothing here is written to disk.',
    [
      stats && stats.entries.length > 0
        ? table({
            columns: [
              { label: 'Section', key: 'section' },
              { label: 'Age', numeric: true, render: (row) => `${number(row.ageSeconds)} s` },
            ],
            rows: stats.entries,
          })
        : el('p', { class: 'muted', text: 'No AWS data is currently held in memory.' }),
    ]
  );
}

export function renderSettings({ state, actions }) {
  const container = el('div', {});
  container.append(
    sectionHeader({
      title: 'Settings',
      description: 'Everything here is stored locally as JSON in your home directory.',
    })
  );

  container.append(generalCard(state, actions));
  container.append(geminiCard(state, actions));
  container.append(customProviderCard(state, actions));
  container.append(sanitizationCard(state, actions));
  container.append(historyCard(state, actions));
  container.append(scanLimitsCard(state, actions));
  container.append(readOnlyCard());
  container.append(memoryCard(state));
  container.append(localDataCard(state, actions));

  return container;
}
