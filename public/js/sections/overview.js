/** Overview: selection context, provider status and section entry points. */

import { el, number, sectionHeader, stat, badge, relativeTime } from '../ui.js';

const SECTION_CARDS = [
  {
    view: 'billing',
    key: 'billing',
    title: 'Billing / Cost',
    description: 'Rolling cost comparison, service and region breakdowns, threshold highlights.',
  },
  {
    view: 'security',
    key: 'security',
    title: 'Security',
    description:
      'Security Hub, GuardDuty, Inspector, Access Analyzer, Config, S3, Lambda, security groups and IAM.',
  },
  {
    view: 'optimizer',
    key: 'compute-optimizer',
    title: 'Compute Optimizer',
    description:
      'Rightsizing and idle-resource recommendations, with AWS-provided savings estimates only.',
  },
  {
    view: 'cloudwatch',
    key: 'cloudwatch',
    title: 'CloudWatch',
    description: 'Largest log groups, rapid growth, missing and long retention.',
  },
  {
    view: 'cloudtrail',
    key: null,
    title: 'CloudTrail',
    description: 'Filterable, paginated event search across profiles and regions.',
  },
];

export function renderOverview({ state, actions }) {
  const container = el('div', {});

  container.append(
    sectionHeader({
      title: 'Overview',
      description:
        'A local, read-only view of your AWS accounts. Data is fetched when you open a section and is kept in memory only for this server session.',
      meta: state.status?.server
        ? `Server ${state.status.server.url} · configuration in ${state.status.configDir}`
        : undefined,
      actions: [
        el('button', {
          class: 'button',
          text: 'Refresh All',
          onClick: () => void actions.refreshAll(),
        }),
      ],
    })
  );

  const validated = state.profiles.filter((profile) =>
    state.selectedProfiles.includes(profile.name)
  );
  const failed = validated.filter((profile) => profile.error);

  container.append(
    el('div', { class: 'grid grid--stats' }, [
      stat(
        'Profiles selected',
        number(state.selectedProfiles.length),
        `${state.profiles.length} discovered locally`
      ),
      stat(
        'Regions selected',
        number(state.selectedRegions.length),
        'Global resources are always included separately'
      ),
      stat(
        'AWS API calls this session',
        number(state.apiCalls),
        'Click to see the breakdown',
        () => {
          actions.setView('usage');
          void actions.loadUsage();
        }
      ),
      stat(
        'AI provider',
        state.ai?.nonLlmMode ? 'Non-LLM mode' : (state.ai?.activeProvider ?? 'unknown'),
        state.ai?.nonLlmMode
          ? 'Install the Gemini CLI or configure a custom endpoint'
          : 'AI runs only when you ask for it'
      ),
    ])
  );

  if (failed.length > 0) {
    container.append(
      el('div', { class: 'notice notice--error' }, [
        el('strong', { text: 'Some selected profiles could not be validated' }),
        el(
          'ul',
          { class: 'list-reset' },
          failed.map((profile) => el('li', { text: `${profile.name}: ${profile.error.message}` }))
        ),
      ])
    );
  }

  if (state.selectedProfiles.length === 0) {
    container.append(
      el('div', { class: 'notice notice--info' }, [
        el('strong', { text: 'Select an AWS profile to begin' }),
        el('span', {
          text: 'Use the Profiles control in the header. Profiles are discovered from your local AWS configuration; nothing is sent anywhere.',
        }),
      ])
    );
  }

  const cards = el('div', { class: 'grid grid--halves' });
  for (const card of SECTION_CARDS) {
    const entry = card.key ? state.sections[card.key] : null;
    const status = card.key
      ? entry.status === 'ready'
        ? badge(`loaded ${relativeTime(entry.fetchedAt)}`, 'ok')
        : entry.status === 'loading'
          ? badge('loading…', 'medium')
          : entry.status === 'error'
            ? badge('error', 'critical')
            : badge('not loaded', 'neutral')
      : badge('on demand', 'neutral');

    cards.append(
      el('div', { class: 'card' }, [
        el('div', { class: 'card__header' }, [
          el('h3', { class: 'card__title', text: card.title }),
          status,
        ]),
        el('p', { class: 'card__hint', text: card.description }),
        el('div', { class: 'section-header__actions' }, [
          el('button', {
            class: 'button button--primary button--small',
            text: 'Open',
            onClick: () => actions.setView(card.view),
          }),
          card.key
            ? el('button', {
                class: 'button button--small',
                text: entry.status === 'ready' ? 'Refresh' : 'Load',
                onClick: () => {
                  actions.setView(card.view);
                  void actions.loadSection(card.key, { force: entry.status === 'ready' });
                },
              })
            : null,
        ]),
      ])
    );
  }
  container.append(cards);

  container.append(
    el('div', { class: 'card' }, [
      el('h3', { class: 'card__title', text: 'How this dashboard treats your account' }),
      el('ul', {}, [
        el('li', {
          text: 'Every AWS call passes through a central access layer that refuses any operation outside a compile-time read-only allowlist. No setting, file or UI action can widen it.',
        }),
        el('li', {
          text: 'AWS data lives in memory for this server session only. Local JSON stores your preferences, your security-finding decisions and, if you enable it, sanitized AI history.',
        }),
        el('li', {
          text: 'AI analysis never runs on its own. It happens only when you press an Analyze button, and only the sections you selected are sent, after sanitization.',
        }),
        el('li', {
          text: 'When a check cannot run — missing permission, service not enabled — the dashboard says so explicitly instead of reporting "secure".',
        }),
      ]),
    ])
  );

  return container;
}
