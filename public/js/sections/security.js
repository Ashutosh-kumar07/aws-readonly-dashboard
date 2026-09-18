/** Security findings view. */

import {
  el,
  badge,
  table,
  stat,
  issueList,
  emptyState,
  openDetail,
  detailGrid,
  codeBlock,
  dateTime,
  confirmDestructive,
  toast,
} from '../ui.js';
import { api } from '../api.js';
import { sectionShell, analyzeButton } from './common.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const STATUSES = ['open', 'acknowledged', 'ignored', 'resolved'];

const filters = {
  severities: new Set(SEVERITIES),
  statuses: new Set(['open', 'acknowledged']),
  text: '',
};

/**
 * The severity to display. After an AI analysis, the model's severity replaces
 * the dashboard's own for findings it matched — the original is not shown too.
 */
function displayedSeverity(finding, overrides) {
  const override = overrides?.[finding.id];
  return override
    ? { severity: override, fromAi: true }
    : { severity: finding.severity, fromAi: false };
}

function findingDetail(finding, actions, overrides) {
  const body = el('div', { class: 'stack' }, [
    detailGrid([
      [
        'Severity',
        (() => {
          const shown = displayedSeverity(finding, overrides);
          return el('span', {}, [
            badge(shown.severity, shown.severity),
            shown.fromAi ? el('span', { class: 'subtle', text: ' assigned by AI analysis' }) : null,
          ]);
        })(),
      ],
      ['Status', finding.status],
      ['Check', finding.checkId],
      ['Source', finding.source],
      ['Profile', finding.profile],
      ['Account', finding.accountId],
      ['Region', finding.region],
      ['Resource type', finding.resourceType],
      ['Resource', el('span', { class: 'mono', text: finding.resourceId })],
      [
        'ARN',
        finding.resourceArn ? el('span', { class: 'mono', text: finding.resourceArn }) : undefined,
      ],
      ['First seen', dateTime(finding.firstSeenAt)],
      ['Last seen', dateTime(finding.lastSeenAt)],
    ]),
    el('div', {}, [el('h4', { text: 'Why this matters' }), el('p', { text: finding.why })]),
    el('div', {}, [
      el('h4', { text: 'Recommendation' }),
      el('p', { text: finding.recommendation }),
      el('p', {
        class: 'subtle',
        text: 'This dashboard never performs AWS changes. Apply anything you decide to act on in the AWS console or your own tooling.',
      }),
    ]),
    el('div', {}, [
      el('h4', { text: 'Evidence (as returned by AWS)' }),
      codeBlock(finding.evidence),
    ]),
    el('div', {}, [
      el('h4', { text: 'Status' }),
      el(
        'div',
        { class: 'toggle-group' },
        STATUSES.map((status) =>
          el('button', {
            class: 'toggle',
            type: 'button',
            'aria-pressed': String(finding.status === status),
            text: status,
            onClick: () => {
              document.getElementById('detail-dialog').close();
              void actions.setFindingStatus(finding.id, status);
            },
          })
        )
      ),
    ]),
  ]);
  return body;
}

function findingsTable(findings, actions, overrides) {
  return table({
    emptyMessage: 'No findings match the current filters.',
    columns: [
      {
        label: 'Severity',
        render: (row) => {
          const shown = displayedSeverity(row, overrides);
          return el(
            'span',
            { title: shown.fromAi ? 'Severity assigned by AI analysis' : undefined },
            [
              badge(shown.severity, shown.severity),
              shown.fromAi ? el('span', { class: 'subtle', text: ' AI' }) : null,
            ]
          );
        },
      },
      {
        label: 'Finding',
        render: (row) => el('span', { class: 'truncate', title: row.title, text: row.title }),
      },
      {
        label: 'Resource',
        render: (row) =>
          el('span', { class: 'mono truncate', title: row.resourceId, text: row.resourceId }),
      },
      { label: 'Region', key: 'region' },
      { label: 'Source', key: 'source' },
      {
        label: 'Status',
        render: (row) => badge(row.status, row.status === 'open' ? 'neutral' : 'ok'),
      },
    ],
    rows: findings,
    onRowClick: (row) => openDetail(row.title, findingDetail(row, actions, overrides)),
  });
}

function coverageNotice(checks) {
  const partial = checks.filter((check) => check.truncated);
  if (partial.length === 0) return null;
  return el('div', { class: 'notice notice--warn' }, [
    el('strong', { text: 'Some checks inspected only part of the inventory' }),
    el(
      'ul',
      { class: 'list-reset' },
      partial.map((check) =>
        el('li', {
          text: `${check.title} (${check.region}): ${check.resourcesEvaluated ?? 0} resource(s) inspected. Raise the scan limits in Settings to cover the rest.`,
        })
      )
    ),
  ]);
}

function checkStatusTable(checks) {
  const notEvaluated = checks.filter((check) => check.state === 'not-evaluated');
  if (notEvaluated.length === 0) return null;

  return el('div', { class: 'card' }, [
    el('div', { class: 'card__header' }, [
      el('h3', { class: 'card__title', text: 'Checks that could not be evaluated' }),
      el('p', {
        class: 'card__hint',
        text: 'These are not "no findings". The dashboard could not assess them, so their status is unknown.',
      }),
    ]),
    table({
      columns: [
        { label: 'Check', key: 'title' },
        { label: 'Service', key: 'service' },
        { label: 'Region', key: 'region' },
        {
          label: 'Reason',
          render: (row) =>
            el('div', {}, [
              el('div', { text: row.issues[0]?.label ?? 'Unknown reason' }),
              row.issues[0]?.missingPermission
                ? el('div', {
                    class: 'mono subtle',
                    text: `needs ${row.issues[0].missingPermission}`,
                  })
                : null,
              // The message AWS (or the dashboard) actually gave, so a generic
              // label is still diagnosable without opening the network tab.
              row.issues[0]?.message
                ? el('div', { class: 'subtle issue-detail', text: row.issues[0].message })
                : null,
            ]),
        },
      ],
      rows: notEvaluated,
    }),
  ]);
}

function renderProfile(profile, state, actions) {
  const data = profile.data;
  const body = el('div', {});

  const issues = issueList(profile.issues, {
    title: 'Some security checks could not be completed',
    onApplySuggestion: async (suggestion) => {
      await actions.persist({ security: { [suggestion.setting]: suggestion.value } });
      await actions.loadSection('security', { force: true });
    },
  });
  if (issues) body.append(issues);

  if (!data) {
    body.append(emptyState('No security data available for this profile'));
    return el('section', { class: 'profile-block' }, [header(profile), body]);
  }

  body.append(
    el('div', { class: 'grid grid--stats' }, [
      stat('Critical', data.summary.bySeverity.critical, 'detected in this scan'),
      stat('High', data.summary.bySeverity.high, 'detected in this scan'),
      stat('Medium', data.summary.bySeverity.medium, 'detected in this scan'),
      stat('Low', data.summary.bySeverity.low, 'detected in this scan'),
      stat(
        'Checks evaluated',
        `${data.summary.evaluatedChecks}`,
        `${data.summary.notEvaluatedChecks} could not be evaluated`
      ),
    ])
  );

  const overrides = state.aiSeverityOverrides ?? {};
  const combined = [...data.findings, ...data.resolvedFindings];
  const visible = combined.filter((finding) => {
    if (!filters.severities.has(displayedSeverity(finding, overrides).severity)) return false;
    if (!filters.statuses.has(finding.status)) return false;
    if (filters.text) {
      const needle = filters.text.toLowerCase();
      if (
        !finding.title.toLowerCase().includes(needle) &&
        !finding.resourceId.toLowerCase().includes(needle) &&
        !finding.checkId.toLowerCase().includes(needle)
      ) {
        return false;
      }
    }
    return true;
  });

  body.append(
    el('div', { class: 'card' }, [
      el('div', { class: 'card__header' }, [
        el('h3', { class: 'card__title', text: 'Findings' }),
        el('p', {
          class: 'card__hint',
          text: `${visible.length} shown of ${combined.length} tracked`,
        }),
      ]),
      findingsTable(visible, actions, overrides),
    ])
  );

  if (Object.keys(overrides).length > 0) {
    body.append(
      el('div', { class: 'notice notice--info' }, [
        el('strong', { text: 'Severities from the latest AI analysis are in effect' }),
        el('span', {
          text: `${Object.keys(overrides).length} finding(s) show the severity the AI assigned from the supplied evidence. Refreshing this section restores the dashboard's own severities.`,
        }),
      ])
    );
  }

  const coverage = coverageNotice(data.checks);
  if (coverage) body.append(coverage);

  const checksCard = checkStatusTable(data.checks);
  if (checksCard) body.append(checksCard);

  return el('section', { class: 'profile-block' }, [header(profile), body]);
}

function header(profile) {
  return el('div', { class: 'profile-block__header' }, [
    el('span', { class: 'profile-block__name', text: profile.profile }),
    profile.accountId
      ? el('span', { class: 'profile-block__account', text: `account ${profile.accountId}` })
      : el('span', { class: 'subtle', text: 'account unknown' }),
  ]);
}

export function renderSecurity({ state, actions }) {
  const filterCard = el('div', { class: 'card' }, [
    el('div', { class: 'filters' }, [
      el('div', { class: 'field' }, [
        el('label', { text: 'Severity' }),
        el(
          'div',
          { class: 'toggle-group' },
          SEVERITIES.map((severity) =>
            el('button', {
              class: 'toggle',
              type: 'button',
              'aria-pressed': String(filters.severities.has(severity)),
              text: severity,
              onClick: () => {
                if (filters.severities.has(severity)) filters.severities.delete(severity);
                else filters.severities.add(severity);
                actions.setView('security');
              },
            })
          )
        ),
      ]),
      el('div', { class: 'field' }, [
        el('label', { text: 'Status' }),
        el(
          'div',
          { class: 'toggle-group' },
          STATUSES.map((status) =>
            el('button', {
              class: 'toggle',
              type: 'button',
              'aria-pressed': String(filters.statuses.has(status)),
              text: status,
              onClick: () => {
                if (filters.statuses.has(status)) filters.statuses.delete(status);
                else filters.statuses.add(status);
                actions.setView('security');
              },
            })
          )
        ),
      ]),
      el('div', { class: 'field' }, [
        el('label', { for: 'security-search', text: 'Search' }),
        el('input', {
          class: 'input input--search',
          id: 'security-search',
          type: 'search',
          placeholder: 'title, resource or check',
          value: filters.text,
          onInput: (event) => {
            filters.text = event.target.value;
          },
          onChange: () => actions.setView('security'),
        }),
      ]),
      el('div', { class: 'field' }, [
        el('label', { text: 'Resolved findings' }),
        el('button', {
          class: 'button button--danger button--small',
          type: 'button',
          text: 'Delete resolved',
          onClick: async () => {
            if (
              !confirmDestructive(
                'Delete all locally stored resolved findings? This cannot be undone.'
              )
            )
              return;
            try {
              const result = await api.deleteResolvedFindings();
              toast(`Deleted ${result.removed} resolved finding(s).`, 'success');
              await actions.loadSection('security', { force: true });
            } catch (error) {
              toast(`Could not delete resolved findings: ${error.message}`, 'error');
            }
          },
        }),
      ]),
    ]),
  ]);

  const shell = sectionShell({
    state,
    actions,
    key: 'security',
    title: 'Security',
    description:
      'Modular read-only checks across AWS security services and resource configuration. A check that cannot run is reported as such — never as "secure".',
    extraActions: [
      analyzeButton({ state, actions, sections: ['security'], label: 'Analyze Security' }),
    ],
    renderBody: (profile) => renderProfile(profile, state, actions),
  });

  shell.insertBefore(filterCard, shell.children[1] ?? null);
  return shell;
}
