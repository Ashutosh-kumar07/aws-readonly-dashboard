/** CloudWatch log-group analysis view. */

import { el, bytes, number, percent, badge, table, stat, issueList, emptyState } from '../ui.js';
import { sectionShell, analyzeButton } from './common.js';

function logGroupTable(rows, emptyMessage) {
  return table({
    emptyMessage,
    columns: [
      {
        label: 'Log group',
        render: (row) => el('span', { class: 'mono truncate', title: row.name, text: row.name }),
      },
      { label: 'Region', key: 'region' },
      { label: 'Stored', numeric: true, render: (row) => bytes(row.storedBytes) },
      {
        label: 'Growth',
        numeric: true,
        render: (row) =>
          row.growthBytes === null
            ? el('span', { class: 'subtle', text: 'metric unavailable' })
            : bytes(row.growthBytes),
      },
      {
        label: 'Growth %',
        numeric: true,
        render: (row) =>
          row.growthPercent === null
            ? el('span', { class: 'subtle', text: '—' })
            : percent(row.growthPercent),
      },
      {
        label: 'Retention',
        render: (row) =>
          row.retentionInDays === null
            ? badge('never expires', 'high')
            : `${row.retentionInDays} days`,
      },
    ],
    rows,
  });
}

function renderProfile(profile) {
  const body = el('div', {});
  const issues = issueList(profile.issues, { title: 'Some CloudWatch data could not be read' });
  if (issues) body.append(issues);

  const data = profile.data;
  if (!data) {
    body.append(emptyState('No CloudWatch data available for this profile'));
    return el('section', { class: 'profile-block' }, [header(profile), body]);
  }

  body.append(
    el('div', { class: 'grid grid--stats' }, [
      stat(
        'Log groups',
        number(data.totals.logGroups),
        `${number(data.totals.inspected)} inspected`
      ),
      stat('Stored data', bytes(data.totals.storedBytes), 'across inspected log groups'),
      stat(
        'Growing quickly',
        number(data.rapidlyGrowing.length),
        `over the last ${data.windowDays} days`
      ),
      stat('No retention set', number(data.noRetention.length), 'these log groups never expire'),
      stat(
        'Long retention',
        number(data.longRetention.length),
        `≥ ${data.thresholds.longRetentionDays} days`
      ),
    ])
  );

  body.append(
    el('div', { class: 'notice notice--info' }, [
      el('strong', { text: 'How growth is measured' }),
      el('span', {
        text: `Growth is the sum of the CloudWatch IncomingBytes metric over the last ${data.windowDays} days. A log group is surfaced when growth is at least ${data.thresholds.growthPercent}% or at least ${bytes(data.thresholds.growthBytes)}. No cost estimates are produced for CloudWatch.`,
      }),
    ])
  );

  body.append(
    el('div', { class: 'card' }, [
      el('h3', { class: 'card__title', text: 'Rapidly growing log groups' }),
      logGroupTable(data.rapidlyGrowing, 'No log group exceeded the growth thresholds.'),
    ])
  );

  body.append(
    el('div', { class: 'card' }, [
      el('h3', { class: 'card__title', text: 'Largest log groups' }),
      logGroupTable(data.largest, 'No log groups found.'),
    ])
  );

  body.append(
    el('div', { class: 'grid grid--halves' }, [
      el('div', { class: 'card' }, [
        el('h3', { class: 'card__title', text: 'No expiration configured' }),
        el('p', { class: 'card__hint', text: 'These log groups retain data forever.' }),
        logGroupTable(
          data.noRetention.slice(0, 25),
          'Every inspected log group has a retention policy.'
        ),
      ]),
      el('div', { class: 'card' }, [
        el('h3', { class: 'card__title', text: 'Long retention' }),
        el('p', {
          class: 'card__hint',
          text: `Retention of at least ${data.thresholds.longRetentionDays} days.`,
        }),
        logGroupTable(
          data.longRetention.slice(0, 25),
          'No log group exceeds the long-retention threshold.'
        ),
      ]),
    ])
  );

  return el('section', { class: 'profile-block' }, [header(profile), body]);
}

function header(profile) {
  return el('div', { class: 'profile-block__header' }, [
    el('span', { class: 'profile-block__name', text: profile.profile }),
    profile.accountId
      ? el('span', { class: 'profile-block__account', text: `account ${profile.accountId}` })
      : null,
  ]);
}

export function renderCloudWatch({ state, actions }) {
  const config = state.config?.cloudwatch ?? {};
  const controls = el('div', { class: 'card' }, [
    el('div', { class: 'card__header' }, [
      el('h3', { class: 'card__title', text: 'Thresholds' }),
      el('p', {
        class: 'card__hint',
        text: 'A log group is surfaced when either growth threshold is met.',
      }),
    ]),
    el('div', { class: 'filters' }, [
      el('div', { class: 'field' }, [
        el('label', { for: 'cw-growth-percent', text: 'Growth % threshold' }),
        el('input', {
          class: 'input',
          id: 'cw-growth-percent',
          type: 'number',
          min: '0',
          step: '1',
          value: String(config.growthPercentThreshold ?? 5),
          onChange: async (event) => {
            await actions.persist({
              cloudwatch: { growthPercentThreshold: Number(event.target.value) },
            });
            await actions.loadSection('cloudwatch', { force: true });
          },
        }),
      ]),
      el('div', { class: 'field' }, [
        el('label', { for: 'cw-growth-gb', text: 'Absolute growth threshold (GB)' }),
        el('input', {
          class: 'input',
          id: 'cw-growth-gb',
          type: 'number',
          min: '0',
          step: '0.5',
          value: String(Math.round(((config.growthBytesThreshold ?? 0) / 1073741824) * 100) / 100),
          onChange: async (event) => {
            await actions.persist({
              cloudwatch: { growthBytesThreshold: Number(event.target.value) * 1073741824 },
            });
            await actions.loadSection('cloudwatch', { force: true });
          },
        }),
      ]),
      el('div', { class: 'field' }, [
        el('label', { for: 'cw-retention', text: 'Long-retention threshold (days)' }),
        el('input', {
          class: 'input',
          id: 'cw-retention',
          type: 'number',
          min: '1',
          max: '3653',
          step: '1',
          value: String(config.longRetentionDays ?? 90),
          onChange: async (event) => {
            await actions.persist({
              cloudwatch: { longRetentionDays: Number(event.target.value) },
            });
            await actions.loadSection('cloudwatch', { force: true });
          },
        }),
      ]),
      el('div', { class: 'field' }, [
        el('label', { for: 'cw-window', text: 'Growth window (days)' }),
        el('input', {
          class: 'input',
          id: 'cw-window',
          type: 'number',
          min: '1',
          max: '90',
          step: '1',
          value: String(config.growthWindowDays ?? 7),
          onChange: async (event) => {
            await actions.persist({ cloudwatch: { growthWindowDays: Number(event.target.value) } });
            await actions.loadSection('cloudwatch', { force: true });
          },
        }),
      ]),
    ]),
  ]);

  const shell = sectionShell({
    state,
    actions,
    key: 'cloudwatch',
    title: 'CloudWatch',
    description: 'Log-group size, growth and retention analysis for the selected regions.',
    extraActions: [
      analyzeButton({ state, actions, sections: ['cloudwatch'], label: 'Analyze CloudWatch' }),
    ],
    renderBody: (profile) => renderProfile(profile),
  });

  shell.insertBefore(controls, shell.children[1] ?? null);
  return shell;
}
