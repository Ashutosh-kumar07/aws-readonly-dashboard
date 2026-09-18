/** AWS API usage accounting view. */

import {
  el,
  number,
  table,
  stat,
  sectionHeader,
  loadingState,
  dateTime,
  badge,
  openDetail,
} from '../ui.js';

export function renderUsage({ state, actions }) {
  const container = el('div', {});

  container.append(
    sectionHeader({
      title: 'AWS API Usage',
      description:
        'Every AWS SDK call this dashboard makes is counted here, grouped by service category. AI calls are not AWS API calls and are deliberately excluded.',
      meta: state.usage ? `Session started ${dateTime(state.usage.sessionStartedAt)}` : undefined,
      actions: [
        el('button', {
          class: 'button',
          text: 'Refresh',
          onClick: () => void actions.loadUsage(),
        }),
      ],
    })
  );

  if (!state.usage) {
    void actions.loadUsage();
    container.append(loadingState('Reading local API call statistics…'));
    return container;
  }

  const usage = state.usage;

  container.append(
    el('div', { class: 'grid grid--stats' }, [
      stat('Total AWS API calls', number(usage.totalCalls), 'this server session'),
      stat('Successful', number(usage.successfulCalls), ''),
      stat(
        'Failed',
        number(usage.failedCalls - (usage.expectedNotFoundCalls ?? 0)),
        'permission, throttling or service errors'
      ),
      stat(
        'Expected "not found"',
        number(usage.expectedNotFoundCalls ?? 0),
        'normal answers, e.g. a bucket with no policy'
      ),
      stat('Categories touched', number(usage.categories.length), ''),
    ])
  );

  container.append(
    el('div', { class: 'notice notice--info' }, [
      el('strong', { text: 'Why this exists' }),
      el('span', {
        text: 'AWS bills some of these APIs (Cost Explorer requests, for example). This counter lets you see exactly how much AWS activity the dashboard itself generates. Statistics are in memory only and reset when the server restarts.',
      }),
    ])
  );

  container.append(
    el('div', { class: 'card' }, [
      el('h3', { class: 'card__title', text: 'By category' }),
      table({
        emptyMessage: 'No AWS calls have been made yet.',
        columns: [
          { label: 'Category', key: 'label' },
          { label: 'Calls', numeric: true, render: (row) => number(row.calls) },
          { label: 'Successful', numeric: true, render: (row) => number(row.successes) },
          {
            label: 'Errors',
            numeric: true,
            render: (row) => number(row.errors - (row.expectedNotFound ?? 0)),
          },
          {
            label: 'Expected 404s',
            numeric: true,
            render: (row) => number(row.expectedNotFound ?? 0),
          },
          {
            label: 'Operations',
            render: (row) =>
              el('span', { class: 'subtle', text: `${row.operations.length} distinct` }),
          },
        ],
        rows: usage.categories,
        onRowClick: (row) =>
          openDetail(
            row.label,
            table({
              columns: [
                {
                  label: 'Operation',
                  render: (item) =>
                    el('span', { class: 'mono', text: `${item.service}:${item.operation}` }),
                },
                { label: 'Calls', numeric: true, render: (item) => number(item.calls) },
                { label: 'Errors', numeric: true, render: (item) => number(item.errors) },
              ],
              rows: row.operations,
            })
          ),
      }),
    ])
  );

  // Slow calls are what a timeout looks like before it becomes one, so they are
  // worth seeing on their own rather than hunting for them among the rest.
  const slowest = [...usage.recentCalls]
    .sort((a, b) => b.durationMs - a.durationMs)
    .slice(0, 10)
    .filter((call) => call.durationMs > 0);

  if (slowest.length > 0) {
    container.append(
      el('div', { class: 'card' }, [
        el('div', { class: 'card__header' }, [
          el('h3', { class: 'card__title', text: 'Slowest calls' }),
          el('p', {
            class: 'card__hint',
            text: 'The longest requests in this session. A call approaching the AWS request timeout in Settings is the one to look at when a section reports a timeout.',
          }),
        ]),
        table({
          columns: [
            {
              label: 'Operation',
              render: (row) =>
                el('span', { class: 'mono', text: `${row.service}:${row.operation}` }),
            },
            { label: 'Region', key: 'region' },
            { label: 'Profile', key: 'profile' },
            { label: 'Triggered by', key: 'section' },
            {
              label: 'Duration',
              numeric: true,
              render: (row) => `${number(row.durationMs)} ms`,
            },
          ],
          rows: slowest,
        }),
      ])
    );
  }

  container.append(
    el('div', { class: 'card' }, [
      el('div', { class: 'card__header' }, [
        el('h3', { class: 'card__title', text: 'Recent calls' }),
        el('p', {
          class: 'card__hint',
          text: usage.truncated
            ? `Showing the most recent ${number(usage.recordedCalls)} of ${number(usage.totalCalls)} calls.`
            : `${number(usage.recentCalls.length)} calls shown.`,
        }),
      ]),
      table({
        emptyMessage: 'No calls recorded yet.',
        columns: [
          { label: 'Time', render: (row) => dateTime(row.timestamp) },
          { label: 'Category', key: 'categoryLabel' },
          {
            label: 'Operation',
            render: (row) => el('span', { class: 'mono', text: `${row.service}:${row.operation}` }),
          },
          { label: 'Profile', key: 'profile' },
          {
            label: 'Account',
            render: (row) => row.accountId ?? el('span', { class: 'subtle', text: 'unknown' }),
          },
          { label: 'Region', key: 'region' },
          { label: 'Triggered by', key: 'section' },
          { label: 'Duration', numeric: true, render: (row) => `${number(row.durationMs)} ms` },
          {
            label: 'Result',
            render: (row) =>
              row.status === 'success'
                ? badge('ok', 'ok')
                : badge(row.errorCode ?? 'error', 'critical'),
          },
        ],
        rows: usage.recentCalls,
      }),
    ])
  );

  return container;
}
