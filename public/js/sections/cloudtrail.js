/** CloudTrail search view: filters, pagination and explicit AI selection. */

import {
  el,
  badge,
  table,
  sectionHeader,
  loadingState,
  errorState,
  emptyState,
  openDetail,
  detailGrid,
  codeBlock,
  dateTime,
  number,
  issueList,
  toast,
} from '../ui.js';

function filterField(state, actions, { id, label, key, type = 'text', placeholder, options }) {
  const current = state.cloudtrail.filters[key] ?? '';
  const control = options
    ? el(
        'select',
        {
          class: 'select',
          id,
          onChange: (event) => {
            state.cloudtrail.filters[key] = event.target.value || undefined;
          },
        },
        options.map((option) =>
          el('option', {
            value: option.value,
            text: option.label,
            selected: current === option.value,
          })
        )
      )
    : el('input', {
        class: 'input',
        id,
        type,
        placeholder: placeholder ?? '',
        value: current,
        onInput: (event) => {
          state.cloudtrail.filters[key] = event.target.value || undefined;
        },
      });

  return el('div', { class: 'field' }, [el('label', { for: id, text: label }), control]);
}

function eventDetail(event) {
  return el('div', { class: 'stack' }, [
    detailGrid([
      ['Time', dateTime(event.eventTime)],
      ['Event', event.eventName],
      ['Source', event.eventSource],
      ['Region', event.awsRegion],
      ['Profile', event.profile],
      ['Account', event.accountId],
      ['Identity', event.username ?? 'unknown'],
      ['Principal type', event.principalType],
      ['Source IP', event.sourceIp],
      ['User agent', event.userAgent],
      ['Read-only', event.readOnly === null ? 'unknown' : String(event.readOnly)],
      ['Error code', event.errorCode],
      ['Error message', event.errorMessage],
    ]),
    event.resources.length > 0
      ? el('div', {}, [el('h4', { text: 'Resources' }), codeBlock(event.resources)])
      : null,
    event.requestParameters
      ? el('div', {}, [
          el('h4', { text: 'Request parameters' }),
          codeBlock(event.requestParameters),
        ])
      : null,
  ]);
}

function aggregateCard(title, rows) {
  return el('div', { class: 'card' }, [
    el('h3', { class: 'card__title', text: title }),
    table({
      emptyMessage: 'No data',
      columns: [
        {
          label: 'Value',
          render: (row) => el('span', { class: 'mono truncate', title: row.key, text: row.key }),
        },
        { label: 'Events', numeric: true, render: (row) => number(row.count) },
      ],
      rows,
    }),
  ]);
}

export function renderCloudTrail({ state, actions }) {
  const container = el('div', {});
  const search = state.cloudtrail;

  container.append(
    sectionHeader({
      title: 'CloudTrail',
      description:
        'Search management events across the selected profiles and regions. AWS evaluates one lookup attribute; the remaining filters are applied locally while paging.',
      meta: search.result
        ? `${number(search.result.total)} matching events · page ${search.result.page} of ${search.result.totalPages}`
        : undefined,
      actions: [
        el('button', {
          class: 'button button--primary',
          text: 'Search',
          disabled: search.status === 'loading',
          onClick: () => void actions.searchCloudTrail({ force: true, page: 1 }),
        }),
        el('button', {
          class: 'button',
          text: 'Refresh',
          disabled: search.status === 'loading' || !search.result,
          onClick: () => void actions.searchCloudTrail({ force: true }),
        }),
      ],
    })
  );

  container.append(
    el('div', { class: 'card' }, [
      el('div', { class: 'filters' }, [
        filterField(state, actions, {
          id: 'ct-start',
          label: 'From',
          key: 'startTime',
          type: 'datetime-local',
        }),
        filterField(state, actions, {
          id: 'ct-end',
          label: 'To',
          key: 'endTime',
          type: 'datetime-local',
        }),
        filterField(state, actions, {
          id: 'ct-event',
          label: 'Event name',
          key: 'eventName',
          placeholder: 'RunInstances',
        }),
        filterField(state, actions, {
          id: 'ct-source',
          label: 'Event source',
          key: 'eventSource',
          placeholder: 'ec2.amazonaws.com',
        }),
        filterField(state, actions, {
          id: 'ct-user',
          label: 'IAM user or role',
          key: 'username',
          placeholder: 'deploy-role',
        }),
        filterField(state, actions, {
          id: 'ct-resource-type',
          label: 'Resource type',
          key: 'resourceType',
          placeholder: 'AWS::S3::Bucket',
        }),
        filterField(state, actions, {
          id: 'ct-resource',
          label: 'Resource name',
          key: 'resourceName',
          placeholder: 'my-bucket',
        }),
        filterField(state, actions, {
          id: 'ct-ip',
          label: 'Source IP',
          key: 'sourceIp',
          placeholder: '203.0.113.10',
        }),
        filterField(state, actions, {
          id: 'ct-readonly',
          label: 'Read / write',
          key: 'readOnly',
          options: [
            { value: '', label: 'All' },
            { value: 'read', label: 'Read only' },
            { value: 'write', label: 'Write' },
          ],
        }),
        filterField(state, actions, {
          id: 'ct-outcome',
          label: 'Outcome',
          key: 'outcome',
          options: [
            { value: '', label: 'All' },
            { value: 'success', label: 'Succeeded' },
            { value: 'failure', label: 'Failed' },
          ],
        }),
        filterField(state, actions, {
          id: 'ct-text',
          label: 'Free text',
          key: 'text',
          type: 'search',
          placeholder: 'any text in the event',
        }),
        el('div', { class: 'field' }, [
          el('label', { text: ' ' }),
          el('button', {
            class: 'button',
            type: 'button',
            text: 'Clear filters',
            onClick: () => {
              state.cloudtrail.filters = {};
              actions.setView('cloudtrail');
            },
          }),
        ]),
      ]),
    ])
  );

  if (state.selectedProfiles.length === 0) {
    container.append(
      emptyState('No AWS profile selected', 'Choose a profile in the header first.')
    );
    return container;
  }

  if (search.status === 'loading') {
    container.append(loadingState('Searching CloudTrail…'));
    return container;
  }

  if (search.status === 'error') {
    container.append(
      errorState(
        'CloudTrail search failed',
        search.error,
        () => void actions.searchCloudTrail({ force: true })
      )
    );
    return container;
  }

  if (search.status === 'idle' || !search.result) {
    container.append(
      emptyState(
        'No search has been run yet',
        'Set your filters and press Search. CloudTrail is queried only when you ask for it.'
      )
    );
    return container;
  }

  const result = search.result;
  const issues = issueList(result.issues, { title: 'CloudTrail could not be searched everywhere' });
  if (issues) container.append(issues);

  if (result.truncated) {
    container.append(
      el('div', { class: 'notice notice--warn' }, [
        el('strong', { text: 'Result set truncated' }),
        el('span', {
          text: 'AWS returned more events than the configured per-search limit. Narrow the time window or add filters for a complete picture.',
        }),
      ])
    );
  }

  const selectionCount = search.selectedIds.size;

  container.append(
    el('div', { class: 'card' }, [
      el('div', { class: 'card__header' }, [
        el('h3', { class: 'card__title', text: 'Events' }),
        el('div', { class: 'section-header__actions' }, [
          el('span', { class: 'subtle', text: `${selectionCount} selected for AI` }),
          el('button', {
            class: 'button button--small',
            text: 'Clear selection',
            disabled: selectionCount === 0,
            onClick: () => {
              search.selectedIds = new Set();
              actions.setView('cloudtrail');
            },
          }),
          el('button', {
            class: 'button button--primary button--small',
            text: selectionCount > 0 ? `Analyze ${selectionCount} selected` : 'Analyze CloudTrail',
            disabled: state.ai?.nonLlmMode || state.aiBusy,
            title: state.ai?.nonLlmMode
              ? 'No AI provider is available.'
              : 'Sends only the selected events (or the current result summary), sanitized.',
            onClick: () => {
              const selected = result.events.filter((event) => search.selectedIds.has(event.id));
              if (selectionCount > 0 && selected.length === 0) {
                toast(
                  'The selected events are not on this page; clear the selection or reselect.',
                  'error'
                );
                return;
              }
              void actions.runAi({
                sections: ['cloudtrail'],
                question: '',
                selectedEvents: selected,
              });
            },
          }),
        ]),
      ]),
      table({
        emptyMessage: 'No events matched these filters.',
        columns: [
          {
            label: 'AI',
            render: (row) =>
              el('input', {
                type: 'checkbox',
                'aria-label': `Select event ${row.eventName}`,
                checked: search.selectedIds.has(row.id),
                onClick: (event) => event.stopPropagation(),
                onChange: (event) => {
                  if (event.target.checked) search.selectedIds.add(row.id);
                  else search.selectedIds.delete(row.id);
                },
              }),
          },
          { label: 'Time', render: (row) => dateTime(row.eventTime) },
          { label: 'Event', key: 'eventName' },
          { label: 'Source', key: 'eventSource' },
          { label: 'Region', key: 'awsRegion' },
          { label: 'Profile', key: 'profile' },
          {
            label: 'Identity',
            render: (row) => row.username ?? el('span', { class: 'subtle', text: 'unknown' }),
          },
          {
            label: 'Type',
            render: (row) =>
              row.readOnly === null
                ? badge('unknown', 'neutral')
                : row.readOnly
                  ? badge('read', 'low')
                  : badge('write', 'medium'),
          },
          {
            label: 'Outcome',
            render: (row) =>
              row.errorCode ? badge(row.errorCode, 'critical') : badge('success', 'ok'),
          },
        ],
        rows: result.events,
        onRowClick: (row) =>
          openDetail(`${row.eventName} · ${dateTime(row.eventTime)}`, eventDetail(row)),
      }),
      el('div', { class: 'pagination' }, [
        el('button', {
          class: 'button button--small',
          text: 'Previous',
          disabled: result.page <= 1,
          onClick: () => void actions.searchCloudTrail({ page: result.page - 1 }),
        }),
        el('span', { text: `Page ${result.page} of ${result.totalPages}` }),
        el('button', {
          class: 'button button--small',
          text: 'Next',
          disabled: result.page >= result.totalPages,
          onClick: () => void actions.searchCloudTrail({ page: result.page + 1 }),
        }),
      ]),
    ])
  );

  container.append(
    el('div', { class: 'grid grid--halves' }, [
      aggregateCard('Top events', result.aggregates.byEventName),
      aggregateCard('Top services', result.aggregates.byEventSource),
      aggregateCard('Top identities', result.aggregates.byUser),
      aggregateCard('Top source IPs', result.aggregates.bySourceIp),
    ])
  );

  return container;
}
