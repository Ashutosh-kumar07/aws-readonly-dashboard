/** Billing / cost analysis view. */

import {
  el,
  money,
  percent,
  badge,
  table,
  stat,
  issueList,
  emptyState,
  openDetail,
  detailGrid,
} from '../ui.js';
import { barChart, lineChart, breakdownBars } from '../charts.js';
import { sectionShell, analyzeButton } from './common.js';

const PERIODS = [1, 7, 14, 30, 60, 90];

function changeBadge(kind) {
  const labels = {
    increase: 'increase',
    decrease: 'decrease',
    new: 'new cost',
    removed: 'removed cost',
    unchanged: 'unchanged',
  };
  return badge(labels[kind] ?? kind, kind);
}

function changeTable(rows, currency, emptyMessage) {
  return table({
    emptyMessage,
    columns: [
      {
        label: 'Service',
        render: (row) => el('span', { class: 'truncate', title: row.key, text: row.key }),
      },
      { label: 'Current', numeric: true, render: (row) => money(row.currentCost, currency) },
      { label: 'Previous', numeric: true, render: (row) => money(row.previousCost, currency) },
      {
        label: 'Change',
        numeric: true,
        render: (row) =>
          el('span', { class: row.delta > 0 ? 'value--up' : row.delta < 0 ? 'value--down' : '' }, [
            `${row.delta > 0 ? '+' : ''}${money(row.delta, currency)}`,
          ]),
      },
      {
        label: '%',
        numeric: true,
        render: (row) =>
          row.percentChange === null
            ? el('span', { class: 'subtle', text: 'n/a (new)' })
            : el('span', { class: row.percentChange > 0 ? 'value--up' : 'value--down' }, [
                percent(row.percentChange),
              ]),
      },
      { label: 'Type', render: (row) => changeBadge(row.kind) },
      {
        label: 'Threshold',
        render: (row) =>
          row.exceedsThreshold ? badge('exceeded', 'high') : badge('below', 'neutral'),
      },
    ],
    rows,
    onRowClick: (row) =>
      openDetail(
        row.key,
        detailGrid([
          ['Current period', money(row.currentCost, currency)],
          ['Previous period', money(row.previousCost, currency)],
          ['Absolute change', money(row.delta, currency)],
          [
            'Percentage change',
            row.percentChange === null ? 'Not applicable (new cost)' : percent(row.percentChange),
          ],
          ['Classification', row.kind],
          ['Meets threshold', row.exceedsThreshold ? 'Yes' : 'No'],
        ])
      ),
  });
}

function renderProfile(profile) {
  const body = el('div', {});
  const issues = issueList(profile.issues, { title: 'Cost Explorer data is incomplete' });
  if (issues) body.append(issues);

  const data = profile.data;
  if (!data) {
    body.append(
      emptyState(
        'No Cost Explorer data available',
        'Cost Explorer must be enabled for the account, and the profile needs ce:GetCostAndUsage.'
      )
    );
    return el('section', { class: 'profile-block' }, [profileHeader(profile), body]);
  }

  const currency = data.currency;

  body.append(
    el('div', { class: 'grid grid--stats' }, [
      stat(
        `Current ${data.comparisonDays}d`,
        money(data.currentPeriod.total, currency),
        `${data.currentPeriod.start} → ${data.currentPeriod.end}`
      ),
      stat(
        `Previous ${data.comparisonDays}d`,
        money(data.previousPeriod.total, currency),
        `${data.previousPeriod.start} → ${data.previousPeriod.end}`
      ),
      stat(
        'Change',
        el('span', { class: data.totalDelta > 0 ? 'value--up' : 'value--down' }, [
          `${data.totalDelta > 0 ? '+' : ''}${money(data.totalDelta, currency)}`,
        ]),
        data.totalPercentChange === null ? 'no previous spend' : percent(data.totalPercentChange)
      ),
      stat(
        'Thresholds',
        `${money(data.thresholds.dollar, currency)} / ${data.thresholds.percent}%`,
        'A change qualifies if either is met'
      ),
    ])
  );

  if (data.containsEstimates) {
    body.append(
      el('div', { class: 'notice notice--info' }, [
        el('strong', { text: 'Some amounts are AWS estimates' }),
        el('span', { text: 'Recent days are not finalised by AWS yet, so totals may still move.' }),
      ])
    );
  }

  body.append(
    el('div', { class: 'card' }, [
      el('div', { class: 'card__header' }, [
        el('h3', { class: 'card__title', text: 'Daily cost' }),
        el('p', { class: 'card__hint', text: `${data.dailySeries.length} days · ${data.metric}` }),
      ]),
      lineChart(
        data.dailySeries.map((point) => ({
          label: point.date.slice(5),
          value: point.amount,
          title: `${point.date}: ${money(point.amount, currency)}`,
        })),
        { ariaLabel: 'Daily cost over time' }
      ),
    ])
  );

  body.append(
    el('div', { class: 'grid grid--halves' }, [
      el('div', { class: 'card' }, [
        el('h3', { class: 'card__title', text: 'Weekly cost (rolling 7-day buckets)' }),
        barChart(
          data.weeklySeries.map((point) => ({
            label: point.weekStart.slice(5),
            value: point.amount,
            title: `${point.weekStart} → ${point.weekEnd}: ${money(point.amount, currency)}`,
          })),
          { height: 160, ariaLabel: 'Weekly cost' }
        ),
      ]),
      el('div', { class: 'card' }, [
        el('h3', { class: 'card__title', text: 'Monthly cost' }),
        barChart(
          data.monthlySeries.map((point) => ({
            label: point.date,
            value: point.amount,
            title: `${point.date}: ${money(point.amount, currency)}`,
          })),
          { height: 160, ariaLabel: 'Monthly cost' }
        ),
      ]),
    ])
  );

  const highlighted = data.byService.filter((change) => change.exceedsThreshold);

  body.append(
    el('div', { class: 'card' }, [
      el('div', { class: 'card__header' }, [
        el('h3', { class: 'card__title', text: 'Changes that meet your thresholds' }),
        el('p', {
          class: 'card__hint',
          text: `${highlighted.length} of ${data.byService.length} services qualify`,
        }),
      ]),
      changeTable(
        highlighted,
        currency,
        'No service change met the dollar or percentage threshold.'
      ),
    ])
  );

  body.append(
    el('div', { class: 'grid grid--halves' }, [
      el('div', { class: 'card' }, [
        el('h3', { class: 'card__title', text: 'Top increases' }),
        changeTable(data.topIncreases.slice(0, 10), currency, 'No increases in this period.'),
      ]),
      el('div', { class: 'card' }, [
        el('h3', { class: 'card__title', text: 'Top decreases' }),
        changeTable(data.topDecreases.slice(0, 10), currency, 'No decreases in this period.'),
      ]),
      el('div', { class: 'card' }, [
        el('h3', { class: 'card__title', text: 'New costs' }),
        el('p', { class: 'card__hint', text: 'Previous period $0, current period above $0.' }),
        changeTable(
          data.newCosts.slice(0, 10),
          currency,
          'No new services started incurring cost.'
        ),
      ]),
      el('div', { class: 'card' }, [
        el('h3', { class: 'card__title', text: 'Removed costs' }),
        el('p', { class: 'card__hint', text: 'Previous period above $0, current period $0.' }),
        changeTable(
          data.removedCosts.slice(0, 10),
          currency,
          'No services stopped incurring cost.'
        ),
      ]),
    ])
  );

  body.append(
    el('div', { class: 'grid grid--halves' }, [
      el('div', { class: 'card' }, [
        el('h3', { class: 'card__title', text: 'Current spend by service' }),
        breakdownBars(
          [...data.byService]
            .filter((change) => change.currentCost > 0)
            .sort((a, b) => b.currentCost - a.currentCost)
            .slice(0, 12)
            .map((change) => ({ label: change.key, value: change.currentCost })),
          { currency }
        ),
      ]),
      el('div', { class: 'card' }, [
        el('h3', { class: 'card__title', text: 'Current spend by region' }),
        breakdownBars(
          [...data.byRegion]
            .filter((change) => change.currentCost > 0)
            .sort((a, b) => b.currentCost - a.currentCost)
            .slice(0, 12)
            .map((change) => ({ label: change.key, value: change.currentCost })),
          { currency }
        ),
      ]),
    ])
  );

  return el('section', { class: 'profile-block' }, [profileHeader(profile), body]);
}

function profileHeader(profile) {
  return el('div', { class: 'profile-block__header' }, [
    el('span', { class: 'profile-block__name', text: profile.profile }),
    profile.accountId
      ? el('span', { class: 'profile-block__account', text: `account ${profile.accountId}` })
      : el('span', { class: 'subtle', text: 'account unknown' }),
    profile.status === 'ok' ? badge('complete', 'ok') : badge('partial data', 'medium'),
  ]);
}

export function renderBilling({ state, actions }) {
  const controls = el('div', { class: 'card' }, [
    el('div', { class: 'card__header' }, [
      el('h3', { class: 'card__title', text: 'Comparison period' }),
      el('p', {
        class: 'card__hint',
        text: 'Rolling comparison: the current window against the window immediately before it.',
      }),
    ]),
    el(
      'div',
      { class: 'toggle-group' },
      PERIODS.map((days) =>
        el('button', {
          class: 'toggle',
          type: 'button',
          'aria-pressed': String(state.config?.billing?.comparisonDays === days),
          text: `${days} day${days === 1 ? '' : 's'}`,
          onClick: async () => {
            await actions.persist({ billing: { comparisonDays: days } });
            await actions.loadSection('billing', { force: true });
          },
        })
      )
    ),
    el('div', { class: 'filters', style: 'margin-top:0.8rem' }, [
      el('div', { class: 'field' }, [
        el('label', { for: 'billing-dollar', text: 'Dollar threshold' }),
        el('input', {
          class: 'input',
          id: 'billing-dollar',
          type: 'number',
          min: '0',
          step: '1',
          value: String(state.config?.billing?.dollarThreshold ?? 20),
          onChange: async (event) => {
            await actions.persist({ billing: { dollarThreshold: Number(event.target.value) } });
            await actions.loadSection('billing', { force: true });
          },
        }),
      ]),
      el('div', { class: 'field' }, [
        el('label', { for: 'billing-percent', text: 'Percentage threshold' }),
        el('input', {
          class: 'input',
          id: 'billing-percent',
          type: 'number',
          min: '0',
          step: '1',
          value: String(state.config?.billing?.percentThreshold ?? 10),
          onChange: async (event) => {
            await actions.persist({ billing: { percentThreshold: Number(event.target.value) } });
            await actions.loadSection('billing', { force: true });
          },
        }),
      ]),
      el('div', { class: 'field' }, [
        el('label', { for: 'billing-metric', text: 'Cost metric' }),
        el(
          'select',
          {
            class: 'select',
            id: 'billing-metric',
            onChange: async (event) => {
              await actions.persist({ billing: { metric: event.target.value } });
              await actions.loadSection('billing', { force: true });
            },
          },
          ['UnblendedCost', 'AmortizedCost', 'NetUnblendedCost', 'BlendedCost'].map((metric) =>
            el('option', {
              value: metric,
              text: metric,
              selected: state.config?.billing?.metric === metric,
            })
          )
        ),
      ]),
    ]),
  ]);

  const shell = sectionShell({
    state,
    actions,
    key: 'billing',
    title: 'Billing / Cost',
    description:
      'Cost Explorer data at the granularity AWS actually provides: by service, by region and by day. Individual resource attribution is not claimed.',
    extraActions: [
      analyzeButton({ state, actions, sections: ['billing'], label: 'Analyze Billing' }),
    ],
    renderBody: (profile) => renderProfile(profile),
  });

  shell.insertBefore(controls, shell.children[1] ?? null);
  return shell;
}
