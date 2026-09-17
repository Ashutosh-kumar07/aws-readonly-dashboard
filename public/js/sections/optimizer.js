/** Compute Optimizer view. */

import {
  el,
  money,
  number,
  badge,
  table,
  stat,
  issueList,
  emptyState,
  openDetail,
  detailGrid,
  codeBlock,
} from '../ui.js';
import { sectionShell, analyzeButton } from './common.js';

function renderProfile(profile) {
  const body = el('div', {});
  const issues = issueList(profile.issues, { title: 'Some Compute Optimizer data is unavailable' });
  if (issues) body.append(issues);

  const data = profile.data;
  if (!data) {
    body.append(emptyState('No Compute Optimizer data available for this profile'));
    return el('section', { class: 'profile-block' }, [header(profile), body]);
  }

  if (data.enrollment && data.enrollment.status !== 'Active') {
    body.append(
      el('div', { class: 'notice notice--warn' }, [
        el('strong', { text: `Compute Optimizer enrollment status: ${data.enrollment.status}` }),
        el('span', {
          text:
            data.enrollment.statusReason ??
            'Opt in to Compute Optimizer in the AWS console to receive recommendations. This dashboard cannot opt in for you.',
        }),
      ])
    );
  }

  body.append(
    el('div', { class: 'grid grid--stats' }, [
      stat('Recommendations', number(data.totals.count), 'non-optimised resources reported by AWS'),
      stat(
        'Estimated monthly savings',
        money(data.totals.estimatedMonthlySavings),
        'sum of AWS-provided estimates only'
      ),
      stat(
        'Without an AWS estimate',
        number(data.totals.withoutSavingsEstimate),
        'no figure is invented for these'
      ),
    ])
  );

  if (data.byResourceType.length > 0) {
    body.append(
      el('div', { class: 'card' }, [
        el('h3', { class: 'card__title', text: 'By resource type' }),
        table({
          columns: [
            { label: 'Resource type', key: 'resourceType' },
            { label: 'Recommendations', numeric: true, render: (row) => number(row.count) },
            {
              label: 'Estimated monthly savings',
              numeric: true,
              render: (row) => money(row.estimatedMonthlySavings),
            },
          ],
          rows: data.byResourceType,
        }),
      ])
    );
  }

  body.append(
    el('div', { class: 'card' }, [
      el('div', { class: 'card__header' }, [
        el('h3', { class: 'card__title', text: 'Recommendations' }),
        el('p', { class: 'card__hint', text: 'Sorted by the savings AWS estimated.' }),
      ]),
      table({
        emptyMessage:
          'AWS reported no rightsizing or idle-resource recommendations for this selection.',
        columns: [
          { label: 'Type', key: 'resourceType' },
          {
            label: 'Resource',
            render: (row) =>
              el('span', { class: 'mono truncate', title: row.resourceId, text: row.resourceId }),
          },
          { label: 'Region', key: 'region' },
          { label: 'Finding', render: (row) => badge(row.finding, 'medium') },
          {
            label: 'Performance risk',
            numeric: true,
            render: (row) =>
              row.performanceRisk === null
                ? el('span', { class: 'subtle', text: 'not provided' })
                : number(row.performanceRisk),
          },
          {
            label: 'Est. monthly savings',
            numeric: true,
            render: (row) =>
              row.estimatedMonthlySavings === null
                ? el('span', { class: 'subtle', text: 'not provided by AWS' })
                : money(row.estimatedMonthlySavings, row.currency ?? 'USD'),
          },
        ],
        rows: data.recommendations,
        onRowClick: (row) =>
          openDetail(
            `${row.resourceType} · ${row.resourceId}`,
            el('div', { class: 'stack' }, [
              detailGrid([
                ['Region', row.region],
                ['Finding', row.finding],
                ['Reasons', row.findingReasons.join(', ') || 'none reported'],
                [
                  'Performance risk',
                  row.performanceRisk === null
                    ? 'Not provided by AWS'
                    : String(row.performanceRisk),
                ],
                [
                  'Estimated monthly savings',
                  row.estimatedMonthlySavings === null
                    ? 'Not provided by AWS'
                    : money(row.estimatedMonthlySavings, row.currency ?? 'USD'),
                ],
                [
                  'Savings percentage',
                  row.savingsPercentage === null
                    ? 'Not provided by AWS'
                    : `${row.savingsPercentage}%`,
                ],
                [
                  'ARN',
                  row.resourceArn
                    ? el('span', { class: 'mono', text: row.resourceArn })
                    : undefined,
                ],
              ]),
              el('div', {}, [
                el('h4', { text: 'Why AWS flagged it' }),
                el('p', { text: row.reason }),
              ]),
              el('div', {}, [
                el('h4', { text: 'Current configuration' }),
                codeBlock(row.currentConfiguration),
              ]),
              el('div', {}, [
                el('h4', { text: 'Recommended configuration' }),
                row.recommendedConfiguration
                  ? codeBlock(row.recommendedConfiguration)
                  : el('p', {
                      class: 'subtle',
                      text: 'AWS did not return an alternative configuration.',
                    }),
              ]),
              el('p', {
                class: 'subtle',
                text: 'Recommendations are informational. This dashboard never resizes or modifies AWS resources.',
              }),
            ])
          ),
      }),
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

export function renderOptimizer({ state, actions }) {
  return sectionShell({
    state,
    actions,
    key: 'compute-optimizer',
    title: 'Compute Optimizer',
    description:
      'Rightsizing and idle-resource recommendations exactly as AWS reports them. Where AWS provides no estimate, none is shown.',
    extraActions: [
      analyzeButton({
        state,
        actions,
        sections: ['compute-optimizer'],
        label: 'Analyze Compute Optimizer',
      }),
    ],
    renderBody: (profile) => renderProfile(profile),
  });
}
