/** DOM helpers, formatters and shared render fragments. */

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key === 'html') node.innerHTML = value;
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

const currencyFormatters = new Map();

export function money(value, currency = 'USD') {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—';
  let formatter = currencyFormatters.get(currency);
  if (!formatter) {
    try {
      formatter = new Intl.NumberFormat(undefined, {
        style: 'currency',
        currency,
        maximumFractionDigits: 2,
      });
    } catch {
      formatter = new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 });
    }
    currencyFormatters.set(currency, formatter);
  }
  return formatter.format(Number(value));
}

export function number(value, digits = 0) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—';
  return new Intl.NumberFormat(undefined, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(Number(value));
}

export function percent(value, digits = 1) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—';
  const sign = Number(value) > 0 ? '+' : '';
  return `${sign}${number(value, digits)}%`;
}

export function bytes(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let size = Number(value);
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${number(size, size < 10 && unit > 0 ? 1 : 0)} ${units[unit]}`;
}

export function dateTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

export function relativeTime(value) {
  if (!value) return '—';
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return String(value);
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

export function badge(text, variant = 'neutral') {
  return el('span', { class: `badge badge--${variant}`, text });
}

export function loadingState(message = 'Loading AWS data…') {
  return el('div', { class: 'state' }, [
    el('span', { class: 'spinner', 'aria-hidden': 'true' }),
    el('p', { class: 'state__title', text: message }),
    el('p', { text: 'Only read-only AWS APIs are called.' }),
  ]);
}

export function emptyState(title, detail) {
  return el('div', { class: 'state' }, [
    el('span', { class: 'state__icon', text: '∅', 'aria-hidden': 'true' }),
    el('p', { class: 'state__title', text: title }),
    detail ? el('p', { text: detail }) : null,
  ]);
}

export function errorState(title, detail, onRetry) {
  return el('div', { class: 'state state--error' }, [
    el('span', { class: 'state__icon', text: '⚠', 'aria-hidden': 'true' }),
    el('p', { class: 'state__title', text: title }),
    detail ? el('p', { text: detail }) : null,
    onRetry ? el('button', { class: 'button', text: 'Try again', onClick: onRetry }) : null,
  ]);
}

/** Renders "unable to evaluate" issues; never collapses them into "secure". */
export function issueList(issues, options = {}) {
  if (!issues || issues.length === 0) return null;
  const grouped = new Map();
  for (const issue of issues) {
    const key = `${issue.service}|${issue.label}|${issue.missingPermission ?? ''}`;
    const entry = grouped.get(key) ?? { issue, regions: new Set() };
    entry.regions.add(issue.region);
    grouped.set(key, entry);
  }

  return el('div', { class: `notice notice--${options.variant ?? 'warn'}` }, [
    el('strong', { text: options.title ?? 'Some checks could not be evaluated' }),
    el(
      'ul',
      { class: 'list-reset' },
      [...grouped.values()].map((entry) =>
        el('li', {}, [
          el('strong', { text: `${entry.issue.service}: ` }),
          `${entry.issue.label}`,
          entry.issue.missingPermission
            ? el('span', { class: 'mono', text: ` (needs ${entry.issue.missingPermission})` })
            : null,
          el('span', { class: 'subtle', text: ` — ${[...entry.regions].join(', ')}` }),
        ])
      )
    ),
  ]);
}

export function sectionHeader({ title, description, meta, actions }) {
  return el('div', { class: 'section-header' }, [
    el('div', {}, [
      el('h2', { text: title }),
      description ? el('p', { class: 'card__hint', text: description }) : null,
      meta ? el('p', { class: 'section-header__meta', text: meta }) : null,
    ]),
    el('div', { class: 'section-header__actions' }, actions ?? []),
  ]);
}

export function table({ columns, rows, onRowClick, emptyMessage }) {
  if (!rows || rows.length === 0) {
    return emptyState(emptyMessage ?? 'Nothing to show');
  }
  const head = el(
    'thead',
    {},
    el(
      'tr',
      {},
      columns.map((column) => el('th', { class: column.numeric ? 'num' : '', text: column.label }))
    )
  );
  const body = el(
    'tbody',
    {},
    rows.map((row, index) => {
      const tr = el(
        'tr',
        { class: onRowClick ? 'is-clickable' : '' },
        columns.map((column) => {
          const value = column.render ? column.render(row, index) : row[column.key];
          return el(
            'td',
            { class: column.numeric ? 'num' : '' },
            value instanceof Node
              ? value
              : value === undefined || value === null
                ? '—'
                : String(value)
          );
        })
      );
      if (onRowClick) {
        tr.addEventListener('click', () => onRowClick(row));
        tr.tabIndex = 0;
        tr.addEventListener('keydown', (event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            onRowClick(row);
          }
        });
      }
      return tr;
    })
  );
  return el('div', { class: 'table-wrap' }, el('table', {}, [head, body]));
}

export function stat(label, value, detail, onClick) {
  const children = [
    el('div', { class: 'stat__label', text: label }),
    el('div', { class: 'stat__value' }, value instanceof Node ? value : String(value)),
    detail
      ? el('div', { class: 'stat__detail' }, detail instanceof Node ? detail : String(detail))
      : null,
  ];
  return onClick
    ? el('button', { class: 'stat stat--clickable', type: 'button', onClick }, children)
    : el('div', { class: 'stat' }, children);
}

export function profileBlock(profile, children) {
  return el('section', { class: 'profile-block' }, [
    el('div', { class: 'profile-block__header' }, [
      el('span', { class: 'profile-block__name', text: profile.profile }),
      profile.accountId
        ? el('span', { class: 'profile-block__account', text: `account ${profile.accountId}` })
        : el('span', { class: 'subtle', text: 'account unknown' }),
      profile.status === 'ok'
        ? badge('complete', 'ok')
        : profile.status === 'partial'
          ? badge('partial data', 'medium')
          : badge('failed', 'critical'),
    ]),
    ...[].concat(children),
  ]);
}

export function toast(message, variant = 'info') {
  const host = document.getElementById('toasts');
  if (!host) return;
  const node = el('div', { class: `toast toast--${variant}`, role: 'status', text: message });
  host.append(node);
  setTimeout(() => node.remove(), variant === 'error' ? 9000 : 5000);
}

export function openDetail(title, content) {
  const dialog = document.getElementById('detail-dialog');
  document.getElementById('detail-dialog-title').textContent = title;
  const body = clear(document.getElementById('detail-body'));
  body.append(content);
  dialog.showModal();
}

export function detailGrid(entries) {
  return el(
    'dl',
    { class: 'detail-grid' },
    entries.flatMap(([key, value]) =>
      value === undefined || value === null || value === ''
        ? []
        : [el('dt', { text: key }), el('dd', {}, value instanceof Node ? value : String(value))]
    )
  );
}

export function codeBlock(value) {
  return el('pre', {
    class: 'code-block',
    text: typeof value === 'string' ? value : JSON.stringify(value, null, 2),
  });
}

export function confirmDestructive(message) {
  return window.confirm(message);
}
