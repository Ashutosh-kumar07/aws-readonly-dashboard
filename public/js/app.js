/** Entry point: top bar wiring, navigation and view rendering. */

import { state, actions, subscribe, notify } from './store.js';
import { clear, el, number, toast } from './ui.js';
import { renderOverview } from './sections/overview.js';
import { renderBilling } from './sections/billing.js';
import { renderSecurity } from './sections/security.js';
import { renderOptimizer } from './sections/optimizer.js';
import { renderCloudWatch } from './sections/cloudwatch.js';
import { renderCloudTrail } from './sections/cloudtrail.js';
import { renderAi } from './sections/ai.js';
import { renderUsage } from './sections/usage.js';
import { renderSettings } from './sections/settings.js';

const VIEWS = {
  overview: renderOverview,
  billing: renderBilling,
  security: renderSecurity,
  optimizer: renderOptimizer,
  cloudwatch: renderCloudWatch,
  cloudtrail: renderCloudTrail,
  ai: renderAi,
  usage: renderUsage,
  settings: renderSettings,
};

const root = document.getElementById('view-root');

function applyTheme() {
  const theme = state.config?.ui?.theme ?? 'system';
  if (theme === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', theme);
}

function renderTopbar() {
  const profileSummary = document.getElementById('profile-summary');
  const selected = state.selectedProfiles;
  profileSummary.textContent =
    selected.length === 0
      ? 'none selected'
      : selected.length === 1
        ? selected[0]
        : `${selected.length} profiles`;

  const regionSummary = document.getElementById('region-summary');
  regionSummary.textContent =
    state.selectedRegions.length === 0
      ? 'global only'
      : state.selectedRegions.length <= 2
        ? state.selectedRegions.join(', ')
        : `${state.selectedRegions.length} regions`;

  const aiChip = document.getElementById('ai-status-chip');
  const aiValue = document.getElementById('ai-status-value');
  if (state.ai) {
    const active = state.ai.activeProvider;
    const provider = state.ai.providers.find((item) => item.id === active);
    aiValue.textContent = state.ai.nonLlmMode ? 'Non-LLM mode' : (provider?.label ?? 'ready');
    aiChip.classList.toggle('chip--ok', !state.ai.nonLlmMode);
    aiChip.classList.toggle('chip--warn', state.ai.nonLlmMode);
    aiChip.title = state.ai.providers
      .map((item) => `${item.label}${item.detail ? ` — ${item.detail}` : ''}`)
      .join('\n');
  }

  document.getElementById('api-counter-value').textContent = number(state.apiCalls);

  const subtitle = document.getElementById('server-subtitle');
  if (state.status?.server) {
    subtitle.textContent = `${state.status.server.url} · read-only · session API calls: ${number(state.apiCalls)}`;
  }
  const version = document.getElementById('version-label');
  if (state.status) version.textContent = `v${state.status.version}`;

  for (const button of document.querySelectorAll('.nav__item')) {
    const active = button.dataset.view === state.view;
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  }
}

function render() {
  applyTheme();
  renderTopbar();
  const renderView = VIEWS[state.view] ?? renderOverview;
  clear(root);
  try {
    root.append(renderView({ state, actions }));
  } catch (error) {
    root.append(
      el('div', { class: 'notice notice--error' }, [
        el('strong', { text: 'The dashboard could not render this view.' }),
        el('span', { text: error.message }),
      ])
    );
  }
}

/* ---------- profile dialog ---------- */

const profileDialog = document.getElementById('profile-dialog');
let pendingProfiles = [];

function renderProfileDialog() {
  const list = clear(document.getElementById('profile-list'));
  if (state.profiles.length === 0) {
    list.append(
      el('p', { class: 'muted' }, [
        'No AWS profiles were found. Configure the AWS CLI (',
        el('code', { text: 'aws configure' }),
        ') or export credentials in your environment, then reopen this dialog.',
      ])
    );
    return;
  }

  for (const profile of state.profiles) {
    const id = `profile-${profile.name}`;
    const checkbox = el('input', {
      type: 'checkbox',
      id,
      checked: pendingProfiles.includes(profile.name),
      onChange: (event) => {
        pendingProfiles = event.target.checked
          ? [...new Set([...pendingProfiles, profile.name])]
          : pendingProfiles.filter((name) => name !== profile.name);
      },
    });

    list.append(
      el('div', { class: 'checkbox-row' }, [
        checkbox,
        el('div', {}, [
          el('label', { for: id, text: profile.label }),
          el(
            'div',
            { class: 'hint' },
            [
              `${profile.kind}`,
              profile.region ? ` · default region ${profile.region}` : '',
              profile.accountId ? ` · account ${profile.accountId}` : '',
              profile.error ? ` · ${profile.error.message}` : '',
            ].join('')
          ),
        ]),
      ])
    );
  }
}

document.getElementById('profile-trigger').addEventListener('click', () => {
  pendingProfiles = [...state.selectedProfiles];
  renderProfileDialog();
  profileDialog.showModal();
});

profileDialog.addEventListener('close', () => {
  if (profileDialog.returnValue !== 'apply') return;
  void actions.setProfiles(pendingProfiles);
});

/* ---------- region dialog ---------- */

const regionDialog = document.getElementById('region-dialog');
let pendingRegions = [];
let regionFilter = '';

function renderRegionDialog() {
  const list = clear(document.getElementById('region-list'));
  const filtered = state.regions.filter(
    (region) =>
      !regionFilter ||
      region.id.includes(regionFilter.toLowerCase()) ||
      region.label.toLowerCase().includes(regionFilter.toLowerCase())
  );

  for (const region of filtered) {
    const id = `region-${region.id}`;
    list.append(
      el('div', { class: 'checkbox-row' }, [
        el('input', {
          type: 'checkbox',
          id,
          checked: pendingRegions.includes(region.id),
          onChange: (event) => {
            pendingRegions = event.target.checked
              ? [...new Set([...pendingRegions, region.id])]
              : pendingRegions.filter((value) => value !== region.id);
          },
        }),
        el('div', {}, [
          el('label', { for: id, text: region.id }),
          el('div', { class: 'hint', text: region.label }),
        ]),
      ])
    );
  }
}

document.getElementById('region-trigger').addEventListener('click', () => {
  pendingRegions = [...state.selectedRegions];
  regionFilter = '';
  document.getElementById('region-filter').value = '';
  renderRegionDialog();
  regionDialog.showModal();
});

document.getElementById('region-filter').addEventListener('input', (event) => {
  regionFilter = event.target.value.trim();
  renderRegionDialog();
});

document.getElementById('region-select-all').addEventListener('click', () => {
  pendingRegions = state.regions.map((region) => region.id);
  renderRegionDialog();
});

document.getElementById('region-clear-all').addEventListener('click', () => {
  pendingRegions = [];
  renderRegionDialog();
});

regionDialog.addEventListener('close', () => {
  if (regionDialog.returnValue !== 'apply') return;
  void actions.setRegions(pendingRegions);
});

/* ---------- top bar actions ---------- */

document.getElementById('api-counter').addEventListener('click', () => {
  actions.setView('usage');
  void actions.loadUsage();
});

document.getElementById('ai-status-chip').addEventListener('click', () => {
  actions.setView('ai');
});

document.getElementById('refresh-all').addEventListener('click', () => {
  void actions.refreshAll();
});

for (const button of document.querySelectorAll('.nav__item')) {
  button.addEventListener('click', () => {
    actions.setView(button.dataset.view);
    document.getElementById('main').focus();
  });
}

/* ---------- boot ---------- */

subscribe(render);

actions.bootstrap().then(
  () => {
    render();
  },
  (error) => {
    toast(`Could not start the dashboard UI: ${error.message}`, 'error');
    clear(root).append(
      el('div', { class: 'notice notice--error' }, [
        el('strong', { text: 'The dashboard could not load its configuration.' }),
        el('span', { text: error.message }),
      ])
    );
  }
);

// Keep the API counter honest without polling AWS: this only reads local state.
setInterval(() => {
  if (!state.ready) return;
  void actions.refreshStatus();
}, 15000);

notify();
