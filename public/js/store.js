/** Application state and the actions that mutate it. */

import { api } from './api.js';
import { toast } from './ui.js';

const SECTION_KEYS = ['billing', 'security', 'cloudwatch', 'compute-optimizer'];

export const state = {
  ready: false,
  status: null,
  config: null,
  profiles: [],
  regions: [],
  view: 'overview',
  selectedProfiles: [],
  selectedRegions: [],
  apiCalls: 0,
  ai: null,
  aiResult: null,
  aiError: null,
  aiBusy: false,
  aiPreview: null,
  aiSelection: { sections: ['billing'], question: '' },
  cloudtrail: {
    filters: {},
    page: 1,
    result: null,
    status: 'idle',
    error: null,
    selectedIds: new Set(),
  },
  usage: null,
  sections: Object.fromEntries(
    SECTION_KEYS.map((key) => [key, { status: 'idle', data: null, error: null, fetchedAt: null }])
  ),
};

const listeners = new Set();

export function subscribe(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function notify() {
  for (const listener of listeners) listener(state);
}

function selectionBody(extra = {}) {
  return {
    profiles: state.selectedProfiles,
    regions: state.selectedRegions,
    ...extra,
  };
}

export const actions = {
  async bootstrap() {
    const [status, config, profiles, regions] = await Promise.all([
      api.status(),
      api.getConfig(),
      api.profiles(),
      api.regions(),
    ]);
    state.status = status;
    state.config = config;
    state.profiles = profiles.profiles;
    state.regions = regions.regions;
    state.ai = status.ai;
    state.apiCalls = status.apiCalls;
    state.selectedProfiles = config.profiles.selected.filter((name) =>
      profiles.profiles.some((profile) => profile.name === name)
    );
    state.selectedRegions = config.regions.selected;

    // Nothing is selected yet on a first run: prefer `default`, else the first profile.
    if (state.selectedProfiles.length === 0 && profiles.profiles.length > 0) {
      const preferred =
        profiles.profiles.find((profile) => profile.name === 'default') ?? profiles.profiles[0];
      state.selectedProfiles = [preferred.name];
    }
    state.ready = true;
    notify();

    if (state.selectedProfiles.length > 0) void actions.validateProfiles();
  },

  async refreshStatus() {
    const status = await api.status();
    state.status = status;
    state.ai = status.ai;
    state.apiCalls = status.apiCalls;
    notify();
  },

  async validateProfiles() {
    if (state.selectedProfiles.length === 0) return;
    try {
      const result = await api.validateProfiles(state.selectedProfiles);
      const byName = new Map(result.profiles.map((profile) => [profile.name, profile]));
      state.profiles = state.profiles.map((profile) =>
        byName.has(profile.name) ? { ...profile, ...byName.get(profile.name) } : profile
      );
      for (const profile of result.profiles) {
        if (profile.error) {
          toast(`Profile ${profile.name}: ${profile.error.message}`, 'error');
        }
      }
      await actions.refreshStatus();
    } catch (error) {
      toast(`Could not validate profiles: ${error.message}`, 'error');
    }
    notify();
  },

  setView(view) {
    state.view = view;
    notify();
  },

  async setProfiles(profiles) {
    state.selectedProfiles = profiles;
    actions.invalidateAllSections();
    notify();
    await actions.persist({ profiles: { selected: profiles } });
    await actions.validateProfiles();
  },

  async setRegions(regions) {
    state.selectedRegions = regions;
    actions.invalidateAllSections();
    notify();
    await actions.persist({ regions: { selected: regions } });
  },

  async persist(patch) {
    try {
      state.config = await api.updateConfig(patch);
      notify();
    } catch (error) {
      toast(`Could not save configuration: ${error.message}`, 'error');
    }
  },

  invalidateAllSections() {
    for (const key of SECTION_KEYS) {
      state.sections[key] = { status: 'idle', data: null, error: null, fetchedAt: null };
    }
    state.cloudtrail.result = null;
    state.cloudtrail.status = 'idle';
    state.cloudtrail.selectedIds = new Set();
  },

  /** Loads a section, reusing in-memory data on the server unless `force`. */
  async loadSection(section, { force = false } = {}) {
    const entry = state.sections[section];
    if (!entry) return;
    if (!force && (entry.status === 'loading' || entry.status === 'ready')) return;
    if (state.selectedProfiles.length === 0) {
      entry.status = 'error';
      entry.error = 'Select at least one AWS profile.';
      notify();
      return;
    }

    entry.status = 'loading';
    entry.error = null;
    notify();

    try {
      const result = await api.section(section, selectionBody(force ? { refresh: true } : {}));
      entry.status = 'ready';
      entry.data = result;
      entry.fetchedAt = result.fetchedAt;
    } catch (error) {
      entry.status = 'error';
      entry.error = error.message;
    }
    await actions.refreshStatus();
    notify();
  },

  async refreshAll() {
    const loaded = SECTION_KEYS.filter((key) => state.sections[key].status === 'ready');
    const targets = loaded.length > 0 ? loaded : ['billing', 'security'];
    for (const key of targets) state.sections[key].status = 'loading';
    notify();

    try {
      await api.refreshAll(selectionBody({ sections: targets }));
      await Promise.all(targets.map((key) => actions.loadSection(key, { force: true })));
      if (state.cloudtrail.result) await actions.searchCloudTrail({ force: true });
      toast('Refreshed AWS data for the current selection.', 'success');
    } catch (error) {
      toast(`Refresh failed: ${error.message}`, 'error');
    }
    await actions.refreshStatus();
    notify();
  },

  async searchCloudTrail({ force = false, page } = {}) {
    if (state.selectedProfiles.length === 0) {
      state.cloudtrail.status = 'error';
      state.cloudtrail.error = 'Select at least one AWS profile.';
      notify();
      return;
    }
    state.cloudtrail.status = 'loading';
    state.cloudtrail.error = null;
    if (page) state.cloudtrail.page = page;
    notify();

    try {
      state.cloudtrail.result = await api.cloudtrailSearch(
        selectionBody({
          filters: state.cloudtrail.filters,
          page: state.cloudtrail.page,
          refresh: force,
        })
      );
      state.cloudtrail.status = 'ready';
    } catch (error) {
      state.cloudtrail.status = 'error';
      state.cloudtrail.error = error.message;
    }
    await actions.refreshStatus();
    notify();
  },

  async loadUsage() {
    try {
      state.usage = await api.usage();
      state.apiCalls = state.usage.totalCalls;
    } catch (error) {
      toast(`Could not load AWS API usage: ${error.message}`, 'error');
    }
    notify();
  },

  async setFindingStatus(id, status) {
    try {
      await api.setFindingStatus(id, status);
      toast(`Finding marked as ${status}.`, 'success');
      await actions.loadSection('security', { force: true });
    } catch (error) {
      toast(`Could not update the finding: ${error.message}`, 'error');
    }
  },

  /** AI analysis — only ever called from an explicit click. */
  async runAi({ sections, question, selectedEvents }) {
    state.aiBusy = true;
    state.aiError = null;
    notify();
    try {
      state.aiResult = await api.aiAnalyze({
        sections,
        profiles: state.selectedProfiles,
        regions: state.selectedRegions,
        question,
        selectedEvents,
      });
      state.view = 'ai';
      toast(`Analysis complete (${state.aiResult.provider}).`, 'success');
    } catch (error) {
      state.aiError = { message: error.message, details: error.details };
      toast(`AI analysis failed: ${error.message}`, 'error');
    }
    state.aiBusy = false;
    await actions.refreshStatus();
    notify();
  },

  async previewAi({ sections, question, selectedEvents }) {
    state.aiBusy = true;
    notify();
    try {
      state.aiPreview = await api.aiPreview({
        sections,
        profiles: state.selectedProfiles,
        regions: state.selectedRegions,
        question,
        selectedEvents,
      });
    } catch (error) {
      toast(`Could not build the payload preview: ${error.message}`, 'error');
    }
    state.aiBusy = false;
    notify();
  },
};
