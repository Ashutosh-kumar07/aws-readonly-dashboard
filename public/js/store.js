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
  /** Finding id -> severity assigned by the AI in the most recent analysis. */
  aiSeverityOverrides: {},
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
    SECTION_KEYS.map((key) => [
      key,
      { status: 'idle', data: null, error: null, fetchedAt: null, progress: null, jobId: null },
    ])
  ),
};

const POLL_INTERVAL_MS = 900;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Follows a streaming section job, rendering each snapshot as it arrives so the
 * user sees real data long before the whole scan finishes.
 */
async function pollJob(section, firstSnapshot) {
  const entry = state.sections[section];
  let snapshot = firstSnapshot;

  for (;;) {
    entry.progress = snapshot.progress ?? null;

    if (snapshot.status === 'cancelled') {
      // The scan stopped on request. Partial data is dropped rather than left
      // on screen, where it would read as a finished result.
      entry.status = 'idle';
      entry.data = null;
      entry.error = null;
      entry.progress = null;
      entry.jobId = null;
      notify();
      return;
    }

    if (snapshot.status === 'failed') {
      entry.status = 'error';
      entry.error = snapshot.error ?? 'The scan failed.';
      entry.progress = null;
      return;
    }

    if (snapshot.status === 'complete') {
      const envelope = snapshot.partial?.envelope;
      if (envelope) {
        entry.status = 'ready';
        entry.data = envelope;
        entry.fetchedAt = envelope.fetchedAt;
      } else {
        entry.status = 'error';
        entry.error = 'The scan finished without returning data.';
      }
      entry.progress = null;
      entry.jobId = null;
      return;
    }

    // Still running: show whatever has been collected so far.
    const partial = snapshot.partial?.partial;
    if (partial?.profiles?.length) {
      entry.status = 'partial';
      entry.data = {
        section,
        fetchedAt: new Date().toISOString(),
        fromCache: false,
        profiles: partial.profiles,
        regions: state.selectedRegions,
        categories: [],
      };
    }
    notify();

    await sleep(POLL_INTERVAL_MS);
    snapshot = await api.job(snapshot.id);
  }
}

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
    state.aiSeverityOverrides = {};
    for (const key of SECTION_KEYS) {
      state.sections[key] = {
        status: 'idle',
        data: null,
        error: null,
        fetchedAt: null,
        progress: null,
        jobId: null,
      };
    }
    state.cloudtrail.result = null;
    state.cloudtrail.status = 'idle';
    state.cloudtrail.selectedIds = new Set();
  },

  /**
   * Loads a section. The server streams partial results, so findings are
   * rendered as each check completes rather than after the slowest one.
   */
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
    entry.progress = null;
    notify();

    try {
      const started = await api.section(
        section,
        selectionBody({ stream: true, ...(force ? { refresh: true } : {}) })
      );
      entry.jobId = started.id;
      await pollJob(section, started);
    } catch (error) {
      entry.status = 'error';
      entry.error = error.message;
      entry.progress = null;
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
      // The server refetches each section once; the reloads below then reuse
      // that in-memory data rather than issuing a second round of AWS calls.
      await api.refreshAll(selectionBody({ sections: targets }));
      await Promise.all(targets.map((key) => actions.loadSection(key)));
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
        cloudtrailFilters: state.cloudtrail.filters,
      });
      // The AI's severity replaces the dashboard's own for any finding it
      // matched; the original severity is not shown alongside it.
      if (sections.includes('security')) {
        const overrides = {};
        for (const finding of state.aiResult.analysis.findings ?? []) {
          if (finding.findingId) overrides[finding.findingId] = finding.severity;
        }
        state.aiSeverityOverrides = overrides;
      }
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
        cloudtrailFilters: state.cloudtrail.filters,
      });
    } catch (error) {
      toast(`Could not build the payload preview: ${error.message}`, 'error');
    }
    state.aiBusy = false;
    notify();
  },
};
