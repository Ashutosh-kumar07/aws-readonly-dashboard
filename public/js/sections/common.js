/** Shared scaffolding for data-backed sections. */

import { el, errorState, loadingState, emptyState, relativeTime, sectionHeader } from '../ui.js';

/**
 * Renders the header + load/loading/error scaffolding for a section, delegating
 * the body to `renderBody` when data is available.
 */
export function sectionShell({
  state,
  actions,
  key,
  title,
  description,
  extraActions = [],
  renderBody,
}) {
  const entry = state.sections[key];
  const container = el('div', {});

  container.append(
    sectionHeader({
      title,
      description,
      meta:
        entry.status === 'ready'
          ? `Fetched ${relativeTime(entry.fetchedAt)} · profiles: ${state.selectedProfiles.join(', ') || 'none'} · regions: ${
              state.selectedRegions.join(', ') || 'global only'
            }`
          : undefined,
      actions: [
        ...extraActions,
        el('button', {
          class: 'button',
          text: 'Refresh',
          disabled: entry.status === 'loading',
          onClick: () => void actions.loadSection(key, { force: true }),
        }),
      ],
    })
  );

  if (state.selectedProfiles.length === 0) {
    container.append(
      emptyState(
        'No AWS profile selected',
        'Choose one or more profiles in the header to load this section.'
      )
    );
    return container;
  }

  if (entry.status === 'idle') {
    // Opening a section fetches its data; returning to it reuses what is in memory.
    void actions.loadSection(key);
    container.append(loadingState());
    return container;
  }

  if (entry.status === 'loading') {
    container.append(loadingState());
    return container;
  }

  if (entry.status === 'error') {
    container.append(
      errorState(
        'Could not load this section',
        entry.error,
        () => void actions.loadSection(key, { force: true })
      )
    );
    return container;
  }

  const profiles = entry.data?.profiles ?? [];
  if (profiles.length === 0) {
    container.append(emptyState('No data returned for the current selection'));
    return container;
  }

  for (const profile of profiles) container.append(renderBody(profile, entry.data));
  return container;
}

/** Button that hands a section's data to the AI orchestrator on an explicit click. */
export function analyzeButton({ state, actions, sections, label }) {
  const disabled = state.ai?.nonLlmMode || state.aiBusy;
  return el('button', {
    class: 'button button--primary',
    text: state.aiBusy ? 'Analysing…' : label,
    disabled,
    title: state.ai?.nonLlmMode
      ? 'No AI provider is available. Install the Gemini CLI or configure a custom LLM endpoint in Settings.'
      : 'Sends only this section, sanitized, to the configured AI provider.',
    onClick: () => void actions.runAi({ sections, question: '' }),
  });
}
