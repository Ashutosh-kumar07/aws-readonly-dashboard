/** Thin fetch wrapper around the dashboard API. */

export class ApiError extends Error {
  constructor(message, status, details) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    method: options.method ?? 'GET',
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { error: text };
    }
  }

  if (!response.ok) {
    throw new ApiError(payload?.error ?? response.statusText, response.status, payload?.details);
  }
  return payload;
}

export const api = {
  status: () => request('/api/status'),
  getConfig: () => request('/api/config'),
  updateConfig: (patch) => request('/api/config', { method: 'PUT', body: patch }),
  deleteConfig: () => request('/api/config', { method: 'DELETE' }),

  profiles: () => request('/api/profiles'),
  validateProfiles: (profiles) =>
    request('/api/profiles/validate', { method: 'POST', body: { profiles } }),
  regions: () => request('/api/regions'),
  permissions: () => request('/api/permissions'),
  securityChecks: () => request('/api/security/checks'),

  section: (section, body) => request(`/api/sections/${section}`, { method: 'POST', body }),
  refreshAll: (body) => request('/api/sections/refresh-all', { method: 'POST', body }),

  cloudtrailSearch: (body) => request('/api/cloudtrail/search', { method: 'POST', body }),

  setFindingStatus: (id, status, note) =>
    request(`/api/security/findings/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: { status, note },
    }),
  trackedFindings: () => request('/api/security/findings'),
  deleteResolvedFindings: () => request('/api/security/findings/resolved', { method: 'DELETE' }),

  usage: (limit = 500) => request(`/api/aws-usage?limit=${limit}`),

  aiStatus: (refresh = false) => request(`/api/ai/status${refresh ? '?refresh=true' : ''}`),
  aiPreview: (body) => request('/api/ai/preview', { method: 'POST', body }),
  aiAnalyze: (body) => request('/api/ai/analyze', { method: 'POST', body }),
  aiHistory: () => request('/api/ai/history'),
  deleteAiHistory: () => request('/api/ai/history', { method: 'DELETE' }),
};
