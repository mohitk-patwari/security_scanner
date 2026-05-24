const _configured = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')
const API_BASE = _configured || (import.meta.env.DEV ? 'http://localhost:8000' : '')

const API_KEY_STORAGE = 'netguard_api_key'

export { API_BASE, API_KEY_STORAGE }

export function getStoredApiKey() {
  try {
    return localStorage.getItem(API_KEY_STORAGE) || ''
  } catch {
    return ''
  }
}

export function setStoredApiKey(key) {
  try {
    if (key) localStorage.setItem(API_KEY_STORAGE, key)
    else localStorage.removeItem(API_KEY_STORAGE)
  } catch { /* storage disabled */ }
}

export function clearStoredApiKey() {
  setStoredApiKey('')
}

const PUBLIC_AUTH_PATHS = new Set(['/api/auth/signup', '/api/auth/login'])

function _redirectToLogin() {
  if (typeof window === 'undefined') return
  const here = window.location.pathname + window.location.search
  if (here.startsWith('/login') || here.startsWith('/signup')) return
  // Preserve intent for after-login redirect.
  try {
    sessionStorage.setItem('netguard_post_login_redirect', here)
  } catch { /* ignore */ }
  window.location.assign('/login')
}

export async function apiFetch(path, opts = {}) {
  const headers = new Headers(opts.headers || {})
  if (!PUBLIC_AUTH_PATHS.has(path)) {
    const key = getStoredApiKey()
    if (key) headers.set('X-API-Key', key)
  }
  const res = await fetch(`${API_BASE}${path}`, { ...opts, headers })
  if (res.status === 401 && !PUBLIC_AUTH_PATHS.has(path)) {
    clearStoredApiKey()
    _redirectToLogin()
  }
  if (!res.ok) {
    let detail = `HTTP ${res.status}`
    try {
      const body = await res.json()
      detail = body?.detail?.message || body?.detail || JSON.stringify(body)
    } catch { /* not JSON */ }
    throw new Error(detail)
  }
  return res.json()
}

export const fetchStats = () => apiFetch('/api/stats')
export const fetchScans = () => apiFetch('/api/scans')
export const fetchRepos = () => apiFetch('/api/repos')
export const fetchScan = (id) => apiFetch(`/api/scans/${id}`)
export const fetchGraph = (id) => apiFetch(`/api/scans/${id}/graph`)
export const fetchDiff = (id) => apiFetch(`/api/scans/${id}/diff`)
export const fetchOverrides = () => apiFetch('/api/overrides')
export const fetchEvaluations = (scanId) =>
  apiFetch(`/api/evaluations${scanId != null ? `?scan_id=${scanId}` : ''}`)
export const fetchEvaluationSummary = () => apiFetch('/api/evaluations/summary')
export const fetchMe = () => apiFetch('/api/me')
export const fetchSettings = () => apiFetch('/api/settings')

export async function proposeFix(scanId, findingId, body = {}) {
  return apiFetch(`/api/scans/${scanId}/findings/${findingId}/propose-fix`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body && Object.keys(body).length ? body : {}),
  })
}

export const fetchScanFixes = (scanId) => apiFetch(`/api/scans/${scanId}/fixes`)

export function postGithubFixComment(proposalId, githubToken) {
  const token = (githubToken || '').trim()
  return apiFetch(`/api/fix-proposals/${proposalId}/post-github-comment`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'X-GitHub-Token': token } : {}),
    },
    body: JSON.stringify(token ? { github_token: token } : {}),
  })
}

export function postScan(payload) {
  return apiFetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

export function postOverride(data) {
  return apiFetch('/api/overrides', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...data, severity_override: null, created_by: 'frontend-user' }),
  })
}

export function postEvaluation(data) {
  return apiFetch('/api/evaluations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
}

export function signup({ name, email, password }) {
  return apiFetch('/api/auth/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password }),
  })
}

export function login({ email, password }) {
  return apiFetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}

export function regenerateApiKey() {
  return apiFetch('/api/auth/regenerate-key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  })
}
