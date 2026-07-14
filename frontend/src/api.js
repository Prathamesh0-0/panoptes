/* PANOPTES — Centralized API client */

const BASE = '/api'

async function get(path) {
  const res = await fetch(`${BASE}${path}`)
  if (!res.ok) throw new Error(`API error ${res.status}: ${path}`)
  return res.json()
}

async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`API error ${res.status}: ${path}`)
  return res.json()
}

async function patch(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  })
  return res.json()
}

export const api = {
  // Health
  health: () => get('/health'),

  // Sessions
  sessions: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return get(`/sessions${q ? '?' + q : ''}`)
  },
  sessionStats: () => get('/sessions/stats'),
  session: (id) => get(`/sessions/${id}`),

  // Alerts
  alerts: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return get(`/alerts${q ? '?' + q : ''}`)
  },
  resolveAlert: (id) => patch(`/alerts/${id}/status?status=RESOLVED`),

  // Identities
  identities: () => get('/identities'),
  identity: (id) => get(`/identities/${id}`),

  // Audit
  auditLogs: () => get('/audit'),
  verifyLog: (id) => post(`/audit/${id}/verify`),
  tamperLog: (id) => post(`/audit/${id}/tamper`),
  auditPqcStatus: () => get('/audit/pqc-status'),

  // PQC
  pqcStatus: () => get('/pqc/status'),
  vaultEncrypt: (label, plaintext, ownerId = 'demo') =>
    post('/pqc/vault/encrypt', { label, plaintext, owner_id: ownerId }),
  vaultDecrypt: (vaultId) => post('/pqc/vault/decrypt', { vault_id: vaultId }),
  vaultList: () => get('/pqc/vault'),
  pqcSign: (message) => post('/pqc/sign', { message }),
  pqcVerify: (entry) => post('/pqc/verify', { entry }),
}

export function scoreColor(score) {
  if (score >= 80) return 'var(--risk-critical)'
  if (score >= 60) return 'var(--risk-high)'
  if (score >= 40) return 'var(--risk-medium)'
  return 'var(--risk-low)'
}

export function scoreLabel(score) {
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 40) return 'MEDIUM'
  if (score >= 20) return 'LOW'
  return 'MINIMAL'
}

export function formatTime(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })
}

export function formatDateTime(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('en-IN', {
    day: '2-digit', month: 'short',
    hour: '2-digit', minute: '2-digit',
  })
}
