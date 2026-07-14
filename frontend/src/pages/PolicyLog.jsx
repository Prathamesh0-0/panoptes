import { useState, useEffect, useCallback } from 'react'
import { api, formatDateTime } from '../api'
import { RiskBadge, VerdictBadge } from '../components/RiskBadge'

const FILTERS = [
  { label: 'All Actions', value: 'ALL' },
  { label: '⛔ Kill Session', value: 'KILL_SESSION' },
  { label: '🔐 Step-Up MFA', value: 'STEPUP_MFA' },
  { label: '📋 Log Only', value: 'LOG_ONLY' },
]

export default function PolicyLog() {
  const [logs, setLogs] = useState([])
  const [filter, setFilter] = useState('ALL')
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const params = filter !== 'ALL' ? { policy_action: filter } : {}
      const data = await api.alerts(params)
      setLogs(data.alerts || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [filter])

  useEffect(() => { load() }, [load])

  const summary = {
    total: logs.length,
    kill: logs.filter(l => l.policy_action === 'KILL_SESSION').length,
    mfa: logs.filter(l => l.policy_action === 'STEPUP_MFA').length,
    log: logs.filter(l => l.policy_action === 'LOG_ONLY').length,
  }

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Policy Verdict Log</div>
          <div className="page-subtitle">OPA Rego policy decisions — every access control action taken by PANOPTES</div>
        </div>
        <button className="btn btn-secondary btn-sm" onClick={load}>↻ Refresh</button>
      </div>

      {/* Summary stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Verdicts</div>
          <div className="stat-value blue">{summary.total}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Sessions Killed</div>
          <div className="stat-value critical">{summary.kill}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">MFA Challenges</div>
          <div className="stat-value high">{summary.mfa}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Log Only</div>
          <div className="stat-value">{summary.log}</div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">OPA Decisions</span>
          <div className="filters-bar">
            {FILTERS.map(f => (
              <button
                key={f.value}
                className={`filter-btn ${filter === f.value ? 'active' : ''}`}
                onClick={() => setFilter(f.value)}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="loading-spinner"><div className="spinner" />Loading policy log…</div>
        ) : logs.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-title">No verdicts yet</div>
            <div className="empty-state-sub">Verdicts appear as sessions are processed</div>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Identity</th>
                <th>Peer Group</th>
                <th>Risk Score</th>
                <th>Anomaly Type</th>
                <th>Policy Action</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => (
                <tr key={log.alert_id} className={log.policy_action === 'KILL_SESSION' ? 'flagged-row' : ''}>
                  <td className="text-muted text-sm mono">{formatDateTime(log.timestamp)}</td>
                  <td>
                    <div style={{ fontWeight: 500 }}>{log.identity_name}</div>
                    <div className="text-muted text-xs">{log.peer_group?.replace(/_/g, ' ')}</div>
                  </td>
                  <td><span className="tag">{log.peer_group?.replace(/_/g, ' ')}</span></td>
                  <td>
                    <span style={{
                      fontWeight: 700,
                      fontVariantNumeric: 'tabular-nums',
                      color: log.risk_score >= 80 ? 'var(--risk-critical)'
                           : log.risk_score >= 60 ? 'var(--risk-high)'
                           : log.risk_score >= 40 ? 'var(--risk-medium)'
                           : 'var(--risk-low)',
                    }}>
                      {log.risk_score?.toFixed(1)}
                    </span>
                    <span className="text-muted text-xs"> /100</span>
                  </td>
                  <td>
                    <span className="inline-code" style={{ fontSize: 11 }}>
                      {log.anomaly_type?.replace(/_/g, ' ') || 'BEHAVIORAL'}
                    </span>
                  </td>
                  <td><VerdictBadge action={log.policy_action} /></td>
                  <td>
                    <span className={`tag ${log.status === 'ACTIVE' ? '' : 'resolved'}`}
                          style={log.status === 'ACTIVE' ? { color: 'var(--risk-medium)', borderColor: 'var(--risk-medium-border)' } : {}}>
                      {log.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* OPA info box */}
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Policy Rules (Rego)</span>
          <span className="tag">OPA v1 · panoptes.rego</span>
        </div>
        <div className="panel-body">
          <div className="code-block" style={{ lineHeight: 1.8 }}>
{`# Rule 1: KILL SESSION  — risk_score ≥ 80
# Rule 2: STEP-UP MFA   — risk_score ≥ 50 (employees)
# Rule 3: STEP-UP MFA   — risk_score ≥ 40 (contractors, tighter threshold)
# Rule 4: KILL SESSION  — after-hours + critical system + contractor/branch (risk ≥ 60)
# Rule 5: KILL SESSION  — ESCALATE + LATERAL actions detected + risk ≥ 70`}
          </div>
        </div>
      </div>
    </>
  )
}
