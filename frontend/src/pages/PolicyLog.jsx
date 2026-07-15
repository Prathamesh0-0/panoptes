import { useState, useEffect, useCallback } from 'react'
import { api, formatDateTime } from '../api'
import { RiskBadge, VerdictBadge } from '../components/RiskBadge'

const FILTERS = [
  { label: 'All Actions',   value: 'ALL' },
  { label: 'Kill Session',  value: 'KILL_SESSION' },
  { label: 'Step-Up MFA',  value: 'STEPUP_MFA' },
  { label: 'Log Only',     value: 'LOG_ONLY' },
]

export default function PolicyLog() {
  const [logs, setLogs] = useState([])
  const [filter, setFilter] = useState('ALL')
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(null)

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
    kill:  logs.filter(l => l.policy_action === 'KILL_SESSION').length,
    mfa:   logs.filter(l => l.policy_action === 'STEPUP_MFA').length,
    log:   logs.filter(l => l.policy_action === 'LOG_ONLY').length,
  }

  return (
    <>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
        <StatCard label="Total Verdicts"   value={summary.total} />
        <StatCard label="Sessions Killed"  value={summary.kill}  variant="critical" />
        <StatCard label="MFA Challenges"   value={summary.mfa}   variant="high" />
        <StatCard label="Log Only"         value={summary.log}   />
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">OPA Verdict Log</span>
          <div className="panel-actions">
            <div className="filters-bar">
              {FILTERS.map(f => (
                <button
                  key={f.value}
                  className={`filter-btn ${filter === f.value ? 'active' : ''}`}
                  onClick={() => setFilter(f.value)}
                >{f.label}</button>
              ))}
            </div>
            <button className="btn btn-secondary btn-sm" onClick={load}>Refresh</button>
          </div>
        </div>

        {loading ? (
          <div className="loading-state"><div className="spinner" /> Loading…</div>
        ) : logs.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-title">No verdicts yet</div>
            <div className="empty-state-sub">Verdicts appear as sessions are scored</div>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Identity</th>
                <th>Risk Score</th>
                <th>Anomaly Type</th>
                <th>Verdict</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => (
                <>
                  <tr
                    key={log.alert_id}
                    className={log.policy_action === 'KILL_SESSION' ? 'row-critical' : ''}
                    onClick={() => setExpanded(expanded === log.alert_id ? null : log.alert_id)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td className="text-muted text-xs mono tabular">
                      {formatDateTime(log.timestamp)}
                    </td>
                    <td>
                      <div className="font-medium">{log.identity_name}</div>
                      <div className="text-muted text-xs">
                        {log.peer_group?.replace(/_/g, ' ')}
                      </div>
                    </td>
                    <td>
                      <span style={{
                        fontWeight: 700,
                        fontVariantNumeric: 'tabular-nums',
                        fontSize: 14,
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
                      <span className={`badge ${log.status === 'ACTIVE' ? 'badge-high' : 'badge-low'}`}>
                        {log.status}
                      </span>
                    </td>
                    <td>
                      <span className="text-muted text-xs">
                        {expanded === log.alert_id ? 'Hide' : 'Details'}
                      </span>
                    </td>
                  </tr>
                  {expanded === log.alert_id && (
                    <tr key={`${log.alert_id}-detail`}>
                      <td
                        colSpan={7}
                        style={{
                          padding: '12px 16px',
                          background: 'var(--surface-inset)',
                          borderBottom: '1px solid var(--border)',
                        }}
                      >
                        <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                          <strong style={{ color: 'var(--text-primary)' }}>Explanation: </strong>
                          {log.explanation_summary || 'No explanation available.'}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* OPA policy rules */}
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Active Policy Rules</span>
          <span className="badge badge-navy">OPA v1 · panoptes.rego</span>
        </div>
        <div className="panel-body">
          <div className="code-block">{`# PANOPTES Access Control Policy (Rego)

# Rule 1 — Immediate Session Termination
KILL_SESSION  if risk_score >= 80

# Rule 2 — Step-Up Authentication (employees)
STEPUP_MFA    if risk_score >= 50 and identity_type == "employee"

# Rule 3 — Step-Up Authentication (contractors — tighter threshold)
STEPUP_MFA    if risk_score >= 40 and identity_type == "contractor"

# Rule 4 — After-Hours Critical System Access
KILL_SESSION  if risk_score >= 60 and is_after_hours and asset_criticality >= 0.80

# Rule 5 — Lateral Movement Pattern
KILL_SESSION  if risk_score >= 70 and "ESCALATE" in actions and "LATERAL" in actions

# Default
LOG_ONLY      if not matched by above rules`}
          </div>
        </div>
      </div>
    </>
  )
}

function StatCard({ label, value, variant }) {
  return (
    <div className={`stat-card ${variant || ''}`}>
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${variant || ''}`}>{value ?? '—'}</div>
    </div>
  )
}
