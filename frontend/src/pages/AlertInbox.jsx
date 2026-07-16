import { useState, useEffect } from 'react'
import { api, scoreColor, formatDateTime } from '../api'

export default function AlertInbox() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)

  const loadAlerts = async () => {
    try {
      const res = await api.alerts({ status: 'ACTIVE', per_page: 50 })
      setAlerts(res.alerts || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAlerts()
    const t = setInterval(loadAlerts, 10000)
    return () => clearInterval(t)
  }, [])

  const resolveAlert = async (id) => {
    try {
      await api.resolveAlert(id)
      setAlerts(alerts.filter(a => a.alert_id !== id))
    } catch (e) {
      console.error(e)
    }
  }

  return (
    <div style={{ maxWidth: 1000, margin: '0 auto', paddingBottom: 40 }}>
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 600, color: 'var(--text-primary)' }}>SOC Incident Inbox</h1>
        <p style={{ color: 'var(--text-secondary)' }}>Triage and investigate active behavioral anomalies flagged by AI.</p>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Active Incidents ({alerts.length})</span>
          <button className="btn btn-secondary btn-sm" onClick={loadAlerts}>Refresh</button>
        </div>

        {loading ? (
          <div className="loading-state"><div className="spinner" />Loading incidents...</div>
        ) : alerts.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-title">Inbox Zero</div>
            <div className="empty-state-sub">No active incidents require investigation.</div>
          </div>
        ) : (
          <div style={{ padding: '0 16px' }}>
            {alerts.map(a => (
              <div key={a.alert_id} style={{ 
                padding: '16px 0', 
                borderBottom: '1px solid var(--border)',
                display: 'flex', gap: 20, alignItems: 'center'
              }}>
                <div style={{
                  width: 48, height: 48, borderRadius: '50%',
                  background: 'rgba(239, 68, 68, 0.1)',
                  color: '#EF4444',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0
                }}>
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/>
                    <line x1="12" y1="17" x2="12.01" y2="17"/>
                  </svg>
                </div>
                
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: 16, fontWeight: 500, color: 'var(--text-primary)' }}>{a.identity_name}</span>
                    <span className="tag" style={{ background: '#374151' }}>{a.peer_group}</span>
                    <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{formatDateTime(a.created_at)}</span>
                  </div>
                  <div style={{ color: 'var(--text-secondary)', fontSize: 14, marginBottom: 8, lineHeight: 1.5 }}>
                    {a.explanation_summary}
                  </div>
                  <div style={{ display: 'flex', gap: 16, fontSize: 13, color: 'var(--text-muted)' }}>
                    <span>Action Taken: <span style={{ color: '#EF4444' }}>{a.policy_action}</span></span>
                    <span>Risk Score: <span style={{ color: scoreColor(a.risk_score) }}>{a.risk_score}</span></span>
                    <span>Type: {a.anomaly_type.replace(/_/g, ' ')}</span>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <button className="btn btn-primary" onClick={() => resolveAlert(a.alert_id)} style={{ width: 140 }}>
                    Resolve Incident
                  </button>
                  <a href={`/sessions/${a.session_id}`} target="_blank" rel="noreferrer" className="btn btn-secondary" style={{ width: 140, textAlign: 'center' }}>
                    View Session Details
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
