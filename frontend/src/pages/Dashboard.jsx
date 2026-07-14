import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts'
import { api, scoreColor, formatDateTime, formatTime } from '../api'
import { RiskBadge, VerdictBadge, ScoreBar } from '../components/RiskBadge'

const REFRESH_INTERVAL = 6000  // ms

export default function Dashboard({ liveEvents }) {
  const [stats, setStats] = useState(null)
  const [sessions, setSessions] = useState([])
  const [filter, setFilter] = useState('ALL')
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const load = useCallback(async () => {
    try {
      const [s, sess] = await Promise.all([
        api.sessionStats(),
        api.sessions({ per_page: 60, risk_label: filter !== 'ALL' ? filter : undefined }),
      ])
      setStats(s)
      setSessions(sess.sessions || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [filter])

  useEffect(() => {
    load()
    const interval = setInterval(load, REFRESH_INTERVAL)
    return () => clearInterval(interval)
  }, [load])

  // Live events → reload on new anomaly
  useEffect(() => {
    if (liveEvents.length > 0) {
      const last = liveEvents[0]
      if (last.is_anomalous) load()
    }
  }, [liveEvents, load])

  const FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

  const trendData = [
    { name: 'Critical', value: stats?.critical || 0, color: 'var(--risk-critical)' },
    { name: 'High', value: stats?.high || 0, color: 'var(--risk-high)' },
    { name: 'Medium', value: stats?.medium || 0, color: 'var(--risk-medium)' },
    { name: 'Blocked', value: stats?.blocked || 0, color: 'var(--risk-critical)' },
    { name: 'MFA', value: stats?.mfa_challenges || 0, color: 'var(--risk-high)' },
  ]

  return (
    <>
      {/* Stats */}
      <div className="stats-grid">
        <StatCard label="Total Sessions" value={stats?.total_sessions} />
        <StatCard label="Critical Alerts" value={stats?.critical} variant="critical" />
        <StatCard label="High Risk" value={stats?.high} variant="high" />
        <StatCard label="Sessions Blocked" value={stats?.blocked} variant="critical" />
        <StatCard label="MFA Challenges" value={stats?.mfa_challenges} variant="high" />
        <StatCard label="Anomalies Detected" value={stats?.anomalous_detected} variant="medium" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 20 }}>
        {/* Main session table */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Session Risk Queue</span>
            <div className="panel-actions">
              <div className="filters-bar">
                {FILTERS.map(f => (
                  <button
                    key={f}
                    className={`filter-btn ${filter === f ? 'active' : ''}`}
                    onClick={() => setFilter(f)}
                  >
                    {f}
                  </button>
                ))}
              </div>
              <button className="btn btn-secondary btn-sm" onClick={load}>↻ Refresh</button>
            </div>
          </div>

          {loading ? (
            <div className="loading-spinner"><div className="spinner" />Loading sessions…</div>
          ) : sessions.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-title">No sessions found</div>
              <div className="empty-state-sub">Sessions will appear as they stream in</div>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Identity</th>
                    <th>Peer Group</th>
                    <th>Target System</th>
                    <th>Risk Score</th>
                    <th>Risk Level</th>
                    <th>Policy Action</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map(s => (
                    <tr
                      key={s.session_id}
                      onClick={() => navigate(`/sessions/${s.session_id}`)}
                      className={s.risk_label === 'CRITICAL' ? 'flagged-row' : ''}
                    >
                      <td>
                        <div style={{ fontWeight: 500 }}>{s.identity_name}</div>
                        <div className="text-muted text-xs">{s.identity_id}</div>
                      </td>
                      <td>
                        <span className="tag">{s.peer_group?.replace('_', ' ')}</span>
                      </td>
                      <td>
                        <span className="inline-code">{s.target_system}</span>
                      </td>
                      <td style={{ minWidth: 140 }}>
                        <ScoreBar score={s.risk_score} />
                      </td>
                      <td><RiskBadge label={s.risk_label} /></td>
                      <td><VerdictBadge action={s.policy_action} /></td>
                      <td className="text-muted text-sm">{formatTime(s.start_time)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Threat distribution chart */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Threat Distribution</span>
            </div>
            <div style={{ padding: '16px 8px 8px' }}>
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={trendData} barSize={32}>
                  <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: 'var(--bg-surface-2)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }}
                    cursor={{ fill: 'var(--bg-surface-3)' }}
                  />
                  <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                    {trendData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Live feed */}
          <div className="panel" style={{ flex: 1 }}>
            <div className="panel-header">
              <span className="panel-title">Live Event Feed</span>
              <span style={{ fontSize: 11, color: 'var(--risk-low)', fontWeight: 600 }}>● LIVE</span>
            </div>
            <div className="live-feed">
              {liveEvents.length === 0 && (
                <div style={{ padding: 16, color: 'var(--text-muted)', fontSize: 12, textAlign: 'center' }}>
                  Waiting for events…
                </div>
              )}
              {liveEvents.slice(0, 25).map((ev, i) => {
                const color = scoreColor(ev.risk_score || 0)
                return (
                  <div key={i} className="live-event" onClick={() => ev.session_id && navigate(`/sessions/${ev.session_id}`)}>
                    <div className="live-event-dot" style={{ background: color }} />
                    <div className="live-event-main">
                      <div className="live-event-name">{ev.identity_name || 'Unknown'}</div>
                      <div className="live-event-meta">{ev.target_system} · {ev.peer_group?.replace('_', ' ')}</div>
                    </div>
                    <div className="live-event-score" style={{ color }}>{ev.risk_score?.toFixed(0) ?? '—'}</div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

function StatCard({ label, value, variant }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${variant || ''}`}>{value ?? '—'}</div>
    </div>
  )
}
