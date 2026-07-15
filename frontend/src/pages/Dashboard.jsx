import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, LineChart, Line, CartesianGrid,
} from 'recharts'
import { api, scoreColor, formatDateTime, formatTime } from '../api'
import { RiskBadge, VerdictBadge, ScoreBar } from '../components/RiskBadge'

const REFRESH = 6000

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
    const t = setInterval(load, REFRESH)
    return () => clearInterval(t)
  }, [load])

  useEffect(() => {
    if (liveEvents[0]?.is_anomalous) load()
  }, [liveEvents, load])

  const FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

  const distData = [
    { name: 'Critical', value: stats?.critical || 0, color: '#C0392B' },
    { name: 'High',     value: stats?.high || 0,     color: '#B45309' },
    { name: 'Medium',   value: stats?.medium || 0,   color: '#0369A1' },
    { name: 'Blocked',  value: stats?.blocked || 0,  color: '#7C1C1C' },
    { name: 'MFA',      value: stats?.mfa_challenges || 0, color: '#78350F' },
  ]

  return (
    <>
      {/* Stats strip */}
      <div className="stats-grid">
        <StatCard label="Total Sessions"    value={stats?.total_sessions}    />
        <StatCard label="Critical Alerts"   value={stats?.critical}           variant="critical" />
        <StatCard label="High Risk"         value={stats?.high}               variant="high" />
        <StatCard label="Sessions Blocked"  value={stats?.blocked}            variant="critical"
                  sub="KILL_SESSION verdicts" />
        <StatCard label="MFA Challenges"    value={stats?.mfa_challenges}     variant="high"
                  sub="STEPUP_MFA verdicts" />
        <StatCard label="Anomalies Found"   value={stats?.anomalous_detected} variant="medium" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 304px', gap: 16 }}>
        {/* Session table */}
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
                  >{f}</button>
                ))}
              </div>
              <button className="btn btn-secondary btn-sm" onClick={load}>Refresh</button>
            </div>
          </div>

          {loading ? (
            <div className="loading-state"><div className="spinner" />Loading sessions…</div>
          ) : sessions.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-title">No sessions found</div>
              <div className="empty-state-sub">Sessions stream in every few seconds</div>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Identity</th>
                    <th>Peer Group</th>
                    <th>Target System</th>
                    <th style={{ minWidth: 160 }}>Risk Score</th>
                    <th>Level</th>
                    <th>Action</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map(s => (
                    <tr
                      key={s.session_id}
                      onClick={() => navigate(`/sessions/${s.session_id}`)}
                      className={s.risk_label === 'CRITICAL' ? 'row-critical' : ''}
                    >
                      <td>
                        <div className="font-medium">{s.identity_name}</div>
                        <div className="text-muted text-xs">{s.identity_type}</div>
                      </td>
                      <td>
                        <span className="tag">{s.peer_group?.replace(/_/g, ' ')}</span>
                      </td>
                      <td>
                        <span className="inline-code">{s.target_system}</span>
                      </td>
                      <td><ScoreBar score={s.risk_score} /></td>
                      <td><RiskBadge label={s.risk_label} /></td>
                      <td><VerdictBadge action={s.policy_action} /></td>
                      <td className="text-muted text-xs tabular">{formatTime(s.start_time)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Threat distribution */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Threat Distribution</span>
            </div>
            <div style={{ padding: '12px 8px 8px' }}>
              <ResponsiveContainer width="100%" height={148}>
                <BarChart data={distData} barSize={28} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                  <XAxis
                    dataKey="name"
                    tick={{ fill: '#9CA3AF', fontSize: 10, fontFamily: 'Inter' }}
                    axisLine={false} tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: '#9CA3AF', fontSize: 10, fontFamily: 'Inter' }}
                    axisLine={false} tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: '#FFFFFF',
                      border: '1px solid #DDE1E9',
                      borderRadius: 6,
                      fontSize: 12,
                      fontFamily: 'Inter',
                      boxShadow: '0 2px 8px rgba(0,0,0,0.08)',
                    }}
                    cursor={{ fill: '#F2F4F7' }}
                  />
                  <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                    {distData.map((d, i) => <Cell key={i} fill={d.color} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Live feed */}
          <div className="panel" style={{ flex: 1 }}>
            <div className="panel-header">
              <span className="panel-title">Live Event Feed</span>
              <span className="live-pill">
                <span className="live-dot" />
                LIVE
              </span>
            </div>
            <div className="live-feed">
              {liveEvents.length === 0 && (
                <div className="loading-state" style={{ padding: 24 }}>
                  <div className="spinner" />
                  Awaiting events…
                </div>
              )}
              {liveEvents.slice(0, 30).map((ev, i) => {
                const color = scoreColor(ev.risk_score || 0)
                const score = ev.risk_score ?? 0
                return (
                  <div
                    key={i}
                    className="live-event"
                    onClick={() => ev.session_id && navigate(`/sessions/${ev.session_id}`)}
                  >
                    <div
                      className="live-event-indicator"
                      style={{ background: color }}
                    />
                    <div className="live-event-main">
                      <div className="live-event-name">{ev.identity_name || 'Unknown'}</div>
                      <div className="live-event-meta">
                        {ev.target_system}
                        {ev.peer_group ? ` · ${ev.peer_group.replace(/_/g, ' ')}` : ''}
                      </div>
                    </div>
                    <div className="live-event-right">
                      <span className="live-event-score" style={{ color }}>
                        {score.toFixed(0)}
                      </span>
                      {ev.is_anomalous && (
                        <span className="badge badge-critical" style={{ fontSize: 9, padding: '1px 5px' }}>
                          ALERT
                        </span>
                      )}
                    </div>
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

function StatCard({ label, value, variant, sub }) {
  return (
    <div className={`stat-card ${variant || ''}`}>
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${variant || ''}`}>{value ?? '—'}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}
