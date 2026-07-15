import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { api, scoreColor, formatDateTime } from '../api'
import { RiskBadge, VerdictBadge, ScoreBar } from '../components/RiskBadge'

const ACTION_RISK = {
  DELETE: 'risky', ESCALATE: 'risky', EXPORT: 'risky', LATERAL: 'risky',
  MODIFY: 'warning', BACKUP: 'warning',
}

export default function SessionDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [session, setSession] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.session(id)
      .then(s => { setSession(s); setLoading(false) })
      .catch(() => setLoading(false))
  }, [id])

  if (loading) return (
    <div className="loading-state" style={{ paddingTop: 80 }}>
      <div className="spinner" /> Loading session…
    </div>
  )
  if (!session) return (
    <div className="empty-state"><div className="empty-state-title">Session not found</div></div>
  )

  const explanation = session.explanation || {}
  const contributors = explanation.contributors || []
  const reasons = explanation.reasons || []
  const actions = typeof session.actions === 'string'
    ? JSON.parse(session.actions)
    : (session.actions || [])

  const riskColor = scoreColor(session.risk_score)
  const barData = contributors.map(c => ({
    name: c.name.split(' ')[0],
    score: c.score,
    color: scoreColor(c.score),
  }))

  return (
    <>
      {/* Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
        <button className="btn btn-secondary btn-sm" onClick={() => navigate(-1)}>
          Back
        </button>
        <span className="text-muted">/</span>
        <span className="text-muted">Sessions</span>
        <span className="text-muted">/</span>
        <span className="inline-code" style={{ fontSize: 11 }}>{id}</span>
      </div>

      {/* Top: Risk hero + session meta */}
      <div style={{ display: 'grid', gridTemplateColumns: '176px 1fr', gap: 16, alignItems: 'start' }}>
        {/* Score hero */}
        <div className="risk-hero">
          <div className="risk-hero-score" style={{ color: riskColor }}>
            {session.risk_score?.toFixed(0)}
          </div>
          <div className="risk-hero-label" style={{ color: riskColor }}>
            {session.risk_label}
          </div>
          <div className="risk-hero-sub">out of 100</div>
          <VerdictBadge action={session.policy_action} />
        </div>

        {/* Session metadata */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">{session.identity_name}</span>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <RiskBadge label={session.risk_label} />
              {session.anomaly_type && (
                <span className="inline-code" style={{ fontSize: 11 }}>
                  {session.anomaly_type.replace(/_/g, ' ')}
                </span>
              )}
            </div>
          </div>
          <div className="panel-body">
            <div className="detail-grid">
              <div>
                <DetailRow label="Identity ID"     value={session.identity_id} mono />
                <DetailRow label="Peer Group"      value={session.peer_group?.replace(/_/g, ' ')} />
                <DetailRow label="Identity Type"   value={session.identity_type} />
                <DetailRow label="Privilege Level" value={session.privilege_level} />
                <DetailRow label="Source IP"       value={session.source_ip} mono />
              </div>
              <div>
                <DetailRow label="Target System"  value={session.target_system} mono />
                <DetailRow label="Login Hour"     value={`${String(session.login_hour).padStart(2,'0')}:00`} />
                <DetailRow label="Duration"       value={`${session.duration_minutes?.toFixed(0)} min`} />
                <DetailRow label="Data Volume"    value={`${session.data_volume_mb?.toFixed(1)} MB`} />
                <DetailRow label="Session Start"  value={formatDateTime(session.start_time)} />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Body grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Left: action timeline + score breakdown */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Action sequence */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Action Sequence</span>
              <span className="text-muted text-xs">{actions.length} steps</span>
            </div>
            <div className="panel-body">
              <div className="timeline">
                {actions.map((action, i) => {
                  const risk = ACTION_RISK[action] || 'normal'
                  return (
                    <div key={i} className="timeline-step">
                      <div className="timeline-node">
                        <div className={`timeline-circle ${risk}`}>
                          {i + 1}
                        </div>
                        <div className={`timeline-label ${risk}`}>{action}</div>
                      </div>
                      {i < actions.length - 1 && (
                        <div className="timeline-connector" />
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          </div>

          {/* Score breakdown */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Score Breakdown</span>
              <span className="badge badge-navy">5-signal fusion</span>
            </div>
            <div style={{ padding: '12px 8px 4px' }}>
              <ResponsiveContainer width="100%" height={140}>
                <BarChart data={barData} barSize={36} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
                  <XAxis
                    dataKey="name"
                    tick={{ fill: '#9CA3AF', fontSize: 10, fontFamily: 'Inter' }}
                    axisLine={false} tickLine={false}
                  />
                  <YAxis
                    domain={[0, 100]}
                    tick={{ fill: '#9CA3AF', fontSize: 10, fontFamily: 'Inter' }}
                    axisLine={false} tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{ background: '#fff', border: '1px solid #DDE1E9', borderRadius: 6, fontSize: 12 }}
                    cursor={{ fill: '#F2F4F7' }}
                    formatter={v => [`${v.toFixed(1)}/100`, 'Score']}
                  />
                  <Bar dataKey="score" radius={[3, 3, 0, 0]}>
                    {barData.map((d, i) => <Cell key={i} fill={d.color} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div style={{ padding: '0 16px 14px' }}>
              {contributors.map((c, i) => (
                <div key={i} className="detail-row">
                  <span className="detail-key">
                    {c.name}
                    <span className="text-muted text-xs" style={{ marginLeft: 4 }}>({c.weight}%)</span>
                  </span>
                  <div style={{ minWidth: 140 }}>
                    <ScoreBar score={c.score} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: policy verdict + explainability */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Policy verdict */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Policy Decision</span>
              <span className="badge badge-navy">OPA · Rego</span>
            </div>
            <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <VerdictBadge action={session.policy_action} />
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                {session.policy_reason}
              </p>
              <div>
                <DetailRow label="Severity"    value={<RiskBadge label={session.policy_severity} />} />
                <DetailRow label="Anomaly"     value={
                  <span className="inline-code" style={{ fontSize: 11 }}>
                    {session.anomaly_type || 'BEHAVIORAL_ANOMALY'}
                  </span>
                } />
                <DetailRow label="Asset Crit." value={`${((session.asset_criticality || 0) * 100).toFixed(0)}%`} />
              </div>
            </div>
          </div>

          {/* Explainability */}
          <div className="panel" style={{ flex: 1 }}>
            <div className="panel-header">
              <span className="panel-title">Risk Explanation</span>
              <span className="badge badge-navy">Deterministic · No external API</span>
            </div>
            <div className="panel-body">
              <div className="explain-panel">
                <div className="explain-section-label">Analysis Summary</div>
                <div className="explain-summary">{explanation.summary || '—'}</div>

                {reasons.length > 0 && (
                  <>
                    <div className="explain-section-label">Detection Reasons</div>
                    <div className="explain-reasons">
                      {reasons.map((r, i) => {
                        const isRisky = r.toUpperCase().includes('TAMPER') ||
                          r.toUpperCase().includes('SCOPE') ||
                          r.toUpperCase().includes('ESCALATE') ||
                          r.toUpperCase().includes('DELETE')
                        return (
                          <div key={i} className={`explain-reason ${isRisky ? 'risky' : ''}`}>
                            <div className="explain-reason-num">{i + 1}</div>
                            <span>{r}</span>
                          </div>
                        )
                      })}
                    </div>
                  </>
                )}

                {explanation.recommendation && (
                  <>
                    <div className="explain-section-label">Recommended Action</div>
                    <div className="explain-recommendation">{explanation.recommendation}</div>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

function DetailRow({ label, value, mono }) {
  return (
    <div className="detail-row">
      <span className="detail-key">{label}</span>
      {typeof value === 'string' || typeof value === 'number' ? (
        <span className={`detail-val ${mono ? 'mono text-sm' : ''}`}>{value || '—'}</span>
      ) : (
        <div className="detail-val">{value || '—'}</div>
      )}
    </div>
  )
}
