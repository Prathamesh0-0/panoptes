import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts'
import { api, scoreColor, formatDateTime } from '../api'
import { RiskBadge, VerdictBadge, ScoreBar } from '../components/RiskBadge'

export default function SessionDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [session, setSession] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.session(id).then(s => { setSession(s); setLoading(false) }).catch(() => setLoading(false))
  }, [id])

  if (loading) return <div className="loading-spinner"><div className="spinner" />Loading session…</div>
  if (!session) return <div className="empty-state"><div className="empty-state-title">Session not found</div></div>

  const explanation = session.explanation || {}
  const contributors = explanation.contributors || []
  const reasons = explanation.reasons || []
  const actions = session.actions || []

  const barData = contributors.map(c => ({
    name: c.name.split(' ')[0],
    score: c.score,
    color: scoreColor(c.score),
  }))

  const riskColor = scoreColor(session.risk_score)

  return (
    <>
      {/* Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
        <button className="btn btn-secondary btn-sm" onClick={() => navigate(-1)}>← Back</button>
        <span className="text-muted">/</span>
        <span className="text-muted">Sessions</span>
        <span className="text-muted">/</span>
        <span className="inline-code">{id}</span>
      </div>

      {/* Header row */}
      <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: 20, alignItems: 'start' }}>
        {/* Risk hero */}
        <div className="risk-hero">
          <div className="risk-hero-score" style={{ color: riskColor }}>
            {session.risk_score?.toFixed(0)}
          </div>
          <div className="risk-hero-label" style={{ color: riskColor }}>
            {session.risk_label}
          </div>
          <div className="risk-hero-sub">Risk Score / 100</div>
          <div style={{ marginTop: 4 }}>
            <VerdictBadge action={session.policy_action} />
          </div>
        </div>

        {/* Session metadata */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">{session.identity_name}</span>
            <RiskBadge label={session.risk_label} />
          </div>
          <div className="panel-body">
            <div className="detail-grid">
              <div>
                <DetailRow label="Identity ID" value={session.identity_id} mono />
                <DetailRow label="Peer Group" value={session.peer_group?.replace(/_/g, ' ')} />
                <DetailRow label="Identity Type" value={session.identity_type} />
                <DetailRow label="Privilege Level" value={session.privilege_level} />
                <DetailRow label="Source IP" value={session.source_ip} mono />
              </div>
              <div>
                <DetailRow label="Target System" value={session.target_system} mono />
                <DetailRow label="Login Hour" value={`${session.login_hour}:00`} />
                <DetailRow label="Duration" value={`${session.duration_minutes?.toFixed(0)} min`} />
                <DetailRow label="Data Volume" value={`${session.data_volume_mb?.toFixed(1)} MB`} />
                <DetailRow label="Time" value={formatDateTime(session.start_time)} />
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="detail-grid">
        {/* Left: action timeline + score breakdown */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Action sequence */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Action Sequence</span>
              <span className="text-muted text-xs">{actions.length} actions</span>
            </div>
            <div className="panel-body">
              <div className="timeline">
                {actions.map((action, i) => {
                  const sensitivity = {
                    DELETE: 'risky', ESCALATE: 'risky', EXPORT: 'risky',
                    LATERAL: 'risky', MODIFY: 'warning', BACKUP: 'warning',
                  }[action] || 'normal'
                  return (
                    <div key={i} className="timeline-item">
                      <div className={`timeline-dot ${sensitivity}`} />
                      <div className="timeline-action">{action}</div>
                      <div className="timeline-time">Step {i + 1}</div>
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
            </div>
            <div style={{ padding: '16px 8px 8px' }}>
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={barData} barSize={40}>
                  <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: 'var(--bg-surface-2)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }}
                    cursor={{ fill: 'var(--bg-surface-3)' }}
                    formatter={(v) => [`${v.toFixed(1)}/100`, 'Score']}
                  />
                  <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                    {barData.map((d, i) => <Cell key={i} fill={d.color} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            {/* Sub-score rows */}
            <div style={{ padding: '0 16px 16px' }}>
              {contributors.map((c, i) => (
                <div key={i} className="detail-row">
                  <span className="detail-key">{c.name} <span className="text-xs text-muted">({c.weight}%)</span></span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <ScoreBar score={c.score} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: explainability + policy verdict */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Policy verdict */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Policy Decision (OPA)</span>
            </div>
            <div className="panel-body">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div>
                  <VerdictBadge action={session.policy_action} />
                </div>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {session.policy_reason}
                </p>
                <div className="detail-row" style={{ marginTop: 4 }}>
                  <span className="detail-key">Severity</span>
                  <RiskBadge label={session.policy_severity} />
                </div>
                <div className="detail-row">
                  <span className="detail-key">Anomaly Type</span>
                  <span className="detail-val inline-code" style={{ fontSize: 12 }}>
                    {session.anomaly_type || 'BEHAVIORAL_ANOMALY'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* AI Explainability */}
          <div className="panel" style={{ flex: 1 }}>
            <div className="panel-header">
              <span className="panel-title">Risk Explanation</span>
              <span className="tag">Template-based · No API</span>
            </div>
            <div className="panel-body">
              <div className="explain-panel">
                <div className="explain-title">Analysis Summary</div>
                <div className="explain-summary">{explanation.summary || '—'}</div>

                {reasons.length > 0 && (
                  <>
                    <div className="explain-title" style={{ marginTop: 4 }}>Detection Reasons</div>
                    <div className="explain-reasons">
                      {reasons.map((r, i) => (
                        <div key={i} className="explain-reason">
                          <div className="explain-reason-bullet">{i + 1}</div>
                          <span>{r}</span>
                        </div>
                      ))}
                    </div>
                  </>
                )}

                {explanation.recommendation && (
                  <>
                    <div className="explain-title" style={{ marginTop: 4 }}>Recommendation</div>
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
      <span className={`detail-val ${mono ? 'mono text-sm' : ''}`}>{value || '—'}</span>
    </div>
  )
}
