import { scoreColor } from '../api'

export function RiskBadge({ label }) {
  return <span className={`risk-badge ${label || 'MINIMAL'}`}>{label || 'MINIMAL'}</span>
}

export function VerdictBadge({ action }) {
  const labels = {
    KILL_SESSION: '⛔ Kill Session',
    STEPUP_MFA: '🔐 Step-Up MFA',
    LOG_ONLY: '📋 Log Only',
  }
  return (
    <span className={`verdict-badge ${action || 'LOG_ONLY'}`}>
      {labels[action] || action || 'LOG_ONLY'}
    </span>
  )
}

export function ScoreBar({ score }) {
  const color = scoreColor(score)
  return (
    <div className="score-bar-wrapper">
      <div className="score-bar-track">
        <div
          className="score-bar-fill"
          style={{ width: `${Math.min(score, 100)}%`, background: color }}
        />
      </div>
      <span className="score-num" style={{ color }}>{score?.toFixed(1) ?? '—'}</span>
    </div>
  )
}
