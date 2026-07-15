/* RiskBadge, VerdictBadge, ScoreBar — shared components */

export function RiskBadge({ label }) {
  const map = {
    CRITICAL: 'badge-critical',
    HIGH:     'badge-high',
    MEDIUM:   'badge-medium',
    LOW:      'badge-low',
    MINIMAL:  'badge-minimal',
  }
  const cls = map[label] || 'badge-default'
  return <span className={`badge ${cls}`}>{label || 'UNKNOWN'}</span>
}

export function VerdictBadge({ action }) {
  const map = {
    KILL_SESSION: ['badge-critical', 'Kill Session'],
    STEPUP_MFA:   ['badge-high',    'Step-Up MFA'],
    LOG_ONLY:     ['badge-minimal', 'Log Only'],
  }
  const [cls, label] = map[action] || ['badge-default', action || 'Unknown']
  return <span className={`badge ${cls}`}>{label}</span>
}

export function ScoreBar({ score }) {
  const s = score ?? 0
  let color = '#16A34A'      // low — muted green
  if (s >= 80) color = '#C0392B'  // critical — muted red
  else if (s >= 60) color = '#B45309'  // high — amber
  else if (s >= 40) color = '#0369A1'  // medium — blue

  return (
    <div className="score-bar-wrap">
      <div className="score-bar-track">
        <div
          className="score-bar-fill"
          style={{ width: `${s}%`, background: color }}
        />
      </div>
      <span className="score-bar-num" style={{ color }}>{s.toFixed(0)}</span>
    </div>
  )
}
