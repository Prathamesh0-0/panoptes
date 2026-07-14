import { NavLink, useLocation } from 'react-router-dom'

const NAV_ITEMS = [
  { to: '/', label: 'Risk Dashboard', icon: IconDashboard, end: true },
  { to: '/policy-log', label: 'Policy Log', icon: IconPolicy },
  { to: '/pqc', label: 'PQC Status', icon: IconShield },
  { to: '/identities', label: 'Identities', icon: IconUsers },
]

export default function Sidebar({ stats, opaRunning }) {
  const criticalCount = stats?.critical || 0

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-brand-name">PANOPTES</div>
        <div className="sidebar-brand-sub">Insider Threat Detection</div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Monitoring</div>
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          >
            <Icon className="nav-icon" />
            {label}
            {label === 'Risk Dashboard' && criticalCount > 0 && (
              <span className="nav-badge">{criticalCount}</span>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="nav-section-label" style={{ padding: '0 0 6px' }}>System Status</div>
        <div className="sidebar-status-row">
          <span className="status-dot green" />
          <span>Stream Processor</span>
        </div>
        <div className="sidebar-status-row">
          <span className={`status-dot ${opaRunning ? 'green' : 'yellow'}`} />
          <span>OPA {opaRunning ? '(Rego)' : '(Inline)'}</span>
        </div>
        <div className="sidebar-status-row">
          <span className="status-dot green" />
          <span>PQC Vault Active</span>
        </div>
        <div className="sidebar-status-row" style={{ marginTop: 8 }}>
          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
            Bank of Maharashtra — PS1
          </span>
        </div>
      </div>
    </aside>
  )
}

/* ─── Inline SVG Icons ───────────────────────────────────────────────────── */
function IconDashboard({ className }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="currentColor">
      <path d="M2 2h5v5H2V2zm0 7h5v5H2V9zm7-7h5v5H9V2zm0 7h5v5H9V9z" />
    </svg>
  )
}
function IconPolicy({ className }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="currentColor">
      <path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8zm9 3H7V7h2v4zm0-5H7V4h2v2z" />
    </svg>
  )
}
function IconShield({ className }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="currentColor">
      <path d="M8 0a.5.5 0 0 1 .217.049l7 3A.5.5 0 0 1 15.5 3.5v5c0 2.9-1.663 5.097-3.653 6.527A13.5 13.5 0 0 1 8 16a13.5 13.5 0 0 1-3.847-1.527C2.163 13.097.5 10.9.5 8.5v-5a.5.5 0 0 1 .283-.451l7-3A.5.5 0 0 1 8 0zm0 1.065-6.5 2.785V8.5c0 2.296 1.337 4.2 3.097 5.465A12.5 12.5 0 0 0 8 14.93a12.5 12.5 0 0 0 2.403-1.465C12.163 12.7 13.5 10.796 13.5 8.5V3.85L8 1.065z" />
    </svg>
  )
}
function IconUsers({ className }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="currentColor">
      <path d="M7 14s-1 0-1-1 1-4 5-4 5 3 5 4-1 1-1 1H7zm4-6a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-5.784 6A2.238 2.238 0 0 1 5 13c0-1.355.68-2.75 1.936-3.72A6.325 6.325 0 0 0 5 9c-4 0-5 3-5 4s1 1 1 1h4.216zM4.5 8a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z" />
    </svg>
  )
}
