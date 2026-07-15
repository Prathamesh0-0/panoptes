import { NavLink } from 'react-router-dom'

const NAV = [
  { to: '/', label: 'Risk Dashboard', icon: IconDashboard, end: true },
  { to: '/policy-log', label: 'Policy Decisions', icon: IconPolicy },
  { to: '/identities', label: 'Identity Registry', icon: IconUsers },
  { to: '/pqc', label: 'PQC Vault', icon: IconShield },
  { to: '/ingest', label: 'Data Sources', icon: IconIngest },
]

export default function Sidebar({ stats, opaRunning }) {
  const criticalCount = stats?.critical || 0

  return (
    <aside className="sidebar">
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="sidebar-brand-mark">
          <div className="sidebar-brand-icon">
            <IconPanoptes />
          </div>
          <span className="sidebar-brand-name">PANOPTES</span>
        </div>
        <div className="sidebar-brand-sub">Insider Threat Detection</div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <div className="nav-section-label">Monitoring</div>
        {NAV.map(({ to, label, icon: Icon, end }) => (
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

      {/* System Status */}
      <div className="sidebar-footer">
        <div className="nav-section-label" style={{ padding: '0 0 8px' }}>System Status</div>
        <StatusRow label="Stream Processor" ok={true} />
        <StatusRow label={`OPA ${opaRunning ? '(Real Rego)' : '(Inline Fallback)'}`} ok={opaRunning} warn={!opaRunning} />
        <StatusRow label="PQC Vault" ok={true} />
        <StatusRow label="ML Models" ok={true} />
        <div style={{ marginTop: 10, fontSize: 11, color: 'rgba(255,255,255,0.28)', lineHeight: 1.5 }}>
          Bank of Maharashtra<br />
          PS1 — Privileged Access Misuse
        </div>
      </div>
    </aside>
  )
}

function StatusRow({ label, ok, warn }) {
  const dotClass = warn ? 'yellow' : ok ? 'green' : 'red'
  return (
    <div className="sidebar-status-row">
      <span className={`status-dot ${dotClass}`} />
      <span>{label}</span>
    </div>
  )
}

/* ─── SVG Icons ─────────────────────────────────────────────────────────── */
function IconPanoptes() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="6" stroke="rgba(255,255,255,0.7)" strokeWidth="1.5" fill="none"/>
      <circle cx="8" cy="8" r="2.5" fill="rgba(255,255,255,0.8)"/>
      <line x1="8" y1="2" x2="8" y2="4" stroke="rgba(255,255,255,0.5)" strokeWidth="1.2" strokeLinecap="round"/>
      <line x1="8" y1="12" x2="8" y2="14" stroke="rgba(255,255,255,0.5)" strokeWidth="1.2" strokeLinecap="round"/>
      <line x1="2" y1="8" x2="4" y2="8" stroke="rgba(255,255,255,0.5)" strokeWidth="1.2" strokeLinecap="round"/>
      <line x1="12" y1="8" x2="14" y2="8" stroke="rgba(255,255,255,0.5)" strokeWidth="1.2" strokeLinecap="round"/>
    </svg>
  )
}
function IconDashboard({ className }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <rect x="1" y="1" width="6" height="6" rx="1"/>
      <rect x="9" y="1" width="6" height="6" rx="1"/>
      <rect x="1" y="9" width="6" height="6" rx="1"/>
      <rect x="9" y="9" width="6" height="6" rx="1"/>
    </svg>
  )
}
function IconPolicy({ className }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 1L14 4v5c0 3-2.5 5-6 6C2.5 14 1 12 1 9V4l7-3z"/>
      <path d="M5.5 8l1.8 1.8L10.5 6"/>
    </svg>
  )
}
function IconShield({ className }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="4" width="5" height="8" rx="1"/>
      <rect x="9" y="4" width="5" height="8" rx="1"/>
      <path d="M7 8h2"/>
      <path d="M2 8h13"/>
    </svg>
  )
}
function IconUsers({ className }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="6" cy="5" r="2.5"/>
      <path d="M1 14c0-2.5 2-4 5-4s5 1.5 5 4"/>
      <circle cx="12" cy="5" r="2"/>
      <path d="M12 9c1.5 0 3 1 3 3"/>
    </svg>
  )
}
function IconIngest({ className }) {
  return (
    <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 1v10M5 8l3 3 3-3"/>
      <path d="M2 12v2a1 1 0 001 1h10a1 1 0 001-1v-2"/>
    </svg>
  )
}
