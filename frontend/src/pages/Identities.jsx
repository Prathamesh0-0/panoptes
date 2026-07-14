import { useState, useEffect } from 'react'
import { api, formatDateTime } from '../api'
import { RiskBadge } from '../components/RiskBadge'

export default function Identities() {
  const [identities, setIdentities] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('ALL')

  useEffect(() => {
    api.identities().then(d => { setIdentities(d.identities || []); setLoading(false) }).catch(() => setLoading(false))
  }, [])

  const groups = ['ALL', 'DB_ADMIN', 'NETWORK_ADMIN', 'BRANCH_STAFF', 'IT_CONTRACTOR', 'FINANCE_ANALYST']
  const filtered = filter === 'ALL' ? identities : identities.filter(i => i.peer_group === filter)

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Identity Registry</div>
          <div className="page-subtitle">50 monitored identities across 5 peer groups — behavioral baselines computed by KMeans clustering</div>
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card"><div className="stat-label">Total Identities</div><div className="stat-value blue">{identities.length}</div></div>
        <div className="stat-card"><div className="stat-label">Employees</div><div className="stat-value">{identities.filter(i => i.identity_type === 'employee').length}</div></div>
        <div className="stat-card"><div className="stat-label">Contractors</div><div className="stat-value high">{identities.filter(i => i.identity_type === 'contractor').length}</div></div>
        <div className="stat-card"><div className="stat-label">Peer Groups</div><div className="stat-value">5</div></div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Identity List</span>
          <div className="filters-bar">
            {groups.map(g => (
              <button key={g} className={`filter-btn ${filter === g ? 'active' : ''}`} onClick={() => setFilter(g)}>
                {g.replace(/_/g, ' ')}
              </button>
            ))}
          </div>
        </div>
        {loading ? (
          <div className="loading-spinner"><div className="spinner" />Loading identities…</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Role / Peer Group</th>
                <th>Type</th>
                <th>Department</th>
                <th>Cluster</th>
                <th>Tenure</th>
                <th>Normal Login Hour</th>
                <th>Allowed Systems</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(i => (
                <tr key={i.id}>
                  <td>
                    <div style={{ fontWeight: 500 }}>{i.name}</div>
                    <div className="text-muted text-xs mono">{i.id}</div>
                  </td>
                  <td><span className="tag">{i.peer_group?.replace(/_/g, ' ')}</span></td>
                  <td>
                    <span className={`tag ${i.identity_type === 'contractor' ? '' : ''}`}
                          style={i.identity_type === 'contractor' ? { color: 'var(--risk-high)', borderColor: 'var(--risk-high-border)' } : {}}>
                      {i.identity_type}
                    </span>
                  </td>
                  <td className="text-secondary">{i.department}</td>
                  <td className="text-muted mono text-sm">C{i.cluster_id}</td>
                  <td className="text-secondary">{i.tenure_years?.toFixed(1)}y</td>
                  <td className="text-secondary">{i.normal_login_hour_mean?.toFixed(0)}:00 ± {i.normal_login_hour_std?.toFixed(1)}h</td>
                  <td>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', maxWidth: 200 }}>
                      {(i.allowed_systems || []).slice(0, 2).map(s => (
                        <span key={s} className="inline-code" style={{ fontSize: 10 }}>{s}</span>
                      ))}
                      {(i.allowed_systems || []).length > 2 && (
                        <span className="text-muted text-xs">+{i.allowed_systems.length - 2}</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
