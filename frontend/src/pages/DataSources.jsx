import { useState } from 'react'

const BASE = 'http://localhost:8000'

const SOURCES = [
  {
    id: 'windows',
    title: 'Windows Event Log',
    subtitle: 'via winlogbeat / WEF Agent',
    endpoint: 'POST /api/ingest/windows-event',
    desc: 'Deployed on each Windows domain controller or PAM server. Winlogbeat forwards Security Event Log entries (4624, 4672, 4688 etc.) in real time.',
    integration: 'Deploy winlogbeat.yml on each DC → configure output.http → point to PANOPTES endpoint.',
    events: ['4624 — Successful Logon', '4672 — Admin Privilege Assigned', '4688 — Process Created', '4698 — Scheduled Task Created', '4660 — Object Deleted'],
    example: {
      agent_id: 'dc-01.bank.local',
      hostname: 'CORE_BANKING_DB',
      events: [
        { EventID: 4624, TimeCreated: '2024-01-15T02:34:00', Computer: 'CORE-DB-01', SubjectUserName: 'Rajan.Shah', IpAddress: '10.10.1.88' },
        { EventID: 4672, TimeCreated: '2024-01-15T02:34:05', Computer: 'CORE-DB-01', SubjectUserName: 'Rajan.Shah', IpAddress: '10.10.1.88' },
        { EventID: 4660, TimeCreated: '2024-01-15T02:35:12', Computer: 'CORE-DB-01', SubjectUserName: 'Rajan.Shah', ObjectName: 'audit_backup_jan.db' },
      ],
    },
  },
  {
    id: 'cyberark',
    title: 'CyberArk PAM',
    subtitle: 'via PVWA Webhook / CPM',
    endpoint: 'POST /api/ingest/cyberark',
    desc: 'CyberArk Central Policy Manager sends session records to PANOPTES when privileged sessions end. Automatically extracts bytes transferred, command count, and protocol.',
    integration: 'CyberArk PVWA → Administration → System Configuration → Webhooks → Add webhook → POST to this endpoint.',
    events: ['Session start / end events', 'Bytes transferred', 'Commands executed', 'Protocol: SSH / RDP / SQL', 'Target address'],
    example: {
      SessionId: 'cyberark-sess-00421',
      User: 'db.admin.rajan',
      AccountName: 'oracle_dba',
      Address: 'CORE-BANKING-DB-01',
      Protocol: 'SQL',
      StartTime: '2024-01-15T02:34:00',
      EndTime: '2024-01-15T03:18:00',
      Duration: 2640,
      CommandsCount: 847,
      BytesTransferred: 623000000,
    },
  },
  {
    id: 'siem',
    title: 'SIEM / CEF Format',
    subtitle: 'Splunk · IBM QRadar · ArcSight',
    endpoint: 'POST /api/ingest/cef',
    desc: 'ArcSight Common Event Format (CEF) used by Splunk, QRadar, and ArcSight. Configure your SIEM to forward enriched events via webhook.',
    integration: 'Splunk → Alert Actions → Webhook → POST to /api/ingest/cef with CEF body. QRadar → Custom Action → REST Call.',
    events: ['All Windows Security events', 'Network access events', 'Database audit logs', 'Application access logs'],
    example: {
      cef_version: 'CEF:0',
      device_vendor: 'Microsoft',
      device_product: 'Active Directory',
      signature_id: '4672',
      name: 'Special privileges assigned to new logon',
      severity: 8,
      extensions: { suser: 'Rajan.Shah', dhost: 'CORE-DB-01', src: '10.10.1.88', rt: '2024-01-15T02:34:05' },
    },
  },
  {
    id: 'generic',
    title: 'Generic API Event',
    subtitle: 'Custom agent or middleware',
    endpoint: 'POST /api/ingest/event',
    desc: 'The simplest integration. Any internal script, middleware, or custom agent can POST a single access event in this minimal JSON format. No special tooling required.',
    integration: 'Write a cron job or hook into your existing access management system to POST events here.',
    events: ['Single-event granularity', 'Simple JSON schema', 'Any action type', 'Optional data volume'],
    example: {
      user_id: 'emp_00142',
      user_name: 'Rajan Shah',
      user_type: 'employee',
      department: 'IT Operations',
      target_system: 'CORE_BANKING_DB',
      source_ip: '10.10.1.88',
      action: 'EXPORT',
      timestamp: '2024-01-15T02:35:00',
      data_volume_bytes: 623000000,
      privilege_level: 'HIGH',
    },
  },
  {
    id: 'csv',
    title: 'CSV Batch Upload',
    subtitle: 'Historical log replay',
    endpoint: 'POST /api/ingest/csv',
    desc: 'Export historical access logs from any system as CSV and upload for offline analysis. Useful for baselining, forensic investigation, or model training.',
    integration: 'Export from SIEM / IAM / DB as CSV → Upload via this UI or curl.',
    events: ['Bulk session replay', 'Forensic investigation', 'Model training data', 'Historical audit'],
    example: `user_id,user_name,user_type,target_system,source_ip,actions,login_hour,data_volume_mb,privilege_level
emp_001,Rajan Shah,employee,CORE_BANKING_DB,10.10.1.88,LOGIN|QUERY|EXPORT|LOGOUT,2,600.0,HIGH
emp_002,Priya Iyer,employee,AUDIT_DB,10.10.1.45,LOGIN|QUERY|LOGOUT,9,12.5,MEDIUM
ctr_003,Ajay Vendor,contractor,HR_DB,10.10.2.12,LOGIN|MODIFY|LOGOUT,11,8.0,LOW`,
  },
]

export default function DataSources() {
  const [activeSource, setActiveSource] = useState(null)
  const [testResult, setTestResult] = useState(null)
  const [testLoading, setTestLoading] = useState(false)

  async function sendTestEvent(source) {
    setTestLoading(true)
    setTestResult(null)
    try {
      const endpoint = source.endpoint.split(' ')[1]
      const body = source.id === 'csv'
        ? null
        : JSON.stringify(source.example)

      const res = await fetch(`${BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      })
      const data = await res.json()
      setTestResult({ ok: res.ok, data })
    } catch (e) {
      setTestResult({ ok: false, data: { error: e.message } })
    } finally {
      setTestLoading(false)
    }
  }

  return (
    <>
      {/* Architecture overview */}
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Real-World Integration Architecture</span>
          <span className="badge badge-blue">Production Ready</span>
        </div>
        <div className="panel-body">
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr auto 1fr auto 1fr',
            gap: 12,
            alignItems: 'center',
            padding: '8px 0',
          }}>
            <ArchBox
              title="Enterprise Sources"
              items={['Active Directory / LDAP', 'CyberArk / BeyondTrust', 'Splunk / IBM QRadar', 'Windows Event Log', 'Custom Agents']}
              color="var(--navy)"
            />
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 20, fontWeight: 300 }}>
              →
            </div>
            <ArchBox
              title="PANOPTES Ingest Layer"
              items={['Format normalisation', 'Session aggregation', 'Identity resolution', 'Peer group mapping']}
              color="var(--blue-text)"
            />
            <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 20, fontWeight: 300 }}>
              →
            </div>
            <ArchBox
              title="Risk Pipeline"
              items={['KMeans behavioural model', 'Markov sequence model', 'OPA Rego policy', 'PQC audit signing']}
              color="#065F46"
            />
          </div>
          <div className="notice info" style={{ marginTop: 12 }}>
            All 5 ingestion formats are normalised to the same internal schema before entering the risk pipeline.
            The ML models, OPA policy engine, and PQC audit layer behave identically regardless of source.
            In demo mode, the synthetic generator replaces enterprise sources.
          </div>
        </div>
      </div>

      {/* Source cards grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 16 }}>
        {SOURCES.map(src => (
          <div
            key={src.id}
            className="source-card"
            style={{ cursor: 'pointer', borderColor: activeSource?.id === src.id ? 'var(--border-focus)' : undefined }}
            onClick={() => setActiveSource(activeSource?.id === src.id ? null : src)}
          >
            <div className="source-card-header">
              <div className="source-icon">
                <SourceIcon id={src.id} />
              </div>
              <div>
                <div className="source-card-title">{src.title}</div>
                <div className="text-muted text-xs">{src.subtitle}</div>
              </div>
            </div>
            <div className="source-card-desc">{src.desc}</div>
            <div className="source-endpoint">{src.endpoint}</div>

            {activeSource?.id === src.id && (
              <div style={{ marginTop: 14 }} onClick={e => e.stopPropagation()}>
                <div className="divider" style={{ margin: '0 0 12px' }} />

                {/* Integration guide */}
                <div style={{ marginBottom: 10 }}>
                  <div className="form-label" style={{ marginBottom: 4 }}>Integration Guide</div>
                  <div className="notice">{src.integration}</div>
                </div>

                {/* Events handled */}
                <div style={{ marginBottom: 10 }}>
                  <div className="form-label" style={{ marginBottom: 4 }}>Events Handled</div>
                  <ul style={{ paddingLeft: 16, margin: 0 }}>
                    {src.events.map((e, i) => (
                      <li key={i} style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 2 }}>{e}</li>
                    ))}
                  </ul>
                </div>

                {/* Example payload */}
                <div style={{ marginBottom: 12 }}>
                  <div className="form-label" style={{ marginBottom: 4 }}>Example Payload</div>
                  <div className="code-block" style={{ fontSize: 11, lineHeight: 1.65, maxHeight: 200, overflow: 'auto' }}>
                    {typeof src.example === 'string'
                      ? src.example
                      : JSON.stringify(src.example, null, 2)}
                  </div>
                </div>

                {/* Test button */}
                {src.id !== 'csv' && (
                  <div>
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={() => sendTestEvent(src)}
                      disabled={testLoading}
                    >
                      {testLoading ? 'Sending…' : 'Send Test Event to PANOPTES'}
                    </button>
                    {testResult && (
                      <div className={`notice ${testResult.ok ? 'success' : 'error'}`} style={{ marginTop: 8 }}>
                        {testResult.ok
                          ? `Accepted: ${testResult.data.accepted ?? 1} event(s) queued for risk scoring.`
                          : `Error: ${JSON.stringify(testResult.data)}`}
                      </div>
                    )}
                  </div>
                )}
                {src.id === 'csv' && (
                  <div className="notice info" style={{ fontSize: 12 }}>
                    Upload CSV via: <code style={{ fontFamily: 'var(--font-mono)' }}>
                      POST /api/ingest/csv
                    </code> with multipart/form-data file field named "file".
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* How demo mode differs */}
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Demo Mode vs. Production Mode</span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Component</th>
                <th>Demo Mode (current)</th>
                <th>Production Mode</th>
              </tr>
            </thead>
            <tbody>
              {[
                ['Data Source',       'Synthetic generator (data_generator.py)',          'Real enterprise connectors (above)'],
                ['Identities',        '50 synthetic bank employees across 5 peer groups', 'Pulled from Active Directory / HR system'],
                ['Sessions',          'Generated at 35% anomaly rate every 4 seconds',    'Real privileged access sessions from PAM/SIEM'],
                ['ML Baseline',       'Trained on 2730 synthetic historical sessions',     'Trained on 6+ months of real session history'],
                ['Risk Scoring',      'Same pipeline — no difference',                    'Same pipeline — no difference'],
                ['OPA Policy',        'Same real Rego rules — no difference',             'Same real Rego rules — customised per bank policy'],
                ['PQC Vault',         'Demo credentials stored in SQLite',                'Credentials from CyberArk / HSM — FIPS 140-2'],
                ['Audit Log',         'SQLite with Ed25519 signatures',                   'PostgreSQL + HSM-backed signing keys'],
              ].map(([comp, demo, prod]) => (
                <tr key={comp}>
                  <td className="font-medium">{comp}</td>
                  <td className="text-secondary text-sm">{demo}</td>
                  <td className="text-sm" style={{ color: 'var(--risk-low-text)' }}>{prod}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}

function ArchBox({ title, items, color }) {
  return (
    <div style={{
      border: '1px solid var(--border)',
      borderRadius: 8,
      padding: '12px 14px',
      background: 'var(--surface-card)',
    }}>
      <div style={{
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: '0.06em',
        textTransform: 'uppercase',
        color,
        marginBottom: 8,
        borderBottom: `2px solid ${color}`,
        paddingBottom: 6,
      }}>{title}</div>
      {items.map((item, i) => (
        <div key={i} style={{
          fontSize: 12,
          color: 'var(--text-secondary)',
          padding: '2px 0',
          borderBottom: i < items.length - 1 ? '1px solid var(--border)' : 'none',
          lineHeight: 1.5,
        }}>{item}</div>
      ))}
    </div>
  )
}

function SourceIcon({ id }) {
  const size = 16
  const stroke = 'var(--navy)'
  const common = { width: size, height: size, stroke, strokeWidth: 1.4, fill: 'none', strokeLinecap: 'round', strokeLinejoin: 'round' }
  if (id === 'windows') return (
    <svg viewBox="0 0 16 16" {...common}>
      <rect x="1" y="1" width="6.5" height="6.5" rx="1"/><rect x="8.5" y="1" width="6.5" height="6.5" rx="1"/>
      <rect x="1" y="8.5" width="6.5" height="6.5" rx="1"/><rect x="8.5" y="8.5" width="6.5" height="6.5" rx="1"/>
    </svg>
  )
  if (id === 'cyberark') return (
    <svg viewBox="0 0 16 16" {...common}>
      <path d="M8 1L14 4v4c0 3.5-2.5 5.5-6 7C2.5 13.5 2 11.5 2 8V4l6-3z"/>
      <path d="M5.5 8.5l2 2 3-3.5"/>
    </svg>
  )
  if (id === 'siem') return (
    <svg viewBox="0 0 16 16" {...common}>
      <rect x="2" y="2" width="12" height="12" rx="2"/>
      <path d="M5 8h6M5 5.5h3M5 10.5h4"/>
    </svg>
  )
  if (id === 'generic') return (
    <svg viewBox="0 0 16 16" {...common}>
      <circle cx="8" cy="8" r="6"/>
      <path d="M8 5v3l2 1"/>
    </svg>
  )
  if (id === 'csv') return (
    <svg viewBox="0 0 16 16" {...common}>
      <path d="M9 1H4a1 1 0 00-1 1v12a1 1 0 001 1h8a1 1 0 001-1V6L9 1z"/>
      <path d="M9 1v5h5M5 9h6M5 12h4"/>
    </svg>
  )
  return null
}
