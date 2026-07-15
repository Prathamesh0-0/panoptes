import { useState, useEffect, useRef, useCallback } from 'react'
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import SessionDetail from './pages/SessionDetail'
import PolicyLog from './pages/PolicyLog'
import PQCStatus from './pages/PQCStatus'
import Identities from './pages/Identities'
import DataSources from './pages/DataSources'
import { api } from './api'

const PAGE_TITLES = {
  '/':             { title: 'Risk Dashboard',      sub: 'Live session monitoring and threat detection' },
  '/policy-log':   { title: 'Policy Decisions',    sub: 'OPA Rego access control verdicts' },
  '/pqc':          { title: 'PQC Vault',            sub: 'Post-quantum cryptography and audit signing' },
  '/identities':   { title: 'Identity Registry',   sub: '50 identities across 5 peer groups' },
  '/ingest':       { title: 'Data Sources',         sub: 'Real-world log ingestion and integration' },
}

function TopBar({ location, stats }) {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])

  const pathKey = location.pathname.startsWith('/sessions/') ? '/' : location.pathname
  const page = PAGE_TITLES[pathKey] || { title: 'PANOPTES', sub: '' }
  const isDetail = location.pathname.startsWith('/sessions/')

  return (
    <header className="topbar">
      <div className="topbar-left">
        <span className="topbar-title">
          {isDetail ? 'Session Detail' : page.title}
        </span>
        {!isDetail && page.sub && (
          <span className="topbar-subtitle">{page.sub}</span>
        )}
      </div>
      <div className="topbar-right">
        {stats?.critical > 0 && (
          <span className="badge badge-critical" style={{ fontSize: 11 }}>
            {stats.critical} Critical Active
          </span>
        )}
        <span className="topbar-time">
          {time.toLocaleString('en-IN', {
            weekday: 'short', day: '2-digit', month: 'short',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            hour12: false,
          })}
        </span>
        <span className="live-pill">
          <span className="live-dot" />
          LIVE
        </span>
      </div>
    </header>
  )
}

function AppInner() {
  const location = useLocation()
  const [stats, setStats] = useState(null)
  const [opaRunning, setOpaRunning] = useState(false)
  const [liveEvents, setLiveEvents] = useState([])
  const wsRef = useRef(null)
  const reconnectRef = useRef(null)

  useEffect(() => {
    const load = () => api.sessionStats().then(setStats).catch(() => {})
    load()
    const t = setInterval(load, 10000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    const check = () => api.health().then(h => setOpaRunning(h.opa_running)).catch(() => {})
    check()
    const t = setInterval(check, 15000)
    return () => clearInterval(t)
  }, [])

  const connectWs = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return
    const ws = new WebSocket(`ws://${window.location.hostname}:8000/ws/live`)
    wsRef.current = ws
    ws.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data)
        if (ev.type === 'session') {
          setLiveEvents(prev => [ev, ...prev].slice(0, 60))
          if (ev.is_anomalous) {
            api.sessionStats().then(setStats).catch(() => {})
          }
        }
      } catch {}
    }
    ws.onclose = () => { reconnectRef.current = setTimeout(connectWs, 3000) }
    ws.onerror = () => ws.close()
  }, [])

  useEffect(() => {
    connectWs()
    return () => { wsRef.current?.close(); clearTimeout(reconnectRef.current) }
  }, [connectWs])

  return (
    <div className="app-layout">
      <Sidebar stats={stats} opaRunning={opaRunning} />
      <TopBar location={location} stats={stats} />
      <main className="main-content">
        <Routes>
          <Route path="/"               element={<Dashboard liveEvents={liveEvents} />} />
          <Route path="/sessions/:id"   element={<SessionDetail />} />
          <Route path="/policy-log"     element={<PolicyLog />} />
          <Route path="/pqc"            element={<PQCStatus />} />
          <Route path="/identities"     element={<Identities />} />
          <Route path="/ingest"         element={<DataSources />} />
        </Routes>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AppInner />
    </BrowserRouter>
  )
}
