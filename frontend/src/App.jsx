import { useState, useEffect, useRef, useCallback } from 'react'
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import SessionDetail from './pages/SessionDetail'
import PolicyLog from './pages/PolicyLog'
import PQCStatus from './pages/PQCStatus'
import Identities from './pages/Identities'
import { api } from './api'

const PAGE_TITLES = {
  '/': 'Risk Dashboard',
  '/policy-log': 'Policy Verdict Log',
  '/pqc': 'PQC Status',
  '/identities': 'Identity Registry',
}

function TopBar({ title, subtitle }) {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
  return (
    <header className="topbar">
      <div className="topbar-left">
        <span className="topbar-title">{title}</span>
        {subtitle && <span className="topbar-subtitle">— {subtitle}</span>}
      </div>
      <div className="topbar-right">
        <span className="topbar-time">
          {time.toLocaleString('en-IN', { weekday: 'short', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </span>
        <span className="tag" style={{ color: 'var(--risk-low)', borderColor: 'var(--risk-low-border)', background: 'var(--risk-low-bg)', fontSize: 10, fontWeight: 700 }}>
          ● LIVE
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

  // Load stats
  useEffect(() => {
    const loadStats = () => api.sessionStats().then(setStats).catch(() => {})
    loadStats()
    const t = setInterval(loadStats, 10000)
    return () => clearInterval(t)
  }, [])

  // Health check
  useEffect(() => {
    const check = () => api.health().then(h => setOpaRunning(h.opa_running)).catch(() => {})
    check()
    const t = setInterval(check, 15000)
    return () => clearInterval(t)
  }, [])

  // WebSocket live feed
  const connectWs = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return
    const ws = new WebSocket(`ws://${window.location.hostname}:8000/ws/live`)
    wsRef.current = ws
    ws.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data)
        if (ev.type === 'session') {
          setLiveEvents(prev => [ev, ...prev].slice(0, 50))
        }
      } catch {}
    }
    ws.onclose = () => {
      reconnectRef.current = setTimeout(connectWs, 3000)
    }
    ws.onerror = () => ws.close()
  }, [])

  useEffect(() => {
    connectWs()
    return () => {
      wsRef.current?.close()
      clearTimeout(reconnectRef.current)
    }
  }, [connectWs])

  const pathKey = location.pathname.startsWith('/sessions/') ? '/' : location.pathname
  const title = PAGE_TITLES[pathKey] || 'PANOPTES'

  return (
    <div className="app-layout">
      <Sidebar stats={stats} opaRunning={opaRunning} />
      <TopBar title={title} subtitle={location.pathname.startsWith('/sessions/') ? 'Session Detail' : ''} />
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard liveEvents={liveEvents} />} />
          <Route path="/sessions/:id" element={<SessionDetail />} />
          <Route path="/policy-log" element={<PolicyLog />} />
          <Route path="/pqc" element={<PQCStatus />} />
          <Route path="/identities" element={<Identities />} />
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
