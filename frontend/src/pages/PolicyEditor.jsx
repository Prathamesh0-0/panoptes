import { useState, useEffect } from 'react'
import { api } from '../api'

export default function PolicyEditor() {
  const [code, setCode] = useState('')
  const [originalCode, setOriginalCode] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState(null)

  useEffect(() => {
    async function load() {
      try {
        const res = await api.policyGet()
        setCode(res.content)
        setOriginalCode(res.content)
      } catch (e) {
        console.error(e)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  const deploy = async () => {
    setSaving(true)
    setMessage(null)
    try {
      const res = await api.policyUpdate(code)
      setOriginalCode(code)
      setMessage({ type: 'success', text: res.message })
      setTimeout(() => setMessage(null), 4000)
    } catch (e) {
      setMessage({ type: 'error', text: e.message })
    } finally {
      setSaving(false)
    }
  }

  const hasChanges = code !== originalCode

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', paddingBottom: 40, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 600, color: '#F9FAFB' }}>Dynamic Policy Editor</h1>
          <p style={{ color: '#9CA3AF' }}>Edit OPA Rego rules and hot-reload the policy engine in real-time.</p>
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          {message && (
            <span style={{ 
              color: message.type === 'success' ? '#10B981' : '#EF4444', 
              fontSize: 14, fontWeight: 500 
            }}>
              {message.text}
            </span>
          )}
          <button className="btn btn-secondary" onClick={() => setCode(originalCode)} disabled={!hasChanges || saving}>
            Discard Changes
          </button>
          <button className="btn btn-primary" onClick={deploy} disabled={!hasChanges || saving}>
            {saving ? 'Deploying...' : 'Deploy Policy to OPA'}
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading-state"><div className="spinner" />Loading policy...</div>
      ) : (
        <div className="panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 600 }}>
          <div className="panel-header" style={{ borderBottom: '1px solid var(--border)', background: '#111827' }}>
            <span style={{ fontFamily: 'monospace', color: '#9CA3AF', fontSize: 13 }}>opa/panoptes.rego</span>
            <div style={{ display: 'flex', gap: 8 }}>
              <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#EF4444' }}></span>
              <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#F59E0B' }}></span>
              <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#10B981' }}></span>
            </div>
          </div>
          <textarea
            value={code}
            onChange={e => setCode(e.target.value)}
            spellCheck="false"
            style={{
              flex: 1,
              width: '100%',
              background: '#030712',
              color: '#E5E7EB',
              fontFamily: '"Fira Code", "JetBrains Mono", monospace',
              fontSize: 14,
              lineHeight: 1.6,
              padding: '24px',
              border: 'none',
              outline: 'none',
              resize: 'none'
            }}
          />
        </div>
      )}
    </div>
  )
}
