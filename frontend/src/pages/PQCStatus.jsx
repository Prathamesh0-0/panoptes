import { useState, useEffect } from 'react'
import { api } from '../api'

export default function PQCStatus() {
  const [status, setStatus] = useState(null)
  const [vaultItems, setVaultItems] = useState([])
  const [auditLogs, setAuditLogs] = useState([])

  // Encrypt demo
  const [encryptLabel, setEncryptLabel] = useState('db-root-password')
  const [encryptPlain, setEncryptPlain] = useState('BankOfMaharashtra@SecretKey#2024')
  const [encryptResult, setEncryptResult] = useState(null)
  const [encryptLoading, setEncryptLoading] = useState(false)

  // Decrypt demo
  const [selectedVaultId, setSelectedVaultId] = useState('')
  const [decryptResult, setDecryptResult] = useState(null)
  const [decryptLoading, setDecryptLoading] = useState(false)

  // Sign / Verify demo
  const [signMessage, setSignMessage] = useState('Critical audit event: DB admin accessed CORE_BANKING_DB at 02:34 AM')
  const [signResult, setSignResult] = useState(null)
  const [signLoading, setSignLoading] = useState(false)
  const [verifyResult, setVerifyResult] = useState(null)
  const [verifyLoading, setVerifyLoading] = useState(false)

  // Audit tamper demo
  const [selectedLogId, setSelectedLogId] = useState('')
  const [verifyLogResult, setVerifyLogResult] = useState(null)
  const [tamperResult, setTamperResult] = useState(null)

  useEffect(() => {
    api.pqcStatus().then(setStatus).catch(console.error)
    api.vaultList().then(d => { setVaultItems(d.entries || []); if (d.entries?.[0]) setSelectedVaultId(d.entries[0].vault_id) }).catch(console.error)
    api.auditLogs().then(d => { setAuditLogs(d.logs || []); if (d.logs?.[0]) setSelectedLogId(d.logs[0].log_id) }).catch(console.error)
  }, [])

  async function handleEncrypt() {
    setEncryptLoading(true)
    try {
      const result = await api.vaultEncrypt(encryptLabel, encryptPlain)
      setEncryptResult(result)
      // Refresh vault list
      const vd = await api.vaultList()
      setVaultItems(vd.entries || [])
      setSelectedVaultId(result.vault_id)
    } finally { setEncryptLoading(false) }
  }

  async function handleDecrypt() {
    if (!selectedVaultId) return
    setDecryptLoading(true)
    try { setDecryptResult(await api.vaultDecrypt(selectedVaultId)) }
    finally { setDecryptLoading(false) }
  }

  async function handleSign() {
    setSignLoading(true)
    try { setSignResult(await api.pqcSign(signMessage)); setVerifyResult(null) }
    finally { setSignLoading(false) }
  }

  async function handleVerify() {
    if (!signResult?.signed_entry) return
    setVerifyLoading(true)
    try { setVerifyResult(await api.pqcVerify(signResult.signed_entry)) }
    finally { setVerifyLoading(false) }
  }

  async function handleVerifyLog() {
    if (!selectedLogId) return
    setVerifyLogResult(await api.verifyLog(selectedLogId))
  }

  async function handleTamperLog() {
    if (!selectedLogId) return
    setTamperResult(await api.tamperLog(selectedLogId))
    setVerifyLogResult(null)
  }

  const vault = status?.vault || {}
  const signing = status?.signing || {}
  const opaRunning = status?.opa_running

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Post-Quantum Cryptography Status</div>
          <div className="page-subtitle">
            NIST-standardized ML-KEM-768 + ML-DSA-65 — tamper-evident audit logs and quantum-safe credential vault
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span className={`opa-pill ${opaRunning ? 'real' : 'fallback'}`}>
            ● OPA {opaRunning ? 'Rego Active' : 'Inline Fallback'}
          </span>
          {vault.pqc_real && (
            <span className="pqc-active-pill">● Real liboqs PQC</span>
          )}
        </div>
      </div>

      {/* Algorithm cards */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        <AlgoCard
          icon="🔐"
          name={vault.kem_algorithm || 'ML-KEM-768 (Kyber768)'}
          standard={vault.kem_standard || 'NIST FIPS 203'}
          isReal={vault.pqc_real}
          stats={[
            { label: 'Purpose', value: 'Key Encapsulation (Encryption)' },
            { label: 'Public Key Size', value: `${vault.public_key_size_bytes || 1184} bytes` },
            { label: 'KEM Ciphertext Size', value: `${vault.kem_ciphertext_size_bytes || 1088} bytes` },
            { label: 'Symmetric Layer', value: 'AES-256-GCM' },
            { label: 'Security Level', value: 'NIST Level 3 (≈AES-192)' },
          ]}
        />
        <AlgoCard
          icon="✍️"
          name={signing.sig_algorithm || 'ML-DSA-65 (Dilithium3)'}
          standard={signing.sig_standard || 'NIST FIPS 204'}
          isReal={signing.pqc_real}
          stats={[
            { label: 'Purpose', value: 'Digital Signature (Audit Signing)' },
            { label: 'Public Key Size', value: `${signing.public_key_size_bytes || 1952} bytes` },
            { label: 'Signature Size', value: `${signing.signature_size_bytes || 3293} bytes` },
            { label: 'Quantum Safety', value: 'Harvest-now-decrypt-later resistant' },
            { label: 'Security Level', value: 'NIST Level 3' },
          ]}
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* Encrypt/Decrypt Demo */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">🔐 Credential Vault — Live Demo</span>
            <span className="tag">{vault.kem_algorithm?.split(' ')[0] || 'ML-KEM-768'}</span>
          </div>
          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Credential Label</label>
              <input className="input" value={encryptLabel} onChange={e => setEncryptLabel(e.target.value)} />
            </div>
            <div>
              <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Plaintext Secret</label>
              <input className="input" value={encryptPlain} onChange={e => setEncryptPlain(e.target.value)} />
            </div>
            <button className="btn btn-primary" onClick={handleEncrypt} disabled={encryptLoading}>
              {encryptLoading ? 'Encrypting…' : '🔒 Encrypt with ML-KEM-768 + AES-256-GCM'}
            </button>

            {encryptResult && (
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Vault ID</div>
                <div className="code-block" style={{ fontSize: 11 }}>{encryptResult.vault_id}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', margin: '8px 0 4px' }}>Ciphertext (truncated)</div>
                <div className="code-block" style={{ fontSize: 11 }}>{encryptResult.ciphertext_preview}</div>
                <div style={{ fontSize: 11, color: 'var(--risk-low)', marginTop: 6 }}>✓ Encrypted and stored in vault</div>
              </div>
            )}

            <div className="divider" />

            <div>
              <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Select Vault Entry to Decrypt</label>
              <select className="select" value={selectedVaultId} onChange={e => setSelectedVaultId(e.target.value)} style={{ width: '100%' }}>
                {vaultItems.map(v => (
                  <option key={v.vault_id} value={v.vault_id}>{v.label} — {v.vault_id.slice(0, 16)}</option>
                ))}
              </select>
            </div>
            <button className="btn btn-secondary" onClick={handleDecrypt} disabled={decryptLoading || !selectedVaultId}>
              {decryptLoading ? 'Decrypting…' : '🔓 Decrypt Credential'}
            </button>
            {decryptResult && (
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Decrypted Plaintext</div>
                <div className="code-block" style={{ color: 'var(--risk-low)' }}>{decryptResult.plaintext}</div>
              </div>
            )}
          </div>
        </div>

        {/* Sign/Verify Demo */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">✍️ Audit Log Signing — Live Demo</span>
              <span className="tag">{signing.sig_algorithm?.split(' ')[0] || 'ML-DSA-65'}</span>
            </div>
            <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Message to Sign</label>
                <textarea className="input" rows={2} value={signMessage} onChange={e => setSignMessage(e.target.value)} style={{ resize: 'vertical' }} />
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-primary" style={{ flex: 1 }} onClick={handleSign} disabled={signLoading}>
                  {signLoading ? 'Signing…' : '🖊 Sign with ML-DSA-65'}
                </button>
                <button className="btn btn-secondary" style={{ flex: 1 }} onClick={handleVerify} disabled={verifyLoading || !signResult}>
                  {verifyLoading ? 'Verifying…' : '✓ Verify Signature'}
                </button>
              </div>

              {signResult && (
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Signature (truncated)</div>
                  <div className="code-block" style={{ fontSize: 11 }}>{signResult.signature_preview}</div>
                </div>
              )}

              {verifyResult && (
                <div className="code-block" style={{
                  color: verifyResult.valid ? 'var(--risk-low)' : 'var(--risk-critical)',
                  fontSize: 12, fontFamily: 'inherit', lineHeight: 1.5,
                }}>
                  {verifyResult.valid ? '✓ SIGNATURE VALID — Entry not tampered' : `✗ TAMPER DETECTED — ${verifyResult.reason}`}
                </div>
              )}
            </div>
          </div>

          {/* Tamper-evidence demo */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">🔎 Tamper Detection — Live Demo</span>
            </div>
            <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <p style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Select an audit log entry, verify it (✓), then tamper it and verify again (✗) to prove tamper-evidence.
              </p>
              <select className="select" value={selectedLogId} onChange={e => { setSelectedLogId(e.target.value); setVerifyLogResult(null); setTamperResult(null) }} style={{ width: '100%' }}>
                {auditLogs.slice(0, 20).map(l => (
                  <option key={l.log_id} value={l.log_id}>{l.event_type} — {l.action_taken} — {l.log_id.slice(0, 16)}</option>
                ))}
              </select>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-secondary" style={{ flex: 1 }} onClick={handleVerifyLog}>✓ Verify</button>
                <button className="btn btn-danger" style={{ flex: 1 }} onClick={handleTamperLog}>⚡ Tamper Entry</button>
              </div>
              {tamperResult && (
                <div className="code-block" style={{ color: 'var(--risk-high)', fontSize: 12, fontFamily: 'inherit' }}>
                  ⚡ Log entry tampered. Now click "Verify" to detect.
                </div>
              )}
              {verifyLogResult && (
                <div className="code-block" style={{
                  color: verifyLogResult.verification?.valid ? 'var(--risk-low)' : 'var(--risk-critical)',
                  fontSize: 12, fontFamily: 'inherit', lineHeight: 1.6,
                }}>
                  {verifyLogResult.verification?.valid
                    ? '✓ INTEGRITY VERIFIED — Log untampered'
                    : `✗ TAMPER DETECTED — ${verifyLogResult.verification?.reason}`}
                  {'\n'}Algorithm: {verifyLogResult.algorithm}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

function AlgoCard({ icon, name, standard, isReal, stats }) {
  return (
    <div className="pqc-algo-card">
      <div className="pqc-algo-header">
        <div className="pqc-algo-icon">
          <span style={{ fontSize: 18 }}>{icon}</span>
        </div>
        <div>
          <div className="pqc-algo-name">{name}</div>
          <div className="pqc-algo-standard">{standard}</div>
        </div>
        <span className="pqc-active-pill" style={{ marginLeft: 'auto' }}>
          ● {isReal ? 'liboqs REAL' : 'Fallback'}
        </span>
      </div>
      {stats.map((s, i) => (
        <div key={i} className="pqc-stat-row">
          <span className="pqc-stat-label">{s.label}</span>
          <span className="pqc-stat-value">{s.value}</span>
        </div>
      ))}
    </div>
  )
}
