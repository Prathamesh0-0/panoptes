# PANOPTES
### Quantum-Safe Insider Threat & Privileged Access Misuse Detection Platform

> **Problem Statement PS1** — Bank of Maharashtra Hackathon  
> Privileged Access Misuse & Insider Threat Detection

---

## What PANOPTES Does (That Others Don't)

| Capability | PANOPTES | Generic SIEM |
|---|---|---|
| Peer-group baselining (admin ≠ anomaly) | ✅ KMeans + z-score | ❌ Global threshold |
| Sequence/temporal modeling | ✅ Markov chain per peer group | ❌ Point-in-time events |
| Real policy enforcement | ✅ OPA + Rego | ❌ Alert dashboard only |
| Post-quantum cryptography | ✅ ML-KEM-768 + ML-DSA-65 | ❌ None |
| Explainability | ✅ Per-session reason breakdown | ❌ Log dump |

---

## Architecture

```
Synthetic Log Generator (50 identities, 8 anomaly scenarios)
          ↓
FastAPI Stream Processor (asyncio background task)
    ├── Identity Resolution + Peer Group Assignment
    ├── Peer-Group Baseline Model (KMeans + z-score deviation)
    ├── Sequence Model (Markov chain per peer group)
    ├── Composite Risk Fusion (0-100 score + explanation)
    ├── OPA Policy Engine (real Rego evaluation)
    └── PQC Layer (ML-KEM-768 + ML-DSA-65)
          ↓
SQLite (sessions, alerts, audit logs, vault)
          ↓
React SOC Dashboard (WebSocket live feed)
```

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- (Optional) OPA binary for real Rego evaluation

### Setup (first time)
```powershell
# Windows
.\setup.ps1
```

### Start
```batch
# One-click
.\start.bat

# Or manually:
# Terminal 1
.\venv\Scripts\activate
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Terminal 2
cd frontend
npm run dev
```

Open **http://localhost:5173** in your browser.

---

## Live Demo Flow (For Judges)

1. **Open Dashboard** → Watch live risk queue populate in real-time
2. **Click a CRITICAL session** → See drill-down: action timeline + score breakdown + OPA verdict
3. **Navigate to Policy Log** → See all OPA decisions (Kill Session / Step-Up MFA / Log Only)
4. **Navigate to PQC Status** → 
   - Type a credential → Click **Encrypt with ML-KEM-768** → See ciphertext
   - Click **Decrypt** → See plaintext restored
   - Type a message → Click **Sign with ML-DSA-65** → See signature
   - Click **Verify** → ✓ Valid
   - Click **Tamper Entry** on an audit log → Re-verify → ✗ TAMPER DETECTED

---

## The 8 Anomaly Scenarios

| Scenario | Trigger | Expected Risk |
|---|---|---|
| Off-Hours Bulk Export | DB_ADMIN at 2AM exporting 2.4GB | CRITICAL (90+) |
| Privilege Escalation Chain | BRANCH_STAFF gaining DB_ADMIN rights | CRITICAL (85+) |
| Contractor Scope Violation | IT_CONTRACTOR on CORE_BANKING_DB | HIGH (75+) |
| Lateral Movement | NETWORK_ADMIN hopping 3+ systems | CRITICAL (80+) |
| Mass Deletion | 4x DELETE on CUSTOMER_DB | CRITICAL (90+) |
| Shadow Admin Creation | LOGIN→ESCALATE→MODIFY→MODIFY | CRITICAL (85+) |
| Data Exfiltration Prep | 6x QUERY → EXPORT on FOREX_DB at 9PM | HIGH (75+) |
| Credential Stuffing | 15 failed logins → success at 4AM | HIGH (70+) |

---

## Post-Quantum Cryptography

### ML-KEM-768 (Kyber768) — Credential Vault
- **Standard**: NIST FIPS 203
- **Key size**: 1184 bytes (public), 2400 bytes (secret)
- **Ciphertext**: 1088 bytes
- **Use**: Encapsulates AES-256-GCM symmetric key for credential encryption
- **Why**: Protects against harvest-now-decrypt-later attacks by quantum adversaries

### ML-DSA-65 (Dilithium3) — Audit Log Signing
- **Standard**: NIST FIPS 204
- **Public key**: 1952 bytes
- **Signature**: 3293 bytes
- **Use**: Every audit log entry is signed; verify endpoint proves tamper-evidence
- **Why**: Quantum-resistant signatures ensure audit integrity even post-quantum

> **Note**: Both algorithms require `liboqs-python` for real NIST PQC. If unavailable, the system gracefully falls back to X25519 + Ed25519 with a clear label in the dashboard.

---

## OPA Policy Rules

```rego
# panoptes.rego — 5 rules evaluated by real OPA engine
Rule 1: score ≥ 80          → KILL_SESSION (critical threshold)
Rule 2: score ≥ 50          → STEPUP_MFA (elevated threshold)
Rule 3: score ≥ 40 + contractor → STEPUP_MFA (tighter for contractors)
Rule 4: after-hours + critical system + contractor → KILL_SESSION
Rule 5: ESCALATE + LATERAL in sequence + score ≥ 70 → KILL_SESSION
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11 + FastAPI |
| Database | SQLite + SQLAlchemy async |
| ML | scikit-learn (KMeans) + Markov chain |
| Policy | OPA (Open Policy Agent) + Rego |
| PQC | liboqs-python (ML-KEM-768 + ML-DSA-65) |
| Frontend | React 18 + Vite + Recharts |
| Realtime | WebSocket (asyncio) |

---

*Built for Bank of Maharashtra Hackathon — PS1: Privileged Access Misuse & Insider Threat Detection*
