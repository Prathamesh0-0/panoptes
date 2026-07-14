# PANOPTES — Quantum-Safe Insider Threat & Privileged Access Misuse Detection Platform

**Problem Statement:** PS1 — Privileged Access Misuse & Insider Threat Detection
**Document type:** Product Requirements Document (PRD)
**Owner:** Prathamesh
**Status:** Draft v1.0

---

## 1. Executive Summary

Insider threats from employees, contractors, vendors, and privileged admins acting maliciously, negligently, or under compromise represent one of the hardest detection problems in banking security, because the actor already holds valid credentials. Signature-based and static-threshold tools fail here because "anomalous" behavior for one role is completely normal for another.

PANOPTES is a real-time, peer-group-aware behavioral analytics platform that fuses privileged-session telemetry, sequence-level action modeling, and asset-criticality weighting into a single explainable risk score — which then drives automated, risk-based access decisions and is protected end-to-end by post-quantum cryptography (PQC), so that today's credential vaults and audit trails remain tamper-evident even against future quantum-capable adversaries.

**What makes this different from a generic anomaly detector:**
- Peer-group baselining instead of global thresholds (admins doing admin things ≠ anomaly)
- Sequence/temporal modeling of action chains, not point-in-time scoring
- A real policy enforcement point (OPA), not a dashboard that just displays a number
- Actual NIST PQC primitives (Kyber, Dilithium) wired into the credential vault and audit log signing — not a "quantum-safe" badge with nothing behind it

---

## 2. Goals & Non-Goals

### Goals
1. Detect misuse of privileged accounts by comparing behavior against peer-group baselines, not global averages.
2. Identify insider threats in near-real-time via a streaming ingestion pipeline.
3. Produce a composite, explainable risk score per session/identity.
4. Enable automated risk-based access control (step-up auth, session kill, access revocation) via policy-as-code.
5. Protect credential vault contents and audit logs with real NIST-standardized post-quantum cryptography.
6. Ship a SOC-style dashboard that a non-technical judge/reviewer can understand in under 2 minutes.

### Non-Goals (explicitly out of scope, state this to avoid scope creep)
- Building a production-grade PAM tool (CyberArk replacement) — we build the detection + policy layer on top of simulated/sample PAM logs.
- Full quantum threat detection — we do NOT claim to detect actual quantum attacks; we claim to protect against harvest-now-decrypt-later by using PQC-encrypted storage and PQC-signed audit trails.
- Multi-tenant SaaS architecture — single-org demo scope.
- Training a from-scratch LLM — we use existing foundation models via API for the explainability/narrative layer.

---

## 3. Users & Personas

| Persona | Need |
|---|---|
| SOC Analyst | Wants a ranked queue of risky sessions with explainable "why," not raw logs |
| CISO / Judge (evaluator) | Wants to see the composite risk logic and the PQC layer actually functioning, not claimed |
| Identity/Access Admin | Wants the system to trigger real access decisions (step-up auth, revoke), not just alert |

---

## 4. Data Sources & Simulated Inputs

Since real PAM/bank logs are unavailable, generate realistic synthetic data covering:

- **PAM session logs**: session start/end, target system, commands executed, privilege level used (CyberArk/BeyondTrust-style schema)
- **Windows Event Logs**: Event IDs 4624 (logon), 4625 (failed logon), 4672 (special privileges assigned), 4688 (process creation), 4768 (Kerberos TGT)
- **SSH/sudo logs**: `auth.log` style — user, source IP, command, timestamp
- **Database access logs**: query type, table accessed, row count returned, timestamp
- **Identity metadata**: role, department, tenure, normal working hours, peer group ID

Build a synthetic data generator that injects a controlled number of "insider threat" scenarios (e.g., off-hours mass data export, privilege escalation followed by lateral movement, contractor accessing systems outside their scope) into an otherwise normal-looking dataset, so detection can be demoed and measured against ground truth.

---

## 5. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DATA INGESTION LAYER                      │
│   Synthetic log generator → Kafka/Redpanda (or simulated queue)  │
└───────────────────────────────┬───────────────────────────────────┘
                                 │
┌───────────────────────────────▼───────────────────────────────────┐
│                      STREAM PROCESSING LAYER                       │
│  - Identity resolution (map raw events → identity + peer group)   │
│  - Feature extraction (session features, action sequences)        │
└───────────────────────────────┬───────────────────────────────────┘
                                 │
┌───────────────────────────────▼───────────────────────────────────┐
│                    BEHAVIORAL ANALYTICS ENGINE                     │
│  1. Peer-Group Baseline Model  (clustering: role/dept/tenure)      │
│  2. Sequence Model (LSTM / Markov chain on action sequences)       │
│  3. Composite Risk Fusion Score = f(behavioral, asset-criticality, │
│     action-sensitivity)                                           │
└───────────────────────────────┬───────────────────────────────────┘
                                 │
┌───────────────────────────────▼───────────────────────────────────┐
│                   POLICY DECISION LAYER (OPA)                     │
│  Risk score crosses threshold → step-up auth / session kill /     │
│  access revoke decision, returned as policy verdict               │
└───────────────────────────────┬───────────────────────────────────┘
                                 │
┌───────────────────────────────▼───────────────────────────────────┐
│                 QUANTUM-SAFE CRYPTOGRAPHY LAYER                    │
│  - Credential vault encrypted with Kyber (ML-KEM)                 │
│  - Audit logs signed with Dilithium (ML-DSA) for tamper-evidence   │
└───────────────────────────────┬───────────────────────────────────┘
                                 │
┌───────────────────────────────▼───────────────────────────────────┐
│                     SOC DASHBOARD (Frontend)                       │
│  Ranked risk queue, session drill-down, explainability panel,     │
│  PQC status indicator, policy verdict log                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 6. Core Modules — Detailed Requirements

### 6.1 Synthetic Data Generator
- Generates identities with role/department/peer-group assignment
- Generates N days of "normal" behavior per identity, sampled from role-specific distributions
- Injects labeled anomaly scenarios at a configurable rate
- Outputs to JSON/CSV, replayable into the stream processor at configurable speed (real-time simulation)

### 6.2 Peer-Group Baseline Model
- Cluster identities by role, department, tenure band (k-means or hierarchical clustering on behavioral feature vectors: typical login hours, typical systems accessed, typical command types, typical data volume touched)
- Compute per-cluster statistical baselines (mean/std or distribution) for each feature
- Score new behavior as deviation from **peer-group** baseline (z-score or Mahalanobis distance), not global baseline
- This is the #1 differentiator — do not skip or fake this with a global threshold

### 6.3 Sequence/Temporal Model
- Represent each session as a sequence of discretized actions (login → file access → privilege escalation → export, etc.)
- Train an LSTM (or start with a Markov transition matrix per peer group if time-constrained) to score how likely an observed sequence is given the peer group's normal transition patterns
- Flag low-probability sequences even if individual actions look benign in isolation

### 6.4 Composite Risk Fusion Engine
Score = weighted combination of:
- Behavioral anomaly score (from 6.2)
- Sequence anomaly score (from 6.3)
- Asset criticality weight (which system/data was touched — maintain a simple criticality lookup table)
- Action sensitivity weight (e.g., mass export > single file read)

Output: single 0-100 risk score + a structured explanation object (which sub-scores contributed, in plain language) — reuse/adapt your CVSS-weighted risk scoring logic from SENTINEL.

### 6.5 Policy Decision Layer (OPA)
- Write actual Rego policies: risk score thresholds mapped to actions (score > 80 → kill session + revoke; 50-80 → step-up MFA challenge; <50 → log only)
- Expose as a real policy decision point the risk engine calls — this must functionally execute, not be simulated with an if-statement, or it will not survive technical Q&A

### 6.6 Post-Quantum Cryptography Layer
- Use `liboqs` (via `liboqs-python` bindings) or `pqcrypto` crate
- **Credential vault**: encrypt stored credentials/secrets using ML-KEM (Kyber) key encapsulation + AES-256-GCM for the symmetric payload
- **Audit log integrity**: sign every audit log entry with ML-DSA (Dilithium); provide a verification endpoint/script that proves logs haven't been tampered with
- Dashboard must show a live "PQC Status" indicator (algorithm in use, key sizes) — this is what makes the claim credible instead of decorative

### 6.7 SOC Dashboard
- Ranked queue of sessions/identities by current risk score
- Drill-down view: raw session timeline + explainability panel (why flagged)
- Policy verdict log (what action was taken, when)
- PQC status panel

---

## 7. Tech Stack (Recommended)

| Layer | Technology |
|---|---|
| Streaming/ingestion | Kafka or Redpanda (or a lightweight simulated queue if time-constrained) |
| Backend/API | Python (FastAPI) |
| Behavioral modeling | scikit-learn (clustering), PyTorch/Keras (LSTM) |
| Policy engine | Open Policy Agent (OPA) + Rego |
| PQC | liboqs-python (Kyber/ML-KEM, Dilithium/ML-DSA) |
| Database | PostgreSQL (session/identity data) + Redis (real-time scoring cache) |
| Frontend | React + Tailwind + Recharts (dark SOC aesthetic, consistent with your existing portfolio style) |
| Explainability narrative | Claude API (Sonnet) for natural-language risk explanations |

---

## 8. Milestones

| Phase | Deliverable | Target |
|---|---|---|
| 1 | Synthetic data generator + schema finalized | Day 1-2 |
| 2 | Peer-group baseline model working on synthetic data | Day 3-4 |
| 3 | Sequence model + composite risk fusion | Day 5-6 |
| 4 | OPA policy layer wired to risk engine | Day 7 |
| 5 | PQC vault + signed audit logs functional | Day 8-9 |
| 6 | Dashboard + end-to-end demo flow | Day 10-11 |
| 7 | Buffer, bug fixes, pitch deck, rehearsal | Day 12-14 |

*(Adjust days to your actual hackathon window — insert real deadline.)*

---

## 9. Success Metrics (for your own validation, and to cite in the pitch)

- Precision/recall of injected anomaly scenarios detected
- False positive rate on normal peer-group behavior
- Latency from event ingestion to risk score (must support the "real-time" claim)
- PQC operations demonstrably functional (encrypt/decrypt/sign/verify all working, not mocked)

---

## 10. Key Risks

| Risk | Mitigation |
|---|---|
| LSTM sequence model underperforms with limited synthetic data/time | Fall back to Markov-chain transition model per peer group — still defensible and faster to implement |
| PQC library integration friction (liboqs build issues) | Test `liboqs-python` install early, Day 1, not Day 8 — this is the single biggest technical risk in the whole project |
| Judges probe "is this actually quantum-safe or just labeled that way" | Have the verification script ready to run live: encrypt/decrypt/sign/verify demo on demand |
| Scope creep into building a full PAM product | Explicitly demo on top of synthetic PAM logs, state this is the detection + policy + crypto layer, not a PAM replacement |

---

## 11. Appendix — Build Prompt (see companion prompt block for Antigravity/Claude Sonnet)
