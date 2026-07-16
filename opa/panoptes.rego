package panoptes

import future.keywords.if
import future.keywords.in

# ─────────────────────────────────────────────────────────────────────────────
# PANOPTES Risk-Based Access Policy
# Evaluated by OPA (Open Policy Agent) — NIST SP 800-207 Zero Trust principles
# ─────────────────────────────────────────────────────────────────────────────

# Default: allow with logging only
default access_decision := {
    "action": "LOG_ONLY",
    "reason": "Risk score within acceptable bounds.",
    "severity": "LOW",
    "alerted": false,
    "policy_version": "1.0",
}

# ─── CRITICAL: Kill session + revoke access (score ≥ 80) ─────────────────────
access_decision := {
    "action": "KILL_SESSION",
    "reason": sprintf(
        "CRITICAL: Risk score %v/100 exceeds maximum threshold. Session terminated and access revoked immediately.",
        [input.risk_score]
    ),
    "severity": "CRITICAL",
    "alerted": true,
    "requires_soc_review": true,
    "policy_version": "1.0",
} if {
    input.risk_score >= 80
}

# ─── HIGH: Step-up MFA required (score 50–79) ────────────────────────────────
access_decision := {
    "action": "STEPUP_MFA",
    "reason": sprintf(
        "HIGH: Risk score %v/100 requires additional verification. Step-up MFA challenge issued.",
        [input.risk_score]
    ),
    "severity": "HIGH",
    "alerted": true,
    "mfa_timeout_seconds": 120,
    "policy_version": "1.0",
} if {
    input.risk_score >= 50
    input.risk_score < 80
}

# ─── CONTRACTOR TIGHTER RULE: Step-up at score ≥ 40 ─────────────────────────
access_decision := {
    "action": "STEPUP_MFA",
    "reason": sprintf(
        "MEDIUM: Contractor identity with risk score %v/100 requires verification (threshold: 40 for contractors).",
        [input.risk_score]
    ),
    "severity": "MEDIUM",
    "alerted": true,
    "mfa_timeout_seconds": 180,
    "policy_version": "1.0",
} if {
    input.risk_score >= 40
    input.risk_score < 50
    input.identity_type == "contractor"
}

# ─── AFTER-HOURS CRITICAL SYSTEM RULE ────────────────────────────────────────
access_decision := {
    "action": "KILL_SESSION",
    "reason": sprintf(
        "CRITICAL: After-hours access to critical system '%v' by non-privileged identity. Session terminated.",
        [input.target_system]
    ),
    "severity": "CRITICAL",
    "alerted": true,
    "requires_soc_review": true,
    "policy_version": "1.0",
} if {
    input.is_after_hours == true
    input.asset_criticality >= 0.9
    input.identity_type in ["contractor", "branch_staff"]
    input.risk_score >= 60
    input.risk_score < 80
}

# ─── PRIVILEGE ESCALATION DETECTION ──────────────────────────────────────────
access_decision := {
    "action": "KILL_SESSION",
    "reason": "CRITICAL: Privilege escalation detected in action sequence. Immediate session termination required.",
    "severity": "CRITICAL",
    "alerted": true,
    "requires_soc_review": true,
    "policy_version": "1.0",
} if {
    "ESCALATE" in input.actions
    "LATERAL" in input.actions
    input.risk_score >= 70
    input.risk_score < 80
    not (input.is_after_hours == true and input.asset_criticality >= 0.9 and input.identity_type in ["contractor", "branch_staff"])
}

# ─── Helpers ─────────────────────────────────────────────────────────────────
allow if {
    access_decision.action != "KILL_SESSION"
}
