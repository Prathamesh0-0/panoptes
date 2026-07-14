"""
PANOPTES — Composite Risk Fusion Engine
Combines behavioral anomaly score, sequence anomaly score, asset criticality,
and action sensitivity into a single explainable 0-100 risk score.
"""
import json
import math
from typing import List, Dict, Any

ASSET_CRITICALITY: Dict[str, float] = {
    "CORE_BANKING_DB": 1.00,
    "AUDIT_DB":        0.95,
    "CUSTOMER_DB":     0.90,
    "FOREX_DB":        0.85,
    "NETWORK_INFRA":   0.80,
    "FIREWALL_MGMT":   0.80,
    "BACKUP_DB":       0.70,
    "REPORTING_DB":    0.60,
    "MONITORING_DB":   0.50,
    "HR_DB":           0.50,
    "TEST_ENV":        0.20,
}

ACTION_SENSITIVITY: Dict[str, float] = {
    "DELETE":   1.00,
    "ESCALATE": 0.95,
    "EXPORT":   0.90,
    "LATERAL":  0.85,
    "MODIFY":   0.65,
    "BACKUP":   0.55,
    "VERIFY":   0.30,
    "QUERY":    0.25,
    "LOGIN":    0.10,
    "LOGOUT":   0.05,
}

# Weights must sum to 1.0
WEIGHTS = {
    "behavioral":        0.35,
    "sequence":          0.30,
    "asset_criticality": 0.20,
    "action_sensitivity": 0.15,
}

RISK_LABELS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0,  "MINIMAL"),
]


def score_to_label(score: float) -> str:
    for threshold, label in RISK_LABELS:
        if score >= threshold:
            return label
    return "MINIMAL"


def fuse(
    behavioral_score: float,
    sequence_score: float,
    target_system: str,
    actions: List[str],
    peer_group: str,
    identity: Dict,
    behavioral_deviations: Dict,
    sequence_result: Dict,
) -> Dict[str, Any]:
    """
    Produce composite risk score + structured explanation object.

    The amplification formula ensures that high asset criticality and
    dangerous actions amplify the behavioral signal — so a normal admin
    on CORE_BANKING_DB during business hours stays LOW risk.
    """
    asset_crit = ASSET_CRITICALITY.get(target_system, 0.50)
    action_sens = max(ACTION_SENSITIVITY.get(a, 0.20) for a in actions) if actions else 0.20

    # Amplified contributions: asset and action sensitivity amplify the behavioral signal
    amplified_asset = asset_crit * max(behavioral_score, sequence_score)
    amplified_action = action_sens * max(behavioral_score, sequence_score)

    raw_score = (
        WEIGHTS["behavioral"] * behavioral_score +
        WEIGHTS["sequence"] * sequence_score +
        WEIGHTS["asset_criticality"] * amplified_asset +
        WEIGHTS["action_sensitivity"] * amplified_action
    )

    # Contractor tighter multiplier (tighter threshold = slightly higher score)
    if identity.get("identity_type") == "contractor":
        raw_score *= 1.15

    # Scope violation: contractor/branch_staff accessing unauthorized system
    allowed = json.loads(identity.get("allowed_systems", "[]"))
    is_scope_violation = (target_system not in allowed) and bool(allowed)
    if is_scope_violation:
        raw_score = min(raw_score + 0.20, 1.0)

    risk_score = round(min(raw_score * 100, 100.0), 1)
    risk_label = score_to_label(risk_score)

    # ── Build explanation object ──────────────────────────────────────────────
    reasons = []

    # Behavioral reasons
    devs = behavioral_deviations or {}
    if "login_hour_mean" in devs:
        d = devs["login_hour_mean"]
        z = d.get("z_score", 0)
        if z >= 2.0:
            reasons.append(
                f"Login at {int(d['value']):02d}:00 is {z:.1f}σ outside peer-group normal "
                f"({d['cluster_mean']:.0f}:00 ± {d['cluster_std']:.0f}h)"
            )

    if "data_volume_mean" in devs:
        d = devs["data_volume_mean"]
        z = d.get("z_score", 0)
        if z >= 2.0:
            reasons.append(
                f"Data volume {d['value']:.0f} MB is {z:.1f}σ above peer-group baseline "
                f"({d['cluster_mean']:.0f} MB ± {d['cluster_std']:.0f} MB)"
            )

    if "session_duration_mean" in devs:
        d = devs["session_duration_mean"]
        z = d.get("z_score", 0)
        if z >= 2.5:
            reasons.append(
                f"Session duration {d['value']:.0f} min is {z:.1f}σ outside normal range "
                f"({d['cluster_mean']:.0f} min ± {d['cluster_std']:.0f} min)"
            )

    # Sequence reasons
    flagged_transitions = sequence_result.get("flagged_transitions", [])
    if flagged_transitions:
        reasons.append(
            f"Anomalous action sequence detected: {sequence_result.get('sequence_display', '')}"
        )
        if flagged_transitions:
            reasons.append(
                f"Low-probability transitions: {', '.join(flagged_transitions[:3])}"
            )

    # Asset/action reasons
    if asset_crit >= 0.85:
        reasons.append(f"Target system '{target_system}' has critical asset classification ({asset_crit:.0%} criticality)")

    if action_sens >= 0.85:
        risky_actions = [a for a in actions if ACTION_SENSITIVITY.get(a, 0) >= 0.85]
        reasons.append(f"High-sensitivity actions performed: {', '.join(set(risky_actions))}")

    if is_scope_violation:
        reasons.append(
            f"System '{target_system}' is OUTSIDE this identity's authorized scope "
            f"(allowed: {', '.join(allowed[:3])}{'...' if len(allowed) > 3 else ''})"
        )

    if not reasons:
        reasons.append("Behavior within normal parameters for peer group.")

    # ── Recommendation ───────────────────────────────────────────────────────
    if risk_score >= 80:
        recommendation = "Immediately terminate session and revoke access. Escalate to SOC Tier 2."
    elif risk_score >= 60:
        recommendation = "Issue step-up MFA challenge. Monitor session actively."
    elif risk_score >= 40:
        recommendation = "Log for review. Consider policy tightening for this peer group."
    else:
        recommendation = "No immediate action required. Continue passive monitoring."

    contributors = [
        {
            "name": "Behavioral Anomaly",
            "score": round(behavioral_score * 100, 1),
            "weight": int(WEIGHTS["behavioral"] * 100),
            "description": f"Deviation from peer-group {peer_group} behavioral baseline",
        },
        {
            "name": "Sequence Anomaly",
            "score": round(sequence_score * 100, 1),
            "weight": int(WEIGHTS["sequence"] * 100),
            "description": f"Action chain log-probability: {sequence_result.get('log_probability', 0):.2f}",
        },
        {
            "name": "Asset Criticality",
            "score": round(asset_crit * 100, 1),
            "weight": int(WEIGHTS["asset_criticality"] * 100),
            "description": f"Target system: {target_system}",
        },
        {
            "name": "Action Sensitivity",
            "score": round(action_sens * 100, 1),
            "weight": int(WEIGHTS["action_sensitivity"] * 100),
            "description": f"Max sensitivity action in session",
        },
    ]

    return {
        "risk_score": risk_score,
        "risk_label": risk_label,
        "behavioral_score": round(behavioral_score, 4),
        "sequence_score": round(sequence_score, 4),
        "asset_criticality": round(asset_crit, 4),
        "action_sensitivity": round(action_sens, 4),
        "is_scope_violation": is_scope_violation,
        "explanation": {
            "summary": f"Risk score {risk_score:.0f}/100 — {risk_label}",
            "reasons": reasons,
            "recommendation": recommendation,
            "contributors": contributors,
        },
    }
