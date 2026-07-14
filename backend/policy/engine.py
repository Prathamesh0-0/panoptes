"""
PANOPTES — OPA Policy Engine
Calls the OPA REST API with real Rego policy evaluation.
Falls back to inline Python implementation of the same logic if OPA unavailable.
"""
import asyncio
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Optional

import httpx

logger = logging.getLogger("panoptes.policy_engine")

OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")
OPA_POLICY_ENDPOINT = f"{OPA_URL}/v1/data/panoptes/access_decision"
OPA_BINARY = os.getenv("OPA_BINARY", "opa.exe" if sys.platform == "win32" else "opa")
OPA_BUNDLE_DIR = str(Path(__file__).parent.parent.parent / "opa")

_opa_process: Optional[subprocess.Popen] = None
_opa_available = False


async def start_opa_server() -> bool:
    """Attempt to launch OPA as a subprocess. Returns True if successful."""
    global _opa_process, _opa_available

    # Check if OPA binary exists
    opa_paths = [
        OPA_BINARY,
        str(Path(__file__).parent.parent.parent / OPA_BINARY),
        str(Path(__file__).parent.parent.parent / "opa" / OPA_BINARY),
    ]
    opa_exe = None
    for p in opa_paths:
        try:
            r = subprocess.run([p, "version"], capture_output=True, timeout=5)
            if r.returncode == 0:
                opa_exe = p
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    if not opa_exe:
        logger.warning("OPA binary not found — using inline policy fallback. "
                       "Download opa.exe from https://github.com/open-policy-agent/opa/releases")
        _opa_available = False
        return False

    try:
        _opa_process = subprocess.Popen(
            [opa_exe, "run", "--server",
             "--addr", "localhost:8181",
             "--log-level", "error",
             OPA_BUNDLE_DIR],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        await asyncio.sleep(2.0)  # Wait for OPA to boot

        # Health check
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{OPA_URL}/health", timeout=3.0)
            if resp.status_code == 200:
                _opa_available = True
                logger.info("OPA server running at %s (real Rego evaluation active)", OPA_URL)
                return True
    except Exception as e:
        logger.warning("OPA server start failed: %s", e)

    _opa_available = False
    return False


def stop_opa_server():
    global _opa_process
    if _opa_process:
        _opa_process.terminate()
        _opa_process = None


async def evaluate(risk_input: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate OPA policy for the given risk input.
    If OPA server is unavailable, falls back to inline Rego-equivalent logic.
    """
    global _opa_available

    if _opa_available:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    OPA_POLICY_ENDPOINT,
                    json={"input": risk_input},
                    timeout=5.0,
                )
                result = resp.json()
                decision = result.get("result", {})
                decision["evaluated_by"] = "OPA (Rego)"
                return decision
        except Exception as e:
            logger.warning("OPA call failed: %s — falling back to inline policy", e)
            _opa_available = False

    # Inline fallback (identical logic to panoptes.rego)
    return _inline_policy(risk_input)


def _inline_policy(inp: Dict[str, Any]) -> Dict[str, Any]:
    """
    Python implementation of panoptes.rego — identical logic.
    Executed when OPA server is unavailable.
    """
    score = inp.get("risk_score", 0)
    itype = inp.get("identity_type", "employee")
    actions = inp.get("actions", [])
    asset_crit = inp.get("asset_criticality", 0.5)
    is_after_hours = inp.get("is_after_hours", False)
    target = inp.get("target_system", "")

    # Rule 5: Privilege escalation + lateral movement
    if "ESCALATE" in actions and "LATERAL" in actions and score >= 70:
        return {
            "action": "KILL_SESSION",
            "reason": "CRITICAL: Privilege escalation detected in action sequence. Immediate session termination required.",
            "severity": "CRITICAL",
            "alerted": True,
            "requires_soc_review": True,
            "evaluated_by": "Inline (OPA fallback)",
        }

    # Rule 4: After-hours critical system + contractor/branch_staff
    if is_after_hours and asset_crit >= 0.9 and itype in ("contractor", "branch_staff") and score >= 60:
        return {
            "action": "KILL_SESSION",
            "reason": f"CRITICAL: After-hours access to critical system '{target}' by non-privileged identity.",
            "severity": "CRITICAL",
            "alerted": True,
            "requires_soc_review": True,
            "evaluated_by": "Inline (OPA fallback)",
        }

    # Rule 1: Critical
    if score >= 80:
        return {
            "action": "KILL_SESSION",
            "reason": f"CRITICAL: Risk score {score}/100 exceeds maximum threshold. Session terminated and access revoked.",
            "severity": "CRITICAL",
            "alerted": True,
            "requires_soc_review": True,
            "evaluated_by": "Inline (OPA fallback)",
        }

    # Rule 2: High
    if score >= 50:
        return {
            "action": "STEPUP_MFA",
            "reason": f"HIGH: Risk score {score}/100 requires additional verification. Step-up MFA challenge issued.",
            "severity": "HIGH",
            "alerted": True,
            "mfa_timeout_seconds": 120,
            "evaluated_by": "Inline (OPA fallback)",
        }

    # Rule 3: Contractor tighter
    if score >= 40 and itype == "contractor":
        return {
            "action": "STEPUP_MFA",
            "reason": f"MEDIUM: Contractor identity with risk score {score}/100 requires verification.",
            "severity": "MEDIUM",
            "alerted": True,
            "mfa_timeout_seconds": 180,
            "evaluated_by": "Inline (OPA fallback)",
        }

    return {
        "action": "LOG_ONLY",
        "reason": "Risk score within acceptable bounds.",
        "severity": "LOW",
        "alerted": False,
        "evaluated_by": "Inline (OPA fallback)",
    }


def is_opa_running() -> bool:
    return _opa_available
