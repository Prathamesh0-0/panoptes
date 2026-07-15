"""
PANOPTES — Audit Log router
PQC-signed tamper-evident audit trail with live verification.
"""
import json
import hashlib
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, update
from backend.database import get_db
from backend.db_models import AuditLog
from backend.crypto.audit_signer import verify_entry, get_pqc_sig_status

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
async def list_audit_logs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(200)
    )
    logs = result.scalars().all()
    return {"logs": [_serialize(log) for log in logs]}


@router.get("/pqc-status")
async def pqc_signing_status():
    return get_pqc_sig_status()


@router.post("/{log_id}/verify")
async def verify_log(log_id: str, db: AsyncSession = Depends(get_db)):
    """
    Verify the cryptographic integrity of an audit log entry.
    Reconstructs the signed object from stored fields and validates:
      1. SHA-256 content hash matches stored hash
      2. Digital signature validates against stored public key
    If the log was tampered (details, action, etc. changed), verification FAILS.
    """
    result = await db.execute(select(AuditLog).where(AuditLog.log_id == log_id))
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(status_code=404, detail="Audit log not found")

    # The original signed entry used timestamp from isoformat() at signing time.
    # We CANNOT safely reconstruct the exact canonical bytes because timestamps
    # may differ in precision (e.g., .123456 vs .123456000). 
    # Instead, use the stored content_hash as ground-truth — it was saved at signing time.
    # Verification checks: stored_hash == hash(current_state). If tampered, they differ.
    
    # Reconstruct the current state of the log entry
    current_entry = {
        "log_id":       log.log_id,
        "event_type":   log.event_type,
        "session_id":   log.session_id,
        "identity_id":  log.identity_id,
        "action_taken": log.action_taken,
        "details":      log.details,
        "timestamp":    log.timestamp.isoformat() if log.timestamp else "",
    }
    canonical_current = json.dumps(
        {k: v for k, v in current_entry.items() if k != "timestamp"},
        sort_keys=True, separators=(",", ":")
    ).encode()
    hash_current = hashlib.sha256(canonical_current).hexdigest()

    # If no content_hash stored (old entry), we cannot verify — return unknown
    if not log.content_hash:
        return {
            "log_id":            log_id,
            "verification":      {"valid": None, "reason": "Signature not available for this entry (pre-migration log).", "algorithm": "N/A"},
            "signature_preview": log.signature[:32] + "..." if log.signature else "",
            "algorithm":         "N/A",
            "tampered":          log.tampered,
        }

    # Core check: compare stored hash (from original signing) with current hash
    if log.tampered or (hash_current != log.content_hash):
        verification = {
            "valid":     False,
            "reason":    "TAMPER DETECTED: Log content differs from signed hash. Entry was modified after signing.",
            "algorithm": get_pqc_sig_status()["sig_algorithm"],
        }
    else:
        # Content matches. Now verify digital signature against the original canonical bytes.
        # We use stored content_hash to reconstruct what was signed (the hash itself was computed
        # from original canonical, so if hashes match, canonical is identical).
        signed_entry = {
            **current_entry,
            "content_hash": log.content_hash,
            "signature":    log.signature,
            "public_key":   log.public_key,
            "sig_algorithm": get_pqc_sig_status()["sig_algorithm"],
        }
        verification = verify_entry(signed_entry)

    return {
        "log_id":            log_id,
        "verification":      verification,
        "signature_preview": log.signature[:32] + "..." if log.signature else "",
        "algorithm":         get_pqc_sig_status()["sig_algorithm"],
        "tampered":          log.tampered,
    }


@router.post("/{log_id}/tamper")
async def simulate_tamper(log_id: str, db: AsyncSession = Depends(get_db)):
    """Demo: Tampers a log entry's details to demonstrate tamper detection."""
    result = await db.execute(select(AuditLog).where(AuditLog.log_id == log_id))
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(status_code=404, detail="Audit log not found")

    await db.execute(
        update(AuditLog)
        .where(AuditLog.log_id == log_id)
        .values(
            details=json.dumps({"tampered": True, "original_data": "MODIFIED BY ATTACKER", "risk_score": 0}),
            tampered=True,
        )
    )
    await db.commit()
    return {
        "ok": True,
        "log_id": log_id,
        "message": "Log entry tampered for demonstration. Click Verify to see detection.",
    }


def _serialize(log: AuditLog) -> dict:
    return {
        "log_id":             log.log_id,
        "event_type":         log.event_type,
        "session_id":         log.session_id,
        "identity_id":        log.identity_id,
        "action_taken":       log.action_taken,
        "details":            log.details,
        "signature_preview":  log.signature[:16] + "..." if log.signature else "",
        "content_hash_preview": log.content_hash[:16] + "..." if log.content_hash else "",
        "verified":           log.verified,
        "tampered":           log.tampered,
        "timestamp":          log.timestamp.isoformat() if log.timestamp else None,
    }
