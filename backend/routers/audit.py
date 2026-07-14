"""
PANOPTES — Audit Log router
Provides PQC-signed audit log listing and tamper-evidence verification.
"""
import json
import uuid
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
    result = await db.execute(select(AuditLog).where(AuditLog.log_id == log_id))
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(status_code=404, detail="Audit log not found")

    entry = {
        "log_id": log.log_id,
        "event_type": log.event_type,
        "session_id": log.session_id,
        "identity_id": log.identity_id,
        "action_taken": log.action_taken,
        "details": log.details,
        "timestamp": log.timestamp.isoformat() if log.timestamp else "",
    }
    signed_entry = {
        **entry,
        "content_hash": "",  # will be in signature field
        "signature": log.signature,
        "public_key": log.public_key,
    }

    # Reconstruct content hash for verification
    import hashlib
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
    signed_entry["content_hash"] = hashlib.sha256(canonical).hexdigest()

    verification = verify_entry(signed_entry)
    return {
        "log_id": log_id,
        "verification": verification,
        "signature_preview": log.signature[:32] + "...",
        "algorithm": get_pqc_sig_status()["sig_algorithm"],
    }


@router.post("/{log_id}/tamper")
async def simulate_tamper(log_id: str, db: AsyncSession = Depends(get_db)):
    """Demo endpoint: tampers the log entry so tamper detection can be demonstrated."""
    result = await db.execute(select(AuditLog).where(AuditLog.log_id == log_id))
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(status_code=404, detail="Audit log not found")

    await db.execute(
        update(AuditLog)
        .where(AuditLog.log_id == log_id)
        .values(details=json.dumps({"tampered": True, "original_modified": True}), tampered=True)
    )
    await db.commit()
    return {"ok": True, "message": "Log entry tampered for demonstration. Run /verify to see detection."}


def _serialize(log: AuditLog) -> dict:
    return {
        "log_id": log.log_id,
        "event_type": log.event_type,
        "session_id": log.session_id,
        "identity_id": log.identity_id,
        "action_taken": log.action_taken,
        "details": log.details,
        "signature_preview": log.signature[:16] + "..." if log.signature else "",
        "verified": log.verified,
        "tampered": log.tampered,
        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
    }
