"""
PANOPTES — Sessions router
"""
import json
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, text
from backend.database import get_db
from backend.db_models import Session as SessionModel

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


@router.get("")
async def list_sessions(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    risk_label: Optional[str] = None,
    peer_group: Optional[str] = None,
    identity_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * per_page
    stmt = select(SessionModel).order_by(desc(SessionModel.risk_score))

    if risk_label:
        stmt = stmt.where(SessionModel.risk_label == risk_label.upper())
    if peer_group:
        stmt = stmt.where(SessionModel.peer_group == peer_group)
    if identity_id:
        stmt = stmt.where(SessionModel.identity_id == identity_id)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.offset(offset).limit(per_page)
    result = await db.execute(stmt)
    sessions = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "sessions": [_serialize(s) for s in sessions],
    }


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """Dashboard summary statistics."""
    from backend.db_models import Alert
    
    total_q = await db.execute(select(func.count()).select_from(SessionModel))
    total = total_q.scalar() or 0

    active_alerts_q = await db.execute(select(func.count()).select_from(Alert).where(Alert.status == 'ACTIVE'))
    active_alerts = active_alerts_q.scalar() or 0

    async def count_label(lbl):
        q = await db.execute(
            select(func.count()).select_from(SessionModel).where(SessionModel.risk_label == lbl)
        )
        return q.scalar() or 0

    critical = await count_label("CRITICAL")
    high = await count_label("HIGH")
    medium = await count_label("MEDIUM")
    low = await count_label("LOW")

    blocked_q = await db.execute(
        select(func.count()).select_from(SessionModel)
        .where(SessionModel.policy_action == "KILL_SESSION")
    )
    blocked = blocked_q.scalar() or 0

    mfa_q = await db.execute(
        select(func.count()).select_from(SessionModel)
        .where(SessionModel.policy_action == "STEPUP_MFA")
    )
    mfa_challenges = mfa_q.scalar() or 0

    anomalous_q = await db.execute(
        select(func.count()).select_from(SessionModel)
        .where(SessionModel.is_anomalous == True)  # noqa
    )
    anomalous = anomalous_q.scalar() or 0

    return {
        "total_sessions": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "blocked": blocked,
        "mfa_challenges": mfa_challenges,
        "anomalous_detected": anomalous,
        "active_alerts": active_alerts,
    }


@router.get("/{session_id}")
async def get_session(session_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(SessionModel).where(SessionModel.session_id == session_id)
    )
    s = result.scalar_one_or_none()
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    return _serialize(s, detail=True)


def _serialize(s: SessionModel, detail: bool = False) -> dict:
    base = {
        "session_id": s.session_id,
        "identity_id": s.identity_id,
        "identity_name": s.identity_name,
        "peer_group": s.peer_group,
        "identity_type": s.identity_type,
        "start_time": s.start_time.isoformat() if s.start_time else None,
        "target_system": s.target_system,
        "privilege_level": s.privilege_level,
        "source_ip": s.source_ip,
        "actions": json.loads(s.actions) if isinstance(s.actions, str) else s.actions,
        "data_volume_mb": s.data_volume_mb,
        "login_hour": s.login_hour,
        "duration_minutes": s.duration_minutes,
        "behavioral_score": s.behavioral_score,
        "sequence_score": s.sequence_score,
        "asset_criticality": s.asset_criticality,
        "action_sensitivity": s.action_sensitivity,
        "risk_score": s.risk_score,
        "risk_label": s.risk_label,
        "policy_action": s.policy_action,
        "policy_reason": s.policy_reason,
        "policy_severity": s.policy_severity,
        "is_anomalous": s.is_anomalous,
        "anomaly_type": s.anomaly_type,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }
    if detail:
        base["explanation"] = json.loads(s.explanation) if isinstance(s.explanation, str) else {}
    return base
