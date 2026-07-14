"""
PANOPTES — Alerts router
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, update
from backend.database import get_db
from backend.db_models import Alert

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    policy_action: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    offset = (page - 1) * per_page
    stmt = select(Alert).order_by(desc(Alert.timestamp))

    if status:
        stmt = stmt.where(Alert.status == status.upper())
    if policy_action:
        stmt = stmt.where(Alert.policy_action == policy_action.upper())

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    stmt = stmt.offset(offset).limit(per_page)
    result = await db.execute(stmt)
    alerts = result.scalars().all()

    return {
        "total": total,
        "alerts": [_serialize(a) for a in alerts],
    }


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    status: str,
    db: AsyncSession = Depends(get_db),
):
    valid = {"ACTIVE", "RESOLVED", "REVIEWED"}
    if status.upper() not in valid:
        return {"error": f"Status must be one of {valid}"}
    await db.execute(
        update(Alert).where(Alert.alert_id == alert_id).values(status=status.upper())
    )
    await db.commit()
    return {"ok": True, "alert_id": alert_id, "status": status.upper()}


def _serialize(a: Alert) -> dict:
    return {
        "alert_id": a.alert_id,
        "session_id": a.session_id,
        "identity_id": a.identity_id,
        "identity_name": a.identity_name,
        "peer_group": a.peer_group,
        "risk_score": a.risk_score,
        "risk_label": a.risk_label,
        "anomaly_type": a.anomaly_type,
        "policy_action": a.policy_action,
        "explanation_summary": a.explanation_summary,
        "status": a.status,
        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
    }
