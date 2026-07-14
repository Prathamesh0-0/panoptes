"""
PANOPTES — Identities router
"""
import json
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from backend.database import get_db
from backend.db_models import Identity

router = APIRouter(prefix="/api/identities", tags=["identities"])


@router.get("")
async def list_identities(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Identity))
    identities = result.scalars().all()
    return {"identities": [_serialize(i) for i in identities]}


@router.get("/{identity_id}")
async def get_identity(identity_id: str, db: AsyncSession = Depends(get_db)):
    from fastapi import HTTPException
    result = await db.execute(select(Identity).where(Identity.id == identity_id))
    i = result.scalar_one_or_none()
    if not i:
        raise HTTPException(status_code=404, detail="Identity not found")
    return _serialize(i)


def _serialize(i: Identity) -> dict:
    return {
        "id": i.id,
        "name": i.name,
        "role": i.role,
        "department": i.department,
        "identity_type": i.identity_type,
        "peer_group": i.peer_group,
        "cluster_id": i.cluster_id,
        "tenure_years": i.tenure_years,
        "normal_login_hour_mean": i.normal_login_hour_mean,
        "normal_login_hour_std": i.normal_login_hour_std,
        "normal_session_duration_mean": i.normal_session_duration_mean,
        "normal_data_volume_mean": i.normal_data_volume_mean,
        "allowed_systems": json.loads(i.allowed_systems) if isinstance(i.allowed_systems, str) else i.allowed_systems,
        "created_at": i.created_at.isoformat() if i.created_at else None,
    }
