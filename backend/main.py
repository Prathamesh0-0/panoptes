"""
PANOPTES — FastAPI main application
Startup: generates data → trains models → starts OPA → starts live stream processor.
"""
import asyncio
import json
import logging
import os
import random
import uuid
import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, update

from backend.database import init_db, AsyncSessionLocal
from backend.db_models import Identity, Session as SessionModel, Alert, AuditLog
from backend.data_generator import generator, PEER_GROUPS
from backend.models.peer_group_model import peer_group_model
from backend.models.sequence_model import sequence_model
from backend.models.risk_fusion import fuse as risk_fuse, ASSET_CRITICALITY, ACTION_SENSITIVITY
from backend.policy import engine as policy_engine
from backend.crypto.audit_signer import sign_entry
from backend.routers import sessions, alerts, identities, audit, pqc, stream, ingest

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("panoptes.main")

STREAM_INTERVAL = float(os.getenv("STREAM_INTERVAL_SECONDS", "5"))
ANOMALY_RATE = float(os.getenv("ANOMALY_INJECTION_RATE", "0.3"))


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE SEED
# ─────────────────────────────────────────────────────────────────────────────

async def _seed_database():
    """Generate synthetic data and persist to DB if not already seeded."""
    async with AsyncSessionLocal() as db:
        count_q = await db.execute(select(Identity).limit(1))
        if count_q.scalar_one_or_none():
            logger.info("Database already seeded — skipping generation.")
            return

        logger.info("Seeding database with synthetic data…")

        # Generate identities
        identities_data = generator.generate_identities()
        for idata in identities_data:
            db.add(Identity(**idata))
        await db.commit()

        # Generate historical sessions
        sessions_data = generator.generate_historical_sessions(days=30)
        for i, sdata in enumerate(sessions_data):
            s = SessionModel(
                session_id=sdata["session_id"],
                identity_id=sdata["identity_id"],
                identity_name=sdata["identity_name"],
                peer_group=sdata["peer_group"],
                identity_type=sdata["identity_type"],
                start_time=datetime.datetime.fromisoformat(sdata["start_time"]),
                target_system=sdata["target_system"],
                privilege_level=sdata["privilege_level"],
                source_ip=sdata["source_ip"],
                actions=sdata["actions"],
                data_volume_mb=sdata["data_volume_mb"],
                login_hour=sdata["login_hour"],
                duration_minutes=sdata["duration_minutes"],
                behavioral_score=sdata["behavioral_score"],
                sequence_score=sdata["sequence_score"],
                asset_criticality=sdata["asset_criticality"],
                action_sensitivity=sdata["action_sensitivity"],
                risk_score=sdata["risk_score"],
                risk_label=sdata["risk_label"],
                policy_action=sdata["policy_action"],
                policy_reason=sdata["policy_reason"],
                policy_severity=sdata["policy_severity"],
                explanation=sdata["explanation"],
                is_anomalous=sdata["is_anomalous"],
                anomaly_type=sdata["anomaly_type"],
            )
            db.add(s)
            if i % 500 == 0:
                await db.commit()

        await db.commit()
        logger.info("Seeded %d identities, %d sessions.", len(identities_data), len(sessions_data))


# ─────────────────────────────────────────────────────────────────────────────
# ML MODEL TRAINING
# ─────────────────────────────────────────────────────────────────────────────

async def _train_models():
    logger.info("Training behavioral models…")
    async with AsyncSessionLocal() as db:
        id_result = await db.execute(select(Identity))
        identities = [
            {
                "id": i.id, "peer_group": i.peer_group,
                "identity_type": i.identity_type,
                "allowed_systems": i.allowed_systems,
            }
            for i in id_result.scalars().all()
        ]

        sess_result = await db.execute(select(SessionModel))
        sessions_raw = sess_result.scalars().all()
        sessions_dicts = [
            {
                "identity_id": s.identity_id,
                "peer_group": s.peer_group,
                "login_hour": s.login_hour,
                "duration_minutes": s.duration_minutes,
                "data_volume_mb": s.data_volume_mb,
                "actions": s.actions,
                "is_anomalous": s.is_anomalous,
            }
            for s in sessions_raw
        ]

    # Peer-group model
    peer_group_model.train(identities, sessions_dicts)

    # Update identity cluster assignments
    async with AsyncSessionLocal() as db:
        for idata in identities:
            cluster_id = peer_group_model.identity_cluster_map.get(idata["id"], 0)
            await db.execute(
                update(Identity)
                .where(Identity.id == idata["id"])
                .values(cluster_id=cluster_id)
            )
        await db.commit()

    # Sequence model — group by peer_group (use only normal sessions for training)
    normal_sessions = [s for s in sessions_dicts if not s.get("is_anomalous", False)]
    sessions_by_pg = {}
    for s in normal_sessions:
        pg = s["peer_group"]
        sessions_by_pg.setdefault(pg, []).append(s)
    sequence_model.train(sessions_by_pg)

    logger.info("Models trained successfully.")


# ─────────────────────────────────────────────────────────────────────────────
# SESSION PROCESSING PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

async def _process_session(raw: dict):
    """Score, fuse, OPA-evaluate, persist and broadcast a single session."""
    actions = json.loads(raw["actions"]) if isinstance(raw["actions"], str) else raw["actions"]
    identity_id = raw["identity_id"]
    peer_group = raw["peer_group"]
    target_system = raw["target_system"]

    # 1. Peer-group behavioral scoring
    behav_result = peer_group_model.score_session(raw, identity_id, peer_group)
    behavioral_score = behav_result["behavioral_score"]

    # 2. Sequence anomaly scoring
    seq_result = sequence_model.score(actions, peer_group)
    sequence_score = seq_result["sequence_score"]

    # 3. Load identity for context
    async with AsyncSessionLocal() as db:
        id_row = await db.execute(select(Identity).where(Identity.id == identity_id))
        identity_obj = id_row.scalar_one_or_none()
    identity_dict = {
        "id": identity_id,
        "identity_type": raw.get("identity_type", "employee"),
        "peer_group": peer_group,
        "allowed_systems": identity_obj.allowed_systems if identity_obj else "[]",
    } if identity_obj else {"id": identity_id, "identity_type": "employee", "peer_group": peer_group, "allowed_systems": "[]"}

    # 4. Risk fusion
    login_hour = raw.get("login_hour", 9)
    fusion = risk_fuse(
        behavioral_score=behavioral_score,
        sequence_score=sequence_score,
        target_system=target_system,
        actions=actions,
        peer_group=peer_group,
        identity=identity_dict,
        behavioral_deviations=behav_result.get("deviations", {}),
        sequence_result=seq_result,
        anomaly_type=raw.get("anomaly_type", ""),
        login_hour=int(login_hour),
    )
    risk_score = fusion["risk_score"]
    risk_label = fusion["risk_label"]

    # 5. OPA policy decision
    is_after_hours = login_hour < 7 or login_hour > 20
    opa_input = {
        "risk_score": risk_score,
        "identity_type": raw.get("identity_type", "employee"),
        "peer_group": peer_group,
        "target_system": target_system,
        "actions": actions,
        "asset_criticality": fusion["asset_criticality"],
        "is_after_hours": is_after_hours,
    }
    verdict = await policy_engine.evaluate(opa_input)

    # 6. Persist session
    session_db = SessionModel(
        session_id=raw["session_id"],
        identity_id=identity_id,
        identity_name=raw["identity_name"],
        peer_group=peer_group,
        identity_type=raw.get("identity_type", "employee"),
        start_time=datetime.datetime.fromisoformat(raw["start_time"]),
        target_system=target_system,
        privilege_level=raw.get("privilege_level", "LOW"),
        source_ip=raw.get("source_ip", "0.0.0.0"),
        actions=json.dumps(actions),
        data_volume_mb=float(raw.get("data_volume_mb", 0)),
        login_hour=int(login_hour),
        duration_minutes=float(raw.get("duration_minutes", 30)),
        behavioral_score=round(behavioral_score, 4),
        sequence_score=round(sequence_score, 4),
        asset_criticality=round(fusion["asset_criticality"], 4),
        action_sensitivity=round(fusion["action_sensitivity"], 4),
        risk_score=risk_score,
        risk_label=risk_label,
        policy_action=verdict.get("action", "LOG_ONLY"),
        policy_reason=verdict.get("reason", ""),
        policy_severity=verdict.get("severity", "LOW"),
        explanation=json.dumps(fusion["explanation"]),
        is_anomalous=raw.get("is_anomalous", False),
        anomaly_type=raw.get("anomaly_type", ""),
    )

    # 7. Write signed audit log entry
    audit_entry = {
        "log_id": f"log_{uuid.uuid4().hex[:12]}",
        "event_type": "SESSION_SCORED",
        "session_id": raw["session_id"],
        "identity_id": identity_id,
        "action_taken": verdict.get("action", "LOG_ONLY"),
        "details": json.dumps({
            "risk_score": risk_score,
            "risk_label": risk_label,
            "policy_action": verdict.get("action"),
            "anomaly_type": raw.get("anomaly_type", ""),
        }),
        "timestamp": datetime.datetime.utcnow().isoformat(),
    }
    signed = sign_entry(audit_entry)
    audit_db = AuditLog(
        log_id=audit_entry["log_id"],
        event_type=audit_entry["event_type"],
        session_id=raw["session_id"],
        identity_id=identity_id,
        action_taken=verdict.get("action", "LOG_ONLY"),
        details=audit_entry["details"],
        signature=signed["signature"],
        public_key=signed["public_key"],
        content_hash=signed["content_hash"],
        verified=True,
    )

    # 8. Persist alert if flagged
    alert_db = None
    if verdict.get("alerted", False):
        alert_db = Alert(
            alert_id=f"alert_{uuid.uuid4().hex[:12]}",
            session_id=raw["session_id"],
            identity_id=identity_id,
            identity_name=raw["identity_name"],
            peer_group=peer_group,
            risk_score=risk_score,
            risk_label=risk_label,
            anomaly_type=raw.get("anomaly_type", "BEHAVIORAL_ANOMALY"),
            policy_action=verdict.get("action", "LOG_ONLY"),
            explanation_summary=fusion["explanation"]["summary"],
            status="ACTIVE",
        )

    async with AsyncSessionLocal() as db:
        db.add(session_db)
        db.add(audit_db)
        if alert_db:
            db.add(alert_db)
        await db.commit()

    # 9. Broadcast to WebSocket clients
    from backend.routers.stream import broadcast
    await broadcast({
        "type": "session",
        "session_id": raw["session_id"],
        "identity_name": raw["identity_name"],
        "peer_group": peer_group,
        "target_system": target_system,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "policy_action": verdict.get("action"),
        "is_anomalous": raw.get("is_anomalous", False),
        "anomaly_type": raw.get("anomaly_type", ""),
        "timestamp": datetime.datetime.utcnow().isoformat(),
    })

    if verdict.get("alerted"):
        logger.warning(
            "🚨 ALERT | %s | %s | Score: %.1f | Action: %s",
            raw["identity_name"], target_system, risk_score, verdict.get("action"),
        )


# ─────────────────────────────────────────────────────────────────────────────
# BACKGROUND STREAM PROCESSOR
# ─────────────────────────────────────────────────────────────────────────────

async def _live_stream_processor():
    """Continuously generates and processes live events for the demo."""
    await asyncio.sleep(3)  # Give startup time to complete
    
    # Ensure generator has identities from the database
    async with AsyncSessionLocal() as db:
        id_result = await db.execute(select(Identity))
        generator.identities = [
            {
                "id": i.id,
                "name": i.name,
                "peer_group": i.peer_group,
                "identity_type": i.identity_type,
                "allowed_systems": i.allowed_systems,
            }
            for i in id_result.scalars().all()
        ]
        
    logger.info("Live stream processor started. Injecting events every %.0fs (anomaly rate: %.0f%%)",
                STREAM_INTERVAL, ANOMALY_RATE * 100)
    while True:
        try:
            inject = random.random() < ANOMALY_RATE
            raw = generator.build_live_event(inject_anomaly=inject)
            await _process_session(raw)
        except Exception as e:
            logger.error("Stream processor error: %s", e, exc_info=True)
        await asyncio.sleep(STREAM_INTERVAL)


# ─────────────────────────────────────────────────────────────────────────────
# APP LIFESPAN
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("═══ PANOPTES starting up ═══")
    await init_db()
    await _seed_database()
    await _train_models()
    await policy_engine.start_opa_server()
    asyncio.create_task(_live_stream_processor())
    logger.info("═══ PANOPTES ready ═══")
    yield
    logger.info("PANOPTES shutting down…")
    policy_engine.stop_opa_server()


# ─────────────────────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PANOPTES",
    description="Quantum-Safe Insider Threat & Privileged Access Misuse Detection Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(sessions.router)
app.include_router(alerts.router)
app.include_router(identities.router)
app.include_router(audit.router)
app.include_router(pqc.router)
app.include_router(stream.router)
app.include_router(ingest.router)

from backend.routers import policy_editor
app.include_router(policy_editor.router)

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "opa_running": policy_engine.is_opa_running(),
        "models_trained": peer_group_model._trained and sequence_model._trained,
    }

# Serve React Frontend
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

frontend_dist = os.path.join(os.path.dirname(__file__), "../frontend/dist")
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")
    
    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        # Fallback to index.html for React Router
        if full_path.startswith("api/") or full_path.startswith("ws/"):
            return {"error": "Not found"}
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(frontend_dist, "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
