import os
import sys
import csv
import json
import uuid
import asyncio
import datetime
from collections import defaultdict
import logging

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy import delete, select, func
from backend.database import init_db, AsyncSessionLocal
from backend.db_models import Session as SessionModel, Identity
from backend.data_generator import generator
from backend.main import _train_models

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_cert")

def parse_date(date_str):
    try:
        return datetime.datetime.strptime(date_str, "%m/%d/%Y %H:%M:%S")
    except Exception:
        return None

async def run():
    await init_db()
    ds_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'DS'))
    
    # We will read files and aggregate by (user, pc, date)
    sessions_map = defaultdict(list)
    identities_map = defaultdict(set) # user -> set of target systems

    logger.info("Reading logon.csv...")
    logon_file = os.path.join(ds_dir, "logon.csv")
    if os.path.exists(logon_file):
        with open(logon_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                dt = parse_date(row['date'])
                if dt:
                    sessions_map[(row['user'], row['pc'], dt.date())].append((dt, row['activity']))
                    identities_map[row['user']].add(row['pc'])

    logger.info("Reading device.csv...")
    device_file = os.path.join(ds_dir, "device.csv")
    if os.path.exists(device_file):
        with open(device_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                dt = parse_date(row['date'])
                if dt:
                    sessions_map[(row['user'], row['pc'], dt.date())].append((dt, row['activity']))
                    identities_map[row['user']].add(row['pc'])

    logger.info("Reading file.csv...")
    file_file = os.path.join(ds_dir, "file.csv")
    if os.path.exists(file_file):
        with open(file_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                dt = parse_date(row['date'])
                if dt:
                    sessions_map[(row['user'], row['pc'], dt.date())].append((dt, "File Access"))
                    identities_map[row['user']].add(row['pc'])

    logger.info(f"Aggregated {len(sessions_map)} unique user-day sessions from CERT datasets.")

    logger.info("Generating rich identities for CERT users...")
    import random
    from backend.data_generator import PEER_GROUPS
    
    cert_identities = []
    user_to_identity_map = {}
    
    for user, target_systems in identities_map.items():
        pg = random.choice(list(PEER_GROUPS.keys()))
        cfg = PEER_GROUPS[pg]
        name = generator._next_name()
        
        id_obj = {
            "id": f"id_{user}",
            "name": name,
            "role": pg,
            "department": cfg["dept"],
            "peer_group": pg,
            "identity_type": cfg["identity_type"],
            "allowed_systems": json.dumps(list(target_systems)),
        }
        cert_identities.append(id_obj)
        user_to_identity_map[user] = id_obj
        
    generator.identities = cert_identities

    db_sessions = []
    logger.info("Converting parsed data to DB models...")
    for (user, pc, sdate), events in sessions_map.items():
        # Sort events by time
        events.sort(key=lambda x: x[0])
        actions = [e[1] for e in events]
        start_time = events[0][0]
        end_time = events[-1][0]
        duration_minutes = max((end_time - start_time).total_seconds() / 60, 1.0)
        
        # Look up identity
        id_info = user_to_identity_map[user]
        
        s = SessionModel(
            session_id=f"cert_{uuid.uuid4().hex[:12]}",
            identity_id=f"id_{user}",
            identity_name=id_info["name"],
            peer_group=id_info["peer_group"],
            identity_type=id_info["identity_type"],
            start_time=start_time,
            target_system=pc,
            privilege_level="LOW",
            source_ip="0.0.0.0",
            actions=json.dumps(actions),
            data_volume_mb=round(len(events) * 2.5, 1), # mock volume
            login_hour=start_time.hour,
            duration_minutes=round(duration_minutes, 1),
            is_anomalous=False, 
            anomaly_type="",
        )
        db_sessions.append(s)

    logger.info("Generating synthetic 'normal' sessions to balance dataset...")
    synthetic_sessions = generator.generate_historical_sessions(days=30)
    
    for sdata in synthetic_sessions:
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
            is_anomalous=False,
            anomaly_type="",
        )
        db_sessions.append(s)

    logger.info("Generating synthetic anomalies for the live stream processor...")
    for _ in range(5000):
        adata = generator._inject_anomaly_event()
        s = SessionModel(
            session_id=adata["session_id"],
            identity_id=adata["identity_id"],
            identity_name=adata["identity_name"],
            peer_group=adata["peer_group"],
            identity_type=adata["identity_type"],
            start_time=datetime.datetime.fromisoformat(adata["start_time"]),
            target_system=adata["target_system"],
            privilege_level=adata["privilege_level"],
            source_ip=adata["source_ip"],
            actions=adata["actions"],
            data_volume_mb=adata["data_volume_mb"],
            login_hour=adata["login_hour"],
            duration_minutes=adata["duration_minutes"],
            is_anomalous=True,
            anomaly_type=adata["anomaly_type"],
        )
        db_sessions.append(s)
        
    logger.info("Saving to database...")
    async with AsyncSessionLocal() as db:
        # Clear existing sessions
        await db.execute(delete(SessionModel))
        await db.execute(delete(Identity))
        
        # Save identities
        for idata in generator.identities:
            db.add(Identity(**idata))
            
        # Save sessions
        for i, s in enumerate(db_sessions):
            db.add(s)
            if i % 1000 == 0:
                await db.commit()
                
        await db.commit()
    
    logger.info(f"Database populated with {len(db_sessions)} sessions.")
    logger.info("Retraining ML models...")
    
    await _train_models()
    
    logger.info("Done!")

if __name__ == "__main__":
    asyncio.run(run())
