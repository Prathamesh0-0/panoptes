import csv
import datetime
import json
import logging
import uuid
import asyncio
import os
import sys

# Ensure backend is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from backend.database import AsyncSessionLocal
from backend.db_models import Identity, Session as SessionModel
from backend.main import _train_models
from sqlalchemy import delete

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cert_ingest")

DS_DIR = r"c:\Projects\PANOPTES\DS"
MAX_DATE = datetime.datetime(2010, 2, 2)  # Process only Jan 2010

async def ingest():
    logger.info("Starting CERT dataset ingestion...")

    identities_map = {}
    
    # 1. Parse LDAP
    logger.info("Parsing LDAP-2009-12.csv...")
    with open(os.path.join(DS_DIR, "LDAP-2009-12.csv"), 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            uid = row["user_id"]
            identities_map[uid] = {
                "id": uid,
                "name": row["employee_name"],
                "role": row["role"],
                "department": row["department"],
                "identity_type": "employee" if "contractor" not in row["role"].lower() else "contractor",
                "peer_group": row["role"].replace(" ", "_"),
                "allowed_systems": json.dumps(["PC-" + str(i) for i in range(1000, 9999)]),
            }
    
    logger.info(f"Loaded {len(identities_map)} identities from LDAP.")

    sessions_map = {} # (user, pc, date_str) -> SessionDict
    
    def get_or_create_session(uid, pc, dt_obj):
        date_str = dt_obj.strftime("%Y-%m-%d")
        key = (uid, pc, date_str)
        if key not in sessions_map:
            sessions_map[key] = {
                "identity_id": uid,
                "target_system": pc,
                "date_str": date_str,
                "events": [],
            }
        return sessions_map[key]

    def parse_dt(dt_str):
        return datetime.datetime.strptime(dt_str, "%m/%d/%Y %H:%M:%S")

    # 2. Parse Logon
    logger.info("Parsing logon.csv (up to Jan 31, 2010)...")
    with open(os.path.join(DS_DIR, "logon.csv"), 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            dt = parse_dt(row["date"])
            if dt >= MAX_DATE: continue
            sess = get_or_create_session(row["user"], row["pc"], dt)
            sess["events"].append((dt, row["activity"].upper()))

    # 3. Parse Device
    logger.info("Parsing device.csv (up to Jan 31, 2010)...")
    with open(os.path.join(DS_DIR, "device.csv"), 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            dt = parse_dt(row["date"])
            if dt >= MAX_DATE: continue
            sess = get_or_create_session(row["user"], row["pc"], dt)
            sess["events"].append((dt, "USB_" + row["activity"].upper()))

    # 4. Parse File
    logger.info("Parsing file.csv (up to Jan 31, 2010)...")
    with open(os.path.join(DS_DIR, "file.csv"), 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            dt = parse_dt(row["date"])
            if dt >= MAX_DATE: continue
            sess = get_or_create_session(row["user"], row["pc"], dt)
            # Use file extension or name to determine action. Default to FILE_ACCESS
            ext = row["filename"].split('.')[-1].upper() if '.' in row["filename"] else "FILE"
            if ext in ["DOC", "PDF", "TXT"]:
                action = "READ_DOC"
            elif ext in ["EXE", "ZIP"]:
                action = "EXEC_BIN"
            else:
                action = "FILE_ACCESS"
            sess["events"].append((dt, action))

    logger.info(f"Aggregated {len(sessions_map)} unique daily sessions.")

    # Sort events per session and finalize
    final_sessions = []
    for key, sess in sessions_map.items():
        uid = sess["identity_id"]
        identity = identities_map.get(uid)
        if not identity: continue
        
        sess["events"].sort(key=lambda x: x[0])
        if not sess["events"]: continue
        
        start_time = sess["events"][0][0]
        end_time = sess["events"][-1][0]
        duration_mins = (end_time - start_time).total_seconds() / 60.0
        
        actions = [e[1] for e in sess["events"]]
        
        # To avoid massive action arrays in DB, compress repetitive file access
        compressed_actions = []
        for action in actions:
            if not compressed_actions or compressed_actions[-1] != action:
                compressed_actions.append(action)
                
        # Hard limit to 30 actions to keep memory low
        if len(compressed_actions) > 30:
            compressed_actions = compressed_actions[:30]
            
        is_anomalous = False
        anomaly_type = ""
        # Randomly inject anomaly label if duration is extremely high or unusual activity
        if duration_mins > 800: # Over 13 hours
            is_anomalous = True
            anomaly_type = "EXTREME_DURATION"
        if "USB_CONNECT" in compressed_actions and "READ_DOC" in compressed_actions:
            # Not definitely an anomaly, but a good simulated heuristic for the demo
            pass
        
        final_sessions.append(SessionModel(
            session_id=f"sess_{uuid.uuid4().hex[:12]}",
            identity_id=uid,
            identity_name=identity["name"],
            peer_group=identity["peer_group"],
            identity_type=identity["identity_type"],
            start_time=start_time,
            target_system=sess["target_system"],
            privilege_level="LOW", # Default
            source_ip="0.0.0.0",
            actions=json.dumps(compressed_actions),
            data_volume_mb=len(actions) * 2.5,  # Estimate volume based on uncompressed event count
            login_hour=start_time.hour,
            duration_minutes=round(max(duration_mins, 1.0), 1),
            behavioral_score=0.1,
            sequence_score=0.1,
            asset_criticality=0.5,
            action_sensitivity=0.3,
            risk_score=5.0,
            risk_label="LOW",
            policy_action="LOG_ONLY",
            policy_reason="Historical CERT baseline.",
            policy_severity="LOW",
            explanation=json.dumps({"summary": "Baseline data."}),
            is_anomalous=is_anomalous,
            anomaly_type=anomaly_type,
        ))

    async with AsyncSessionLocal() as db:
        logger.info("Clearing old synthetic data...")
        await db.execute(delete(Identity))
        await db.execute(delete(SessionModel))
        await db.commit()

        logger.info("Inserting CERT identities...")
        identities_to_insert = [Identity(**idata) for idata in identities_map.values()]
        db.add_all(identities_to_insert)
        await db.commit()

        logger.info(f"Inserting {len(final_sessions)} CERT sessions...")
        batch_size = 1000
        for i in range(0, len(final_sessions), batch_size):
            db.add_all(final_sessions[i:i+batch_size])
            await db.commit()
            logger.info(f"Inserted {min(i+batch_size, len(final_sessions))} / {len(final_sessions)}")

    logger.info("Triggering ML model retraining on new CERT data...")
    await _train_models()
    logger.info("Ingestion and training complete!")

if __name__ == "__main__":
    asyncio.run(ingest())
