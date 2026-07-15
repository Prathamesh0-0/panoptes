"""
PANOPTES — Real-World Data Ingestion API
=========================================
Accepts log data from actual enterprise systems:
  - Windows Event Log (JSON format from WEF/winlogbeat)
  - Syslog CEF (ArcSight Common Event Format from SIEM)
  - CyberArk PAM Session JSON
  - Generic PAM session POST (custom agent)
  - Bulk CSV upload (offline replay)

Each incoming event is normalized into PANOPTES internal format,
then passed through the full risk pipeline (same as synthetic events).

In production, these endpoints would be called by:
  - A lightweight agent installed on Windows DCs / PAM servers
  - Webhook integrations from Splunk / QRadar
  - CyberArk Central Policy Manager webhooks
  - A scheduled batch job pulling from SIEM
"""
import csv
import io
import json
import datetime
import uuid
import logging
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db

logger = logging.getLogger("panoptes.ingest")

router = APIRouter(prefix="/api/ingest", tags=["ingest"])


# ─── Normalised internal event schema ────────────────────────────────────────
class NormalisedEvent(BaseModel):
    """Common schema that all source adapters convert into."""
    identity_id: str
    identity_name: str
    identity_type: str = "employee"          # employee | contractor | service_account
    peer_group: str = "UNKNOWN"
    target_system: str
    source_ip: str = "0.0.0.0"
    actions: List[str]
    data_volume_mb: float = 0.0
    login_hour: int = 9
    duration_minutes: float = 30.0
    privilege_level: str = "LOW"
    raw_source: str = "api"                  # windows_event | cef | cyberark | csv | api
    raw_payload: Optional[str] = None        # original JSON/line for audit


# ─── Source-specific request schemas ─────────────────────────────────────────

class WindowsEventLogEntry(BaseModel):
    """
    Windows Security Event Log format (as forwarded by winlogbeat / WEF).
    Event IDs mapped to PANOPTES actions:
      4624 → LOGIN        4648 → LOGIN (explicit creds)
      4634/4647 → LOGOUT  4768 → LOGIN (Kerberos)
      4672 → ESCALATE     4688 → MODIFY (process create)
      4698 → MODIFY       4732 → ESCALATE (group add)
      4740 → (failed - counted separately)
      5145 → QUERY        4663 → QUERY/EXPORT (file access)
    """
    EventID: int
    TimeCreated: str                         # ISO datetime
    Computer: str                            # hostname = target system
    SubjectUserName: str                     # actor
    SubjectUserSid: Optional[str] = None
    TargetUserName: Optional[str] = None
    LogonType: Optional[int] = None
    IpAddress: Optional[str] = None
    ProcessName: Optional[str] = None
    ObjectName: Optional[str] = None
    Keywords: Optional[str] = None


class WindowsEventBatch(BaseModel):
    """Batch of Windows events from a single agent push."""
    agent_id: str
    hostname: str
    events: List[WindowsEventLogEntry]


class CEFEvent(BaseModel):
    """
    ArcSight CEF (Common Event Format) syslog line parsed into fields.
    Used by Splunk, QRadar, IBM SIEM.
    Example: CEF:0|Microsoft|Active Directory|...|4624|User logged in|5|...
    """
    cef_version: str = "CEF:0"
    device_vendor: str
    device_product: str
    signature_id: str                        # Event ID or rule ID
    name: str                                # Human-readable event name
    severity: int = 5                        # 0-10
    extensions: Dict[str, str] = {}         # key=value pairs from CEF extension


class CyberArkPAMSession(BaseModel):
    """
    CyberArk PAM session log format (from CPM webhooks or PVWA API).
    Sent when a privileged session starts/ends.
    """
    SessionId: str
    User: str
    AccountName: str                         # privileged account used
    Address: str                             # target machine
    Protocol: str = "RDP"                   # RDP | SSH | SQL | HTTP
    StartTime: str
    EndTime: Optional[str] = None
    Duration: Optional[int] = None          # seconds
    ActivitiesCount: Optional[int] = None
    CommandsCount: Optional[int] = None
    KeystrокesCount: Optional[int] = None   # typo preserved for CyberArk compat
    BytesTransferred: Optional[int] = None
    Risk: Optional[str] = None              # CyberArk's own risk score
    Reason: Optional[str] = None


class GenericPAMEvent(BaseModel):
    """
    Generic PAM event for custom integrations.
    Can be sent from any agent, script, or middleware.
    This is the simplest way for a bank's IT team to integrate.
    """
    user_id: str                             # employee ID or service account
    user_name: str
    user_type: str = "employee"             # employee | contractor | service_account
    department: Optional[str] = None
    target_system: str                       # DB name, server hostname, app name
    source_ip: str = "0.0.0.0"
    action: str                              # LOGIN | QUERY | MODIFY | EXPORT | DELETE | ESCALATE | LOGOUT
    timestamp: str                           # ISO 8601
    data_volume_bytes: Optional[int] = None
    session_id: Optional[str] = None
    privilege_level: str = "LOW"            # LOW | MEDIUM | HIGH | SUPERUSER


# ─── Action mapping tables ────────────────────────────────────────────────────

WINDOWS_EVENTID_ACTION = {
    4624: "LOGIN",      # Successful logon
    4648: "LOGIN",      # Logon with explicit credentials
    4768: "LOGIN",      # Kerberos TGT requested
    4769: "QUERY",      # Kerberos service ticket (resource access)
    4634: "LOGOUT",     # Logoff
    4647: "LOGOUT",     # User-initiated logoff
    4672: "ESCALATE",   # Special privileges assigned (admin logon)
    4732: "ESCALATE",   # Member added to security group
    4688: "MODIFY",     # New process created
    4698: "MODIFY",     # Scheduled task created
    4663: "QUERY",      # Object access attempt
    4660: "DELETE",     # Object deleted
    5145: "QUERY",      # Network share object access
    4776: "LOGIN",      # Credential validation (NTLM)
    4771: "LOGIN",      # Kerberos pre-auth failed → still LOGIN
    4719: "MODIFY",     # System audit policy changed (suspicious)
    4765: "ESCALATE",   # SID History added to account
}

PROTOCOL_ACTION = {
    "SQL": ["LOGIN", "QUERY", "LOGOUT"],
    "RDP": ["LOGIN", "MODIFY", "LOGOUT"],
    "SSH": ["LOGIN", "MODIFY", "LATERAL", "LOGOUT"],
    "HTTP": ["LOGIN", "QUERY", "LOGOUT"],
    "SFTP": ["LOGIN", "EXPORT", "LOGOUT"],
}

SYSTEM_PEER_GROUP_GUESS = {
    "ORACLE": "DB_ADMIN",      "MSSQL": "DB_ADMIN",   "MYSQL": "DB_ADMIN",
    "POSTGRES": "DB_ADMIN",    "DB": "DB_ADMIN",       "DATABASE": "DB_ADMIN",
    "CORE_BANKING": "DB_ADMIN","FINACLE": "DB_ADMIN",
    "FIREWALL": "NETWORK_ADMIN","ROUTER": "NETWORK_ADMIN","SWITCH": "NETWORK_ADMIN",
    "INFRA": "NETWORK_ADMIN",  "NETWORK": "NETWORK_ADMIN",
    "TELLER": "BRANCH_STAFF",  "BRANCH": "BRANCH_STAFF","CBS": "BRANCH_STAFF",
    "FOREX": "FINANCE_ANALYST","TREASURY": "FINANCE_ANALYST","ANALYST": "FINANCE_ANALYST",
}


def _guess_peer_group(target: str, user_type: str) -> str:
    if user_type == "contractor":
        return "IT_CONTRACTOR"
    upper = target.upper()
    for keyword, group in SYSTEM_PEER_GROUP_GUESS.items():
        if keyword in upper:
            return group
    return "BRANCH_STAFF"


def _normalise_windows_batch(batch: WindowsEventBatch) -> List[NormalisedEvent]:
    """Convert a batch of Windows events into PANOPTES session events."""
    # Group events by user (session-like aggregation)
    user_events: Dict[str, List] = {}
    for ev in batch.events:
        user = ev.SubjectUserName or "UNKNOWN"
        user_events.setdefault(user, []).append(ev)

    sessions = []
    for user, events in user_events.items():
        actions = []
        login_hour = 9
        source_ip = "0.0.0.0"

        for ev in sorted(events, key=lambda e: e.TimeCreated):
            action = WINDOWS_EVENTID_ACTION.get(ev.EventID)
            if action:
                actions.append(action)
            try:
                dt = datetime.datetime.fromisoformat(ev.TimeCreated.rstrip("Z"))
                login_hour = dt.hour
            except Exception:
                pass
            if ev.IpAddress and ev.IpAddress != "-":
                source_ip = ev.IpAddress

        if not actions:
            actions = ["LOGIN", "LOGOUT"]

        sessions.append(NormalisedEvent(
            identity_id=f"win_{user.lower().replace(' ', '_')}",
            identity_name=user,
            target_system=batch.hostname.upper(),
            source_ip=source_ip,
            actions=actions,
            login_hour=login_hour,
            raw_source="windows_event",
            raw_payload=batch.model_dump_json(),
        ))
    return sessions


def _normalise_cef(cef: CEFEvent) -> NormalisedEvent:
    """Convert CEF event to PANOPTES event."""
    ext = cef.extensions
    user = ext.get("suser") or ext.get("duser") or ext.get("suid") or "cef_user"
    target = ext.get("dhost") or ext.get("dst") or ext.get("destinationHostName") or "UNKNOWN_SYSTEM"
    source_ip = ext.get("src") or ext.get("sourceAddress") or "0.0.0.0"
    ts_str = ext.get("rt") or ext.get("end") or datetime.datetime.utcnow().isoformat()
    try:
        dt = datetime.datetime.fromisoformat(ts_str.rstrip("Z"))
        login_hour = dt.hour
    except Exception:
        login_hour = 9

    event_id = int(cef.signature_id) if cef.signature_id.isdigit() else 0
    action = WINDOWS_EVENTID_ACTION.get(event_id, "QUERY")

    return NormalisedEvent(
        identity_id=f"cef_{user.lower().replace(' ', '_')}",
        identity_name=user,
        target_system=target.upper(),
        source_ip=source_ip,
        actions=[action, "LOGOUT"],
        login_hour=login_hour,
        raw_source="cef",
        raw_payload=cef.model_dump_json(),
    )


def _normalise_cyberark(session: CyberArkPAMSession) -> NormalisedEvent:
    """Convert CyberArk PAM session to PANOPTES event."""
    try:
        dt = datetime.datetime.fromisoformat(session.StartTime.rstrip("Z"))
        login_hour = dt.hour
    except Exception:
        login_hour = 9

    duration = (session.Duration or 0) / 60  # seconds → minutes
    actions = PROTOCOL_ACTION.get(session.Protocol.upper(), ["LOGIN", "QUERY", "LOGOUT"])

    # Infer extra actions from session metadata
    if session.BytesTransferred and session.BytesTransferred > 50_000_000:
        actions = ["LOGIN", "QUERY", "EXPORT", "LOGOUT"]
    if session.CommandsCount and session.CommandsCount > 100:
        actions.insert(-1, "MODIFY")

    data_mb = (session.BytesTransferred or 0) / 1_000_000

    return NormalisedEvent(
        identity_id=f"ca_{session.User.lower().replace(' ', '_')}",
        identity_name=session.User,
        target_system=session.Address.upper(),
        source_ip=session.Address,
        actions=actions,
        login_hour=login_hour,
        duration_minutes=max(duration, 1.0),
        data_volume_mb=data_mb,
        privilege_level="HIGH",
        raw_source="cyberark",
        raw_payload=session.model_dump_json(),
    )


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/windows-event")
async def ingest_windows_event_batch(
    batch: WindowsEventBatch,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest Windows Security Event Log batch.
    Called by winlogbeat / Windows Event Forwarder agent.

    Deploy the agent on each Windows DC / PAM server:
      winlogbeat.yml → output.logstash or webhook → this endpoint
    """
    events = _normalise_windows_batch(batch)
    background_tasks.add_task(_process_normalised_events, events)
    return {
        "accepted": len(events),
        "source":   "windows_event",
        "message":  f"{len(events)} session(s) queued for risk scoring.",
    }


@router.post("/cef")
async def ingest_cef_event(
    event: CEFEvent,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest a single CEF (Common Event Format) event from a SIEM.
    Configure Splunk / QRadar to forward relevant events here via webhook.
    """
    normalised = _normalise_cef(event)
    background_tasks.add_task(_process_normalised_events, [normalised])
    return {
        "accepted": 1,
        "source":   "cef",
        "message":  "Event queued for risk scoring.",
    }


@router.post("/cyberark")
async def ingest_cyberark_session(
    session: CyberArkPAMSession,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest a CyberArk PAM session record.
    Configure CyberArk CPM webhooks to POST to this endpoint on session end.
    """
    normalised = _normalise_cyberark(session)
    background_tasks.add_task(_process_normalised_events, [normalised])
    return {
        "accepted": 1,
        "source":   "cyberark",
        "message":  "PAM session queued for risk scoring.",
    }


@router.post("/event")
async def ingest_generic_event(
    event: GenericPAMEvent,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Generic PAM event ingest — easiest integration point.
    Any internal agent, script, or middleware can POST here.

    Example (curl):
      curl -X POST http://panoptes:8000/api/ingest/event \\
        -H "Content-Type: application/json" \\
        -d '{"user_id":"emp_001","user_name":"Rajan Shah",
             "target_system":"CORE_BANKING_DB","action":"EXPORT",
             "timestamp":"2024-01-15T02:34:00","privilege_level":"HIGH"}'
    """
    try:
        dt = datetime.datetime.fromisoformat(event.timestamp)
        login_hour = dt.hour
    except Exception:
        login_hour = datetime.datetime.utcnow().hour

    normalised = NormalisedEvent(
        identity_id=event.user_id,
        identity_name=event.user_name,
        identity_type=event.user_type,
        peer_group=_guess_peer_group(event.target_system, event.user_type),
        target_system=event.target_system.upper(),
        source_ip=event.source_ip,
        actions=[event.action, "LOGOUT"] if event.action != "LOGOUT" else ["LOGIN", "LOGOUT"],
        login_hour=login_hour,
        data_volume_mb=(event.data_volume_bytes or 0) / 1_000_000,
        privilege_level=event.privilege_level,
        raw_source="api",
        raw_payload=event.model_dump_json(),
    )
    background_tasks.add_task(_process_normalised_events, [normalised])
    return {
        "accepted": 1,
        "source":   "generic_api",
        "message":  "Event queued for risk scoring.",
    }


@router.post("/csv")
async def ingest_csv_upload(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Bulk CSV upload — for offline replay of historical logs.
    CSV format (header row required):
      user_id, user_name, user_type, target_system, source_ip,
      actions (pipe-separated), login_hour, data_volume_mb, privilege_level

    Example row:
      emp_001,Rajan Shah,employee,CORE_BANKING_DB,10.10.1.5,
      LOGIN|QUERY|EXPORT|LOGOUT,2,450.0,HIGH
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(400, "Only .csv files accepted")

    content = await file.read()
    text = content.decode("utf-8")
    reader = csv.DictReader(io.StringIO(text))

    events = []
    errors = []
    for i, row in enumerate(reader):
        try:
            actions_str = row.get("actions", "LOGIN|LOGOUT")
            actions = [a.strip() for a in actions_str.split("|") if a.strip()]
            events.append(NormalisedEvent(
                identity_id=row["user_id"].strip(),
                identity_name=row["user_name"].strip(),
                identity_type=row.get("user_type", "employee").strip(),
                peer_group=_guess_peer_group(row.get("target_system", ""), row.get("user_type", "employee")),
                target_system=row.get("target_system", "UNKNOWN").strip().upper(),
                source_ip=row.get("source_ip", "0.0.0.0").strip(),
                actions=actions,
                login_hour=int(row.get("login_hour", 9)),
                data_volume_mb=float(row.get("data_volume_mb", 0)),
                privilege_level=row.get("privilege_level", "LOW").strip(),
                raw_source="csv",
            ))
        except Exception as e:
            errors.append(f"Row {i+2}: {e}")

    background_tasks.add_task(_process_normalised_events, events)
    return {
        "accepted": len(events),
        "errors":   errors[:10],
        "source":   "csv_upload",
        "message":  f"{len(events)} events queued for risk scoring.",
    }


@router.get("/formats")
async def get_supported_formats():
    """Returns documentation of all supported ingestion formats."""
    return {
        "formats": [
            {
                "name": "Windows Event Log",
                "endpoint": "POST /api/ingest/windows-event",
                "description": "Batch of Windows Security Events from winlogbeat/WEF",
                "integration": "Deploy winlogbeat on DCs, configure output to this endpoint",
                "events_mapped": list(WINDOWS_EVENTID_ACTION.keys()),
            },
            {
                "name": "CEF / SIEM",
                "endpoint": "POST /api/ingest/cef",
                "description": "ArcSight Common Event Format from Splunk/QRadar",
                "integration": "Configure SIEM webhook to forward selected event types",
            },
            {
                "name": "CyberArk PAM",
                "endpoint": "POST /api/ingest/cyberark",
                "description": "CyberArk PAM session records via CPM webhook",
                "integration": "Configure CyberArk PVWA → Administration → System Configuration → Webhooks",
            },
            {
                "name": "Generic API",
                "endpoint": "POST /api/ingest/event",
                "description": "Single PAM event in simple JSON format",
                "integration": "Call from any agent, middleware, or script — easiest to integrate",
            },
            {
                "name": "CSV Batch",
                "endpoint": "POST /api/ingest/csv",
                "description": "Bulk historical log replay via CSV upload",
                "integration": "Export logs from SIEM/DB as CSV, upload for offline analysis",
            },
        ],
        "note": "All formats are normalized to the same internal schema before risk scoring. The ML models, OPA policy, and PQC audit layer behave identically regardless of source.",
    }


# ─── Async pipeline hook ──────────────────────────────────────────────────────
async def _process_normalised_events(events: List[NormalisedEvent]):
    """
    Pass normalised real-world events through the full PANOPTES risk pipeline.
    This is the bridge between real data ingestion and the same scoring
    engine used for synthetic events.
    """
    from backend.main import _process_session
    import random

    for ev in events:
        raw = {
            "session_id":    f"sess_{uuid.uuid4().hex[:12]}",
            "identity_id":   ev.identity_id,
            "identity_name": ev.identity_name,
            "identity_type": ev.identity_type,
            "peer_group":    ev.peer_group,
            "target_system": ev.target_system,
            "source_ip":     ev.source_ip,
            "actions":       json.dumps(ev.actions),
            "data_volume_mb": ev.data_volume_mb,
            "login_hour":    ev.login_hour,
            "duration_minutes": ev.duration_minutes,
            "privilege_level": ev.privilege_level,
            "start_time":    datetime.datetime.utcnow().isoformat(),
            "is_anomalous":  False,
            "anomaly_type":  "",
        }
        try:
            await _process_session(raw)
            logger.info("Ingested %s event: %s → %s", ev.raw_source, ev.identity_name, ev.target_system)
        except Exception as e:
            logger.error("Failed to process ingested event: %s", e)
