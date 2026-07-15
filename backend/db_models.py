"""
PANOPTES — SQLAlchemy ORM models
"""
import datetime
import json
from sqlalchemy import String, Float, Integer, Boolean, Text, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from backend.database import Base


def _now():
    return datetime.datetime.utcnow()


class Identity(Base):
    __tablename__ = "identities"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(64))          # DB_ADMIN, NETWORK_ADMIN, …
    department: Mapped[str] = mapped_column(String(64))
    identity_type: Mapped[str] = mapped_column(String(32)) # employee | contractor
    peer_group: Mapped[str] = mapped_column(String(64))
    cluster_id: Mapped[int] = mapped_column(Integer, default=0)
    tenure_years: Mapped[float] = mapped_column(Float, default=1.0)
    normal_login_hour_mean: Mapped[float] = mapped_column(Float, default=9.0)
    normal_login_hour_std: Mapped[float] = mapped_column(Float, default=1.5)
    normal_session_duration_mean: Mapped[float] = mapped_column(Float, default=60.0)
    normal_data_volume_mean: Mapped[float] = mapped_column(Float, default=200.0)
    allowed_systems: Mapped[str] = mapped_column(Text, default="[]")  # JSON list
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=_now)

    def allowed_systems_list(self):
        return json.loads(self.allowed_systems)


class Session(Base):
    __tablename__ = "sessions"

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    identity_id: Mapped[str] = mapped_column(String(64))
    identity_name: Mapped[str] = mapped_column(String(128))
    peer_group: Mapped[str] = mapped_column(String(64))
    identity_type: Mapped[str] = mapped_column(String(32))
    start_time: Mapped[datetime.datetime] = mapped_column(DateTime)
    target_system: Mapped[str] = mapped_column(String(64))
    privilege_level: Mapped[str] = mapped_column(String(32))
    source_ip: Mapped[str] = mapped_column(String(64))
    actions: Mapped[str] = mapped_column(Text, default="[]")  # JSON list
    data_volume_mb: Mapped[float] = mapped_column(Float, default=0.0)
    login_hour: Mapped[int] = mapped_column(Integer, default=9)
    duration_minutes: Mapped[float] = mapped_column(Float, default=30.0)

    # Risk scores
    behavioral_score: Mapped[float] = mapped_column(Float, default=0.0)
    sequence_score: Mapped[float] = mapped_column(Float, default=0.0)
    asset_criticality: Mapped[float] = mapped_column(Float, default=0.5)
    action_sensitivity: Mapped[float] = mapped_column(Float, default=0.3)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_label: Mapped[str] = mapped_column(String(16), default="LOW")

    # OPA verdict
    policy_action: Mapped[str] = mapped_column(String(32), default="LOG_ONLY")
    policy_reason: Mapped[str] = mapped_column(Text, default="")
    policy_severity: Mapped[str] = mapped_column(String(16), default="LOW")

    # Explainability
    explanation: Mapped[str] = mapped_column(Text, default="{}")  # JSON

    # Ground truth (for demo validation)
    is_anomalous: Mapped[bool] = mapped_column(Boolean, default=False)
    anomaly_type: Mapped[str] = mapped_column(String(64), default="")

    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=_now)

    def actions_list(self):
        return json.loads(self.actions)

    def explanation_dict(self):
        return json.loads(self.explanation)


class Alert(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64))
    identity_id: Mapped[str] = mapped_column(String(64))
    identity_name: Mapped[str] = mapped_column(String(128))
    peer_group: Mapped[str] = mapped_column(String(64))
    risk_score: Mapped[float] = mapped_column(Float)
    risk_label: Mapped[str] = mapped_column(String(16))
    anomaly_type: Mapped[str] = mapped_column(String(64))
    policy_action: Mapped[str] = mapped_column(String(32))
    explanation_summary: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")  # ACTIVE | RESOLVED | REVIEWED
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime, default=_now)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    log_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64))
    session_id: Mapped[str] = mapped_column(String(64), default="")
    identity_id: Mapped[str] = mapped_column(String(64), default="")
    action_taken: Mapped[str] = mapped_column(String(32))
    details: Mapped[str] = mapped_column(Text)  # JSON
    signature: Mapped[str] = mapped_column(Text, default="")     # hex-encoded digital signature
    public_key: Mapped[str] = mapped_column(Text, default="")    # hex-encoded public key
    content_hash: Mapped[str] = mapped_column(String(64), default="")  # SHA-256 of canonical entry
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    tampered: Mapped[bool] = mapped_column(Boolean, default=False)
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime, default=_now)


class CredentialVault(Base):
    __tablename__ = "credential_vault"

    vault_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    label: Mapped[str] = mapped_column(String(128))
    owner_id: Mapped[str] = mapped_column(String(64))
    ciphertext_hex: Mapped[str] = mapped_column(Text)        # AES-GCM ciphertext
    kem_ciphertext_hex: Mapped[str] = mapped_column(Text)   # KEM encapsulated key
    public_key_hex: Mapped[str] = mapped_column(Text)
    kem_algorithm: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=_now)
