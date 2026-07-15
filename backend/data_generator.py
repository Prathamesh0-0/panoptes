"""
PANOPTES — Synthetic Data Generator
Generates realistic Bank of Maharashtra-style PAM/IAM logs.
Injects 8 labeled anomaly scenarios for demo and validation.
"""
import random
import json
import uuid
import math
import datetime
from typing import List, Dict, Any

random.seed(42)

# ─────────────────────────────────────────────────────────────────────────────
# PEER GROUP DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────
PEER_GROUPS = {
    "DB_ADMIN": {
        "count": 10,
        "identity_type": "employee",
        "login_hour_mean": 9.0,
        "login_hour_std": 1.2,
        "session_duration_mean": 90.0,
        "session_duration_std": 30.0,
        "data_volume_mean": 450.0,
        "data_volume_std": 150.0,
        "allowed_systems": ["CORE_BANKING_DB", "REPORTING_DB", "BACKUP_DB", "AUDIT_DB"],
        "typical_systems": ["CORE_BANKING_DB", "REPORTING_DB"],
        "normal_actions": ["LOGIN", "QUERY", "MODIFY", "BACKUP", "LOGOUT"],
        "normal_sequences": [
            ["LOGIN", "QUERY", "QUERY", "MODIFY", "LOGOUT"],
            ["LOGIN", "BACKUP", "VERIFY", "LOGOUT"],
            ["LOGIN", "QUERY", "EXPORT", "LOGOUT"],
            ["LOGIN", "QUERY", "QUERY", "QUERY", "LOGOUT"],
        ],
        "privilege_level": "HIGH",
        "dept": "IT Operations",
    },
    "NETWORK_ADMIN": {
        "count": 10,
        "identity_type": "employee",
        "login_hour_mean": 8.5,
        "login_hour_std": 1.5,
        "session_duration_mean": 75.0,
        "session_duration_std": 25.0,
        "data_volume_mean": 100.0,
        "data_volume_std": 60.0,
        "allowed_systems": ["NETWORK_INFRA", "FIREWALL_MGMT", "MONITORING_DB", "BACKUP_DB"],
        "typical_systems": ["NETWORK_INFRA", "FIREWALL_MGMT"],
        "normal_actions": ["LOGIN", "QUERY", "MODIFY", "VERIFY", "BACKUP", "LATERAL", "LOGOUT"],
        "normal_sequences": [
            ["LOGIN", "QUERY", "MODIFY", "VERIFY", "LOGOUT"],
            ["LOGIN", "BACKUP", "LATERAL", "BACKUP", "LOGOUT"],
            ["LOGIN", "QUERY", "VERIFY", "LOGOUT"],
        ],
        "privilege_level": "HIGH",
        "dept": "Network & Infrastructure",
    },
    "BRANCH_STAFF": {
        "count": 10,
        "identity_type": "employee",
        "login_hour_mean": 9.5,
        "login_hour_std": 0.8,
        "session_duration_mean": 45.0,
        "session_duration_std": 15.0,
        "data_volume_mean": 50.0,
        "data_volume_std": 30.0,
        "allowed_systems": ["CORE_BANKING_DB", "CUSTOMER_DB", "REPORTING_DB"],
        "typical_systems": ["CUSTOMER_DB", "REPORTING_DB"],
        "normal_actions": ["LOGIN", "QUERY", "MODIFY", "LOGOUT"],
        "normal_sequences": [
            ["LOGIN", "QUERY", "MODIFY", "LOGOUT"],
            ["LOGIN", "QUERY", "LOGOUT"],
            ["LOGIN", "QUERY", "QUERY", "MODIFY", "LOGOUT"],
        ],
        "privilege_level": "LOW",
        "dept": "Branch Operations",
    },
    "IT_CONTRACTOR": {
        "count": 10,
        "identity_type": "contractor",
        "login_hour_mean": 10.0,
        "login_hour_std": 1.0,
        "session_duration_mean": 60.0,
        "session_duration_std": 20.0,
        "data_volume_mean": 80.0,
        "data_volume_std": 40.0,
        "allowed_systems": ["TEST_ENV", "MONITORING_DB", "REPORTING_DB"],
        "typical_systems": ["TEST_ENV", "MONITORING_DB"],
        "normal_actions": ["LOGIN", "QUERY", "VERIFY", "LOGOUT"],
        "normal_sequences": [
            ["LOGIN", "QUERY", "LOGOUT"],
            ["LOGIN", "VERIFY", "LOGOUT"],
            ["LOGIN", "QUERY", "VERIFY", "LOGOUT"],
        ],
        "privilege_level": "LOW",
        "dept": "External — IT Services",
    },
    "FINANCE_ANALYST": {
        "count": 10,
        "identity_type": "employee",
        "login_hour_mean": 9.0,
        "login_hour_std": 1.0,
        "session_duration_mean": 80.0,
        "session_duration_std": 20.0,
        "data_volume_mean": 300.0,
        "data_volume_std": 120.0,
        "allowed_systems": ["FOREX_DB", "REPORTING_DB", "CUSTOMER_DB"],
        "typical_systems": ["FOREX_DB", "REPORTING_DB"],
        "normal_actions": ["LOGIN", "QUERY", "EXPORT", "LOGOUT"],
        "normal_sequences": [
            ["LOGIN", "QUERY", "EXPORT", "LOGOUT"],
            ["LOGIN", "QUERY", "QUERY", "EXPORT", "LOGOUT"],
            ["LOGIN", "QUERY", "LOGOUT"],
        ],
        "privilege_level": "MEDIUM",
        "dept": "Treasury & Finance",
    },
}

INDIAN_FIRST_NAMES = [
    "Arjun", "Priya", "Rahul", "Ananya", "Vikram", "Deepa", "Suresh", "Kavita",
    "Amit", "Pooja", "Rajesh", "Sunita", "Nikhil", "Meera", "Sanjay", "Rekha",
    "Aakash", "Divya", "Pranav", "Sneha", "Kiran", "Nisha", "Rohan", "Anjali",
    "Mohit", "Geeta", "Vishal", "Shreya", "Anil", "Preeti", "Tarun", "Ritu",
    "Harsh", "Bhavna", "Yash", "Alka", "Dev", "Shweta", "Manu", "Varsha",
    "Sandeep", "Usha", "Gaurav", "Seema", "Akash", "Rani", "Pankaj", "Lata",
    "Dinesh", "Hema",
]

INDIAN_LAST_NAMES = [
    "Sharma", "Patel", "Singh", "Kumar", "Joshi", "Gupta", "Mehta", "Verma",
    "Rao", "Nair", "Iyer", "Desai", "Chaudhary", "Pandey", "Shukla", "Mishra",
    "Kulkarni", "Patil", "More", "Jadhav", "Sawant", "Kadam", "Pawar", "Mane",
    "Gaikwad", "Kale", "Subramaniam", "Krishnan", "Pillai", "Menon", "Reddy",
    "Naidu", "Yadav", "Tiwari", "Dwivedi", "Tripathi", "Bhat", "Hegde",
    "Anand", "Saxena", "Aggarwal", "Bansal", "Goel", "Arora", "Batra",
    "Khanna", "Malhotra", "Chopra", "Sethi", "Kapoor",
]

ASSET_CRITICALITY = {
    "CORE_BANKING_DB": 1.0,
    "AUDIT_DB": 0.95,
    "CUSTOMER_DB": 0.90,
    "FOREX_DB": 0.85,
    "NETWORK_INFRA": 0.80,
    "FIREWALL_MGMT": 0.80,
    "BACKUP_DB": 0.70,
    "REPORTING_DB": 0.60,
    "MONITORING_DB": 0.50,
    "HR_DB": 0.50,
    "TEST_ENV": 0.20,
}

ACTION_SENSITIVITY = {
    "DELETE": 1.0,
    "ESCALATE": 0.95,
    "LATERAL": 0.85,
    "EXPORT": 0.90,
    "MODIFY": 0.65,
    "BACKUP": 0.55,
    "VERIFY": 0.30,
    "QUERY": 0.25,
    "LOGIN": 0.10,
    "LOGOUT": 0.05,
}

# ─────────────────────────────────────────────────────────────────────────────
# ANOMALY SCENARIOS
# ─────────────────────────────────────────────────────────────────────────────
ANOMALY_SCENARIOS = [
    {
        "type": "OFF_HOURS_BULK_EXPORT",
        "label": "Off-Hours Bulk Data Export",
        "peer_group": "DB_ADMIN",
        "login_hour": 2,
        "target_system": "CORE_BANKING_DB",
        "actions": ["LOGIN", "ESCALATE", "EXPORT", "EXPORT", "EXPORT", "LOGOUT"],
        "data_volume_mb": 2400.0,
        "duration_minutes": 35.0,
    },
    {
        "type": "PRIVILEGE_ESCALATION_CHAIN",
        "label": "Privilege Escalation Chain",
        "peer_group": "BRANCH_STAFF",
        "login_hour": 14,
        "target_system": "CORE_BANKING_DB",
        "actions": ["LOGIN", "ESCALATE", "ESCALATE", "QUERY", "EXPORT", "LOGOUT"],
        "data_volume_mb": 800.0,
        "duration_minutes": 22.0,
    },
    {
        "type": "CONTRACTOR_SCOPE_VIOLATION",
        "label": "Contractor Scope Violation",
        "peer_group": "IT_CONTRACTOR",
        "login_hour": 11,
        "target_system": "CORE_BANKING_DB",
        "actions": ["LOGIN", "QUERY", "MODIFY", "EXPORT", "LOGOUT"],
        "data_volume_mb": 600.0,
        "duration_minutes": 18.0,
    },
    {
        "type": "LATERAL_MOVEMENT",
        "label": "Lateral Movement Detected",
        "peer_group": "NETWORK_ADMIN",
        "login_hour": 3,
        "target_system": "CORE_BANKING_DB",
        "actions": ["LOGIN", "LATERAL", "LATERAL", "LATERAL", "ESCALATE", "QUERY", "LOGOUT"],
        "data_volume_mb": 200.0,
        "duration_minutes": 12.0,
    },
    {
        "type": "MASS_DELETION",
        "label": "Mass Deletion Event",
        "peer_group": "DB_ADMIN",
        "login_hour": 23,
        "target_system": "CUSTOMER_DB",
        "actions": ["LOGIN", "ESCALATE", "DELETE", "DELETE", "DELETE", "DELETE", "LOGOUT"],
        "data_volume_mb": 1800.0,
        "duration_minutes": 8.0,
    },
    {
        "type": "SHADOW_ADMIN_CREATION",
        "label": "Shadow Admin Account Created",
        "peer_group": "DB_ADMIN",
        "login_hour": 1,
        "target_system": "AUDIT_DB",
        "actions": ["LOGIN", "ESCALATE", "MODIFY", "MODIFY", "LOGOUT"],
        "data_volume_mb": 10.0,
        "duration_minutes": 6.0,
    },
    {
        "type": "DATA_EXFILTRATION_PREP",
        "label": "Data Exfiltration Preparation",
        "peer_group": "FINANCE_ANALYST",
        "login_hour": 21,
        "target_system": "FOREX_DB",
        "actions": ["LOGIN", "QUERY", "QUERY", "QUERY", "QUERY", "QUERY", "QUERY", "EXPORT", "LOGOUT"],
        "data_volume_mb": 1200.0,
        "duration_minutes": 45.0,
    },
    {
        "type": "CREDENTIAL_STUFFING",
        "label": "Credential Stuffing + Successful Login",
        "peer_group": "BRANCH_STAFF",
        "login_hour": 4,
        "target_system": "CUSTOMER_DB",
        "actions": ["LOGIN", "QUERY", "EXPORT", "LOGOUT"],
        "data_volume_mb": 450.0,
        "duration_minutes": 20.0,
        "failed_logins_prior": 15,
    },
]

IP_PREFIXES = ["10.0.", "192.168.", "172.16.", "10.10."]


def _random_ip():
    prefix = random.choice(IP_PREFIXES)
    return f"{prefix}{random.randint(1,254)}.{random.randint(1,254)}"


def _jitter(value, std, min_val=0, max_val=None):
    result = value + random.gauss(0, std)
    result = max(min_val, result)
    if max_val is not None:
        result = min(max_val, result)
    return result


class SyntheticDataGenerator:

    def __init__(self):
        self._name_pool = list(zip(
            random.sample(INDIAN_FIRST_NAMES, len(INDIAN_FIRST_NAMES)),
            random.sample(INDIAN_LAST_NAMES, len(INDIAN_LAST_NAMES)),
        ))
        self._name_idx = 0
        self.identities: List[Dict] = []
        self.historical_sessions: List[Dict] = []

    def _next_name(self):
        first, last = self._name_pool[self._name_idx % len(self._name_pool)]
        self._name_idx += 1
        return f"{first} {last}"

    def generate_identities(self) -> List[Dict]:
        identities = []
        idx = 0
        for peer_group, cfg in PEER_GROUPS.items():
            for i in range(cfg["count"]):
                uid = f"usr_{peer_group[:3].lower()}_{idx:03d}"
                tenure = round(random.uniform(0.5, 12.0), 1)
                identities.append({
                    "id": uid,
                    "name": self._next_name(),
                    "role": peer_group,
                    "department": cfg["dept"],
                    "identity_type": cfg["identity_type"],
                    "peer_group": peer_group,
                    "cluster_id": 0,  # set after KMeans
                    "tenure_years": tenure,
                    "normal_login_hour_mean": cfg["login_hour_mean"],
                    "normal_login_hour_std": cfg["login_hour_std"],
                    "normal_session_duration_mean": cfg["session_duration_mean"],
                    "normal_data_volume_mean": cfg["data_volume_mean"],
                    "allowed_systems": json.dumps(cfg["allowed_systems"]),
                })
                idx += 1
        self.identities = identities
        return identities

    def generate_historical_sessions(self, days: int = 30) -> List[Dict]:
        """Generate N days of normal session history for all identities."""
        sessions = []
        base_date = datetime.datetime.utcnow() - datetime.timedelta(days=days)

        for identity in self.identities:
            pg = identity["peer_group"]
            cfg = PEER_GROUPS[pg]
            sessions_per_day = random.randint(1, 3)

            for day in range(days):
                for _ in range(sessions_per_day):
                    session_date = base_date + datetime.timedelta(days=day)
                    login_hour = int(_jitter(cfg["login_hour_mean"], cfg["login_hour_std"], 6, 20))
                    session_dt = session_date.replace(
                        hour=login_hour,
                        minute=random.randint(0, 59),
                        second=0, microsecond=0
                    )
                    duration = _jitter(cfg["session_duration_mean"], cfg["session_duration_std"], 5, 300)
                    data_vol = _jitter(cfg["data_volume_mean"], cfg["data_volume_std"], 0)
                    target = random.choice(cfg["typical_systems"])
                    action_seq = random.choice(cfg["normal_sequences"])

                    sessions.append({
                        "session_id": f"sess_{uuid.uuid4().hex[:12]}",
                        "identity_id": identity["id"],
                        "identity_name": identity["name"],
                        "peer_group": pg,
                        "identity_type": identity["identity_type"],
                        "start_time": session_dt.isoformat(),
                        "target_system": target,
                        "privilege_level": cfg["privilege_level"],
                        "source_ip": _random_ip(),
                        "actions": json.dumps(action_seq),
                        "data_volume_mb": round(data_vol, 1),
                        "login_hour": login_hour,
                        "duration_minutes": round(duration, 1),
                        "is_anomalous": False,
                        "anomaly_type": "",
                        # Pre-filled low scores for historical normal data
                        "behavioral_score": round(random.uniform(0.02, 0.18), 3),
                        "sequence_score": round(random.uniform(0.02, 0.15), 3),
                        "asset_criticality": ASSET_CRITICALITY.get(target, 0.5),
                        "action_sensitivity": max(
                            ACTION_SENSITIVITY.get(a, 0.2) for a in action_seq
                        ),
                        "risk_score": round(random.uniform(3, 28), 1),
                        "risk_label": "LOW",
                        "policy_action": "LOG_ONLY",
                        "policy_reason": "Normal behavior within peer-group baseline.",
                        "policy_severity": "LOW",
                        "explanation": json.dumps({
                            "summary": "Session within normal parameters.",
                            "reasons": [],
                            "recommendation": "No action required.",
                        }),
                    })

        self.historical_sessions = sessions
        return sessions

    def build_live_event(self, inject_anomaly: bool = False) -> Dict:
        """Build a single new event for the live streaming demo."""
        if inject_anomaly and self.identities:
            return self._inject_anomaly_event()
        return self._build_normal_event()

    def _build_normal_event(self) -> Dict:
        identity = random.choice(self.identities)
        pg = identity.get("peer_group", "UNKNOWN")
        
        # Fallback for CERT dataset roles
        if pg in PEER_GROUPS:
            cfg = PEER_GROUPS[pg]
        else:
            allowed = identity.get("allowed_systems")
            if isinstance(allowed, str):
                try:
                    sys_list = json.loads(allowed)
                except:
                    sys_list = ["PC-0000"]
            else:
                sys_list = allowed or ["PC-0000"]
                
            cfg = {
                "session_duration_mean": 45.0,
                "session_duration_std": 15.0,
                "data_volume_mean": 20.0,
                "data_volume_std": 10.0,
                "typical_systems": sys_list if sys_list else ["PC-0000"],
                "normal_sequences": [["LOGIN", "FILE_ACCESS", "FILE_ACCESS", "LOGOUT"]],
                "privilege_level": "LOW",
            }

        now = datetime.datetime.utcnow()
        login_hour = now.hour
        duration = _jitter(cfg["session_duration_mean"], cfg["session_duration_std"], 5, 300)
        data_vol = _jitter(cfg["data_volume_mean"], cfg["data_volume_std"], 0)
        target = random.choice(cfg["typical_systems"])
        action_seq = random.choice(cfg["normal_sequences"])

        return {
            "session_id": f"sess_{uuid.uuid4().hex[:12]}",
            "identity_id": identity["id"],
            "identity_name": identity["name"],
            "peer_group": pg,
            "identity_type": identity.get("identity_type", "employee"),
            "start_time": now.isoformat(),
            "target_system": target,
            "privilege_level": cfg["privilege_level"],
            "source_ip": _random_ip(),
            "actions": json.dumps(action_seq),
            "data_volume_mb": round(data_vol, 1),
            "login_hour": login_hour,
            "duration_minutes": round(duration, 1),
            "is_anomalous": False,
            "anomaly_type": "",
        }

    def _inject_anomaly_event(self) -> Dict:
        scenario = random.choice(ANOMALY_SCENARIOS)
        
        # In CERT data, we might not have the specific peer_group. Just pick any.
        candidates = [i for i in self.identities if i.get("peer_group") == scenario["peer_group"]]
        identity = random.choice(candidates) if candidates else random.choice(self.identities)

        now = datetime.datetime.utcnow()
        session_dt = now.replace(hour=scenario["login_hour"], minute=random.randint(0, 59))

        return {
            "session_id": f"sess_{uuid.uuid4().hex[:12]}",
            "identity_id": identity["id"],
            "identity_name": identity["name"],
            "peer_group": identity.get("peer_group", "UNKNOWN"),
            "identity_type": identity.get("identity_type", "employee"),
            "start_time": session_dt.isoformat(),
            "target_system": scenario["target_system"],
            "privilege_level": "HIGH" if "ADMIN" in identity.get("peer_group", "").upper() else "LOW",
            "source_ip": _random_ip(),
            "actions": json.dumps(scenario["actions"]),
            "data_volume_mb": scenario["data_volume_mb"],
            "login_hour": scenario["login_hour"],
            "duration_minutes": scenario["duration_minutes"],
            "is_anomalous": True,
            "anomaly_type": scenario["type"],
        }


# Singleton
generator = SyntheticDataGenerator()
