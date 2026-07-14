"""
PANOPTES — Peer-Group Behavioral Baseline Model
Uses KMeans clustering on behavioral feature vectors + per-cluster z-score deviation.
This is the #1 differentiator: an admin doing admin things ≠ anomaly.
"""
import json
import math
import logging
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from typing import List, Dict, Any, Optional

logger = logging.getLogger("panoptes.peer_group_model")

FEATURE_COLS = [
    "login_hour_mean",
    "login_hour_std",
    "session_duration_mean",
    "data_volume_mean",
    "action_diversity",     # unique action types / total actions
    "export_frequency",     # fraction of sessions with EXPORT
]

N_CLUSTERS = 5  # Matches the 5 peer groups


class PeerGroupModel:

    def __init__(self):
        self.kmeans: Optional[KMeans] = None
        self.scaler: Optional[StandardScaler] = None
        self.cluster_stats: Dict[int, Dict[str, Dict[str, float]]] = {}
        self.identity_cluster_map: Dict[str, int] = {}  # identity_id -> cluster_id
        self.cluster_to_peer_group: Dict[int, str] = {}
        self._trained = False

    def _extract_identity_features(self, sessions: List[Dict]) -> Dict[str, float]:
        """Aggregate sessions per identity into a behavioral feature vector."""
        if not sessions:
            return {col: 0.0 for col in FEATURE_COLS}

        login_hours = [s["login_hour"] for s in sessions]
        durations = [s["duration_minutes"] for s in sessions]
        volumes = [s["data_volume_mb"] for s in sessions]

        all_actions = []
        export_count = 0
        for s in sessions:
            acts = json.loads(s["actions"]) if isinstance(s["actions"], str) else s["actions"]
            all_actions.extend(acts)
            if "EXPORT" in acts or "DELETE" in acts:
                export_count += 1

        diversity = len(set(all_actions)) / max(len(all_actions), 1)
        export_freq = export_count / max(len(sessions), 1)

        return {
            "login_hour_mean": np.mean(login_hours),
            "login_hour_std": np.std(login_hours) if len(login_hours) > 1 else 1.0,
            "session_duration_mean": np.mean(durations),
            "data_volume_mean": np.mean(volumes),
            "action_diversity": diversity,
            "export_frequency": export_freq,
        }

    def train(self, identities: List[Dict], historical_sessions: List[Dict]) -> None:
        """
        Train the model:
        1. Group sessions by identity
        2. Build feature vectors per identity
        3. Run KMeans
        4. Compute per-cluster statistics for z-score scoring
        """
        # Group sessions by identity
        sessions_by_identity: Dict[str, List[Dict]] = {}
        for s in historical_sessions:
            iid = s["identity_id"]
            sessions_by_identity.setdefault(iid, []).append(s)

        # Build feature matrix
        identity_ids = []
        feature_rows = []
        peer_group_labels = []

        for identity in identities:
            iid = identity["id"]
            iid_sessions = sessions_by_identity.get(iid, [])
            features = self._extract_identity_features(iid_sessions)
            identity_ids.append(iid)
            feature_rows.append([features[col] for col in FEATURE_COLS])
            peer_group_labels.append(identity["peer_group"])

        if len(feature_rows) < N_CLUSTERS:
            logger.warning("Not enough identities to train KMeans. Using defaults.")
            self._trained = False
            return

        X = np.array(feature_rows)
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.kmeans = KMeans(n_clusters=N_CLUSTERS, random_state=42, n_init=10)
        labels = self.kmeans.fit_predict(X_scaled)

        # Map identity -> cluster
        for iid, cluster_id in zip(identity_ids, labels):
            self.identity_cluster_map[iid] = int(cluster_id)

        # Compute per-cluster stats (mean + std of each feature)
        for cluster_id in range(N_CLUSTERS):
            mask = labels == cluster_id
            cluster_X = X[mask]
            stats = {}
            for col_idx, col_name in enumerate(FEATURE_COLS):
                col_vals = cluster_X[:, col_idx]
                stats[col_name] = {
                    "mean": float(np.mean(col_vals)),
                    "std": float(np.std(col_vals)) if len(col_vals) > 1 else 1.0,
                }
            self.cluster_stats[cluster_id] = stats

            # Infer dominant peer group for this cluster
            cluster_peer_groups = [
                peer_group_labels[i]
                for i, lab in enumerate(labels)
                if lab == cluster_id
            ]
            if cluster_peer_groups:
                self.cluster_to_peer_group[cluster_id] = max(
                    set(cluster_peer_groups), key=cluster_peer_groups.count
                )

        self._trained = True
        logger.info(f"PeerGroupModel trained: {N_CLUSTERS} clusters, {len(identity_ids)} identities")

    def score_session(
        self,
        session: Dict,
        identity_id: str,
        peer_group: str,
    ) -> Dict[str, Any]:
        """
        Score a single session against the identity's cluster baseline.
        Returns: {behavioral_score, z_scores, deviations}
        """
        if not self._trained:
            return self._default_score(session, peer_group)

        cluster_id = self.identity_cluster_map.get(identity_id, 0)
        stats = self.cluster_stats.get(cluster_id, {})

        actions = json.loads(session["actions"]) if isinstance(session["actions"], str) else session["actions"]
        session_features = {
            "login_hour_mean": float(session.get("login_hour", 9)),
            "login_hour_std": 0.0,
            "session_duration_mean": float(session.get("duration_minutes", 30)),
            "data_volume_mean": float(session.get("data_volume_mb", 100)),
            "action_diversity": len(set(actions)) / max(len(actions), 1),
            "export_frequency": 1.0 if "EXPORT" in actions else 0.0,
        }

        z_scores = {}
        individual_scores = []
        deviations = {}

        for col in FEATURE_COLS:
            if col not in stats:
                continue
            cluster_mean = stats[col]["mean"]
            cluster_std = max(stats[col]["std"], 0.5)  # floor to avoid division by near-zero
            feat_val = session_features[col]
            z = abs(feat_val - cluster_mean) / cluster_std
            z_capped = min(z, 5.0)
            normalized = z_capped / 5.0  # [0, 1]

            z_scores[col] = round(z, 2)
            individual_scores.append(normalized)
            deviations[col] = {
                "value": round(feat_val, 2),
                "cluster_mean": round(cluster_mean, 2),
                "cluster_std": round(cluster_std, 2),
                "z_score": round(z, 2),
            }

        behavioral_score = float(np.mean(individual_scores)) if individual_scores else 0.1

        return {
            "behavioral_score": round(behavioral_score, 4),
            "cluster_id": cluster_id,
            "z_scores": z_scores,
            "deviations": deviations,
            "feature_values": session_features,
        }

    def _default_score(self, session: Dict, peer_group: str) -> Dict[str, Any]:
        """Fallback when model is not yet trained — use manual heuristics."""
        from backend.data_generator import PEER_GROUPS
        cfg = PEER_GROUPS.get(peer_group, {})
        login_hour = session.get("login_hour", 9)
        data_vol = session.get("data_volume_mb", 100)
        actions = json.loads(session["actions"]) if isinstance(session["actions"], str) else session.get("actions", [])

        lh_mean = cfg.get("login_hour_mean", 9.0)
        lh_std = cfg.get("login_hour_std", 1.5)
        vol_mean = cfg.get("data_volume_mean", 200.0)
        vol_std = cfg.get("data_volume_std", 100.0)

        z_hour = abs(login_hour - lh_mean) / max(lh_std, 0.5)
        z_vol = abs(data_vol - vol_mean) / max(vol_std, 50.0)
        z_export = 0.8 if ("EXPORT" in actions and "ESCALATE" in actions) else 0.0

        avg_z = (min(z_hour, 5) / 5 + min(z_vol, 5) / 5 + z_export) / 3
        return {
            "behavioral_score": round(avg_z, 4),
            "cluster_id": -1,
            "z_scores": {"login_hour_mean": round(z_hour, 2), "data_volume_mean": round(z_vol, 2)},
            "deviations": {},
            "feature_values": {},
        }

    def get_cluster_summary(self) -> List[Dict]:
        """Return cluster summaries for the PQC/model status page."""
        summaries = []
        for cid, stats in self.cluster_stats.items():
            summaries.append({
                "cluster_id": cid,
                "dominant_peer_group": self.cluster_to_peer_group.get(cid, "UNKNOWN"),
                "identity_count": sum(
                    1 for v in self.identity_cluster_map.values() if v == cid
                ),
                "feature_stats": stats,
            })
        return summaries


# Singleton
peer_group_model = PeerGroupModel()
