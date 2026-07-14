"""
PANOPTES — Markov Chain Sequence Model
Scores action sequences by their log-probability under each peer group's
learned transition matrix. Flags low-probability sequences even when
individual actions look benign in isolation.
"""
import json
import math
import logging
from collections import defaultdict
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("panoptes.sequence_model")

# Minimum probability for unseen transitions (Laplace smoothing denominator)
LAPLACE_ALPHA = 0.1

# Normalization: expected log-probability of a "normal" sequence of length 5
# (tuned empirically on the normal training data)
NORMAL_LOG_PROB_BASELINE = -4.0
ANOMALY_LOG_PROB_FLOOR = -15.0  # Sequences worse than this → max anomaly score


class MarkovSequenceModel:

    def __init__(self):
        self.transition_counts: Dict[str, Dict[str, Dict[str, float]]] = {}  # pg → from → to → count
        self.transition_probs: Dict[str, Dict[str, Dict[str, float]]] = {}   # pg → from → to → prob
        self.start_probs: Dict[str, Dict[str, float]] = {}                    # pg → first_action → prob
        self._trained = False
        self._all_actions = set([
            "LOGIN", "QUERY", "EXPORT", "ESCALATE", "MODIFY",
            "DELETE", "BACKUP", "LATERAL", "VERIFY", "LOGOUT",
        ])

    def train(self, sessions_by_peer_group: Dict[str, List[Dict]]) -> None:
        """
        Build transition matrices from historical sessions, per peer group.
        Uses Laplace (add-alpha) smoothing so unseen transitions have low but
        non-zero probability.
        """
        raw_counts: Dict[str, Dict[str, Dict[str, float]]] = {}
        start_counts: Dict[str, Dict[str, float]] = {}

        for peer_group, sessions in sessions_by_peer_group.items():
            raw_counts[peer_group] = defaultdict(lambda: defaultdict(float))
            start_counts[peer_group] = defaultdict(float)

            for s in sessions:
                actions = json.loads(s["actions"]) if isinstance(s["actions"], str) else s["actions"]
                if not actions:
                    continue

                start_counts[peer_group][actions[0]] += 1

                for i in range(len(actions) - 1):
                    from_a = actions[i]
                    to_a = actions[i + 1]
                    raw_counts[peer_group][from_a][to_a] += 1

        # Normalize to probabilities with Laplace smoothing
        vocab = self._all_actions
        for peer_group in raw_counts:
            self.transition_probs[peer_group] = {}
            for from_a in vocab:
                to_counts = dict(raw_counts[peer_group].get(from_a, {}))
                total = sum(to_counts.values()) + LAPLACE_ALPHA * len(vocab)
                self.transition_probs[peer_group][from_a] = {
                    to_a: (to_counts.get(to_a, 0) + LAPLACE_ALPHA) / total
                    for to_a in vocab
                }

            # Normalize start probabilities
            total_start = sum(start_counts[peer_group].values()) + LAPLACE_ALPHA * len(vocab)
            self.start_probs[peer_group] = {
                a: (start_counts[peer_group].get(a, 0) + LAPLACE_ALPHA) / total_start
                for a in vocab
            }

        self._trained = True
        logger.info(f"MarkovSequenceModel trained for {len(raw_counts)} peer groups")

    def score(self, action_sequence: List[str], peer_group: str) -> Dict:
        """
        Compute anomaly score for the given action sequence.

        Returns:
          sequence_score    : float in [0, 1] — higher = more anomalous
          log_probability   : float (raw)
          sequence_display  : human-readable arrow notation
          flagged_transitions: list of surprising transitions
        """
        if not self._trained or peer_group not in self.transition_probs:
            return self._heuristic_score(action_sequence)

        if len(action_sequence) < 2:
            return {
                "sequence_score": 0.1,
                "log_probability": 0.0,
                "sequence_display": " → ".join(action_sequence),
                "flagged_transitions": [],
            }

        transitions = self.transition_probs[peer_group]
        start_p = self.start_probs.get(peer_group, {})

        log_prob = math.log(start_p.get(action_sequence[0], LAPLACE_ALPHA))
        flagged = []

        for i in range(len(action_sequence) - 1):
            from_a = action_sequence[i]
            to_a = action_sequence[i + 1]
            p = transitions.get(from_a, {}).get(to_a, LAPLACE_ALPHA)
            lp = math.log(p)
            log_prob += lp

            # Flag this transition if it's surprisingly unlikely
            if p < 0.05:
                flagged.append(f"{from_a} → {to_a} (p={p:.4f})")

        # Normalize by sequence length to make comparable across lengths
        normalized_log_prob = log_prob / len(action_sequence)

        # Map to [0, 1] anomaly score
        # NORMAL_LOG_PROB_BASELINE → score ≈ 0
        # ANOMALY_LOG_PROB_FLOOR  → score ≈ 1
        clamped = max(min(normalized_log_prob, NORMAL_LOG_PROB_BASELINE), ANOMALY_LOG_PROB_FLOOR)
        anomaly_score = (NORMAL_LOG_PROB_BASELINE - clamped) / (
            NORMAL_LOG_PROB_BASELINE - ANOMALY_LOG_PROB_FLOOR
        )

        return {
            "sequence_score": round(float(anomaly_score), 4),
            "log_probability": round(log_prob, 4),
            "sequence_display": " → ".join(action_sequence),
            "flagged_transitions": flagged,
        }

    def _heuristic_score(self, actions: List[str]) -> Dict:
        """Fallback heuristic when model is not trained."""
        HIGH_RISK = {"DELETE", "ESCALATE", "LATERAL"}
        risky_count = sum(1 for a in actions if a in HIGH_RISK)
        score = min(risky_count * 0.25, 0.95)
        return {
            "sequence_score": round(score, 4),
            "log_probability": -9999.0,
            "sequence_display": " → ".join(actions),
            "flagged_transitions": [a for a in actions if a in HIGH_RISK],
        }

    def get_top_transitions(self, peer_group: str, n: int = 10) -> List[Dict]:
        """Return the N most probable transitions for a peer group (for UI display)."""
        if peer_group not in self.transition_probs:
            return []
        transitions = self.transition_probs[peer_group]
        rows = []
        for from_a, to_dict in transitions.items():
            for to_a, prob in to_dict.items():
                rows.append({"from": from_a, "to": to_a, "probability": round(prob, 4)})
        rows.sort(key=lambda x: x["probability"], reverse=True)
        return rows[:n]


# Singleton
sequence_model = MarkovSequenceModel()
