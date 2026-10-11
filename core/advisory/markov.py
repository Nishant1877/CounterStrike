"""
AI Advisory Module: Action Sequence Markov Chain Model (A-03, Section 13).
Computes blended sequence anomaly score over session action transitions.
Output is strictly advisory and carries advisory: True.
"""

from __future__ import annotations
import math
from typing import Dict, List, Optional, Tuple, Any
from core.contracts import AdvisoryResult

# Global base-rate transition matrix representing typical banking user sequences
DEFAULT_GLOBAL_TRANSITIONS: Dict[str, Dict[str, float]] = {
    "login": {
        "view_balance": 0.65,
        "view_statement": 0.15,
        "view_profile": 0.10,
        "search": 0.05,
        "change_email": 0.02,
        "change_password": 0.01,
        "request_transfer": 0.01,
        "add_payee": 0.01,
    },
    "view_balance": {
        "view_statement": 0.40,
        "request_transfer": 0.25,
        "search": 0.15,
        "view_profile": 0.10,
        "logout": 0.10,
    },
    "view_statement": {
        "view_balance": 0.40,
        "request_transfer": 0.30,
        "logout": 0.20,
        "export_data": 0.10,
    },
    "change_email": {
        "view_profile": 0.40,
        "logout": 0.30,
        "view_balance": 0.25,
        "request_transfer": 0.01,  # Highly anomalous transition
        "change_password": 0.04,
    },
    "change_password": {
        "logout": 0.60,
        "view_profile": 0.25,
        "view_balance": 0.14,
        "request_transfer": 0.01,  # Highly anomalous transition
    },
    "add_payee": {
        "request_transfer": 0.50,
        "view_balance": 0.30,
        "logout": 0.20,
    },
    "request_transfer": {
        "view_balance": 0.50,
        "view_statement": 0.30,
        "logout": 0.20,
    },
}

# Known high-risk action chains that raise anomaly suspicion
RISKY_PATTERNS = [
    ["change_email", "request_transfer"],
    ["change_password", "request_transfer"],
    ["change_email", "change_password", "request_transfer"],
    ["login", "change_email", "request_transfer"],
]


class MarkovSequenceAdvisor:
    """Action sequence anomaly scorer based on blended Markov transitions."""

    def __init__(
        self,
        global_transitions: Optional[Dict[str, Dict[str, float]]] = None,
        min_sessions_for_evidence: int = 3,
        saturation_sessions: int = 20
    ):
        self.global_matrix = global_transitions or DEFAULT_GLOBAL_TRANSITIONS
        self.min_sessions = min_sessions_for_evidence
        self.saturation_sessions = saturation_sessions

    def get_transition_prob(
        self,
        prev_act: str,
        curr_act: str,
        user_transitions: Dict[str, Dict[str, int]],
        lambda_blend: float
    ) -> Tuple[float, int, int]:
        """
        Blends user transition frequency with global prior:
        P = lambda * P_user + (1 - lambda) * P_global
        Returns: (probability, user_pair_count, user_prev_total)
        """
        # User frequency
        user_prev_counts = user_transitions.get(prev_act, {})
        user_prev_total = sum(user_prev_counts.values())
        user_pair_count = user_prev_counts.get(curr_act, 0)

        p_user = (user_pair_count / user_prev_total) if user_prev_total > 0 else 0.0

        # Global frequency
        global_prev = self.global_matrix.get(prev_act, {})
        p_global = global_prev.get(curr_act, 0.005)  # Epsilon laplace smoothing

        # Blend
        blended = lambda_blend * p_user + (1.0 - lambda_blend) * p_global
        return max(blended, 0.001), user_pair_count, user_prev_total

    def evaluate_sequence(
        self,
        session_actions: List[str],
        user_session_count: int,
        user_transitions: Dict[str, Dict[str, int]]
    ) -> AdvisoryResult:
        """
        Evaluates the session's action sequence so far.
        Returns standardized AdvisoryResult.
        """
        evidence_str = f"{user_session_count} earlier sessions evaluated"

        # Cold start check: below minimum sessions (Section 13.4)
        if user_session_count < self.min_sessions:
            return AdvisoryResult(
                advisory=True,
                label="not evaluable",
                score=0.0,
                top_transitions=[],
                reason=f"Fewer than {self.min_sessions} earlier sessions ({user_session_count} seen); sequence baseline is not evaluable.",
                evidence=evidence_str,
                model_version="markov-v1"
            )

        if len(session_actions) < 2:
            return AdvisoryResult(
                advisory=True,
                label="typical",
                score=0.0,
                top_transitions=[],
                reason="Single action in session so far; sequence is normal.",
                evidence=evidence_str,
                model_version="markov-v1"
            )

        # Compute dynamic lambda blending weight
        lambda_blend = min(1.0, user_session_count / float(self.saturation_sessions))

        # Score transitions along the sequence
        transition_details = []
        log_prob_sum = 0.0

        for i in range(1, len(session_actions)):
            prev_a = session_actions[i - 1]
            curr_a = session_actions[i]

            prob, user_cnt, user_tot = self.get_transition_prob(
                prev_a, curr_a, user_transitions, lambda_blend
            )
            log_prob_sum += math.log(prob)

            transition_details.append({
                "transition": f"{prev_a} -> {curr_a}",
                "prob": round(prob, 4),
                "user_count": f"{user_cnt} of {user_tot}"
            })

        # Average transition log likelihood
        n_steps = len(session_actions) - 1
        avg_log_prob = log_prob_sum / n_steps

        # Map log-prob to [0.0, 1.0] anomaly score (lower prob -> higher anomaly score)
        # log(0.001) ~ -6.91 (highly anomalous), log(0.5) ~ -0.69 (typical)
        anomaly_score = min(1.0, max(0.0, (-avg_log_prob - 0.7) / 5.0))
        anomaly_score = round(anomaly_score, 2)

        # Check for explicitly matching risky patterns
        has_risky_chain = False
        risky_chain_name = ""
        actions_str = " -> ".join(session_actions)
        for pattern in RISKY_PATTERNS:
            p_str = " -> ".join(pattern)
            if p_str in actions_str:
                has_risky_chain = True
                risky_chain_name = p_str
                anomaly_score = max(anomaly_score, 0.88)
                break

        # Categorize label
        if anomaly_score >= 0.75 or has_risky_chain:
            label = "suspicious"
        elif anomaly_score >= 0.45:
            label = "unusual"
        else:
            label = "typical"

        # Find least likely transition for explanation
        least_likely = min(transition_details, key=lambda t: t["prob"])
        least_trans = least_likely["transition"]
        prev_act, next_act = least_trans.split(" -> ")

        if has_risky_chain:
            reason = f"Recognized known high-risk attack sequence pattern: '{risky_chain_name}'."
        else:
            reason = (
                f"Action sequence scored {anomaly_score:.2f} ({label}). "
                f"Transition '{prev_act}' -> '{next_act}' occurred in {least_likely['user_count']} prior sessions."
            )

        # Sort transitions by lowest probability
        top_anomalous_transitions = sorted(transition_details, key=lambda t: t["prob"])[:3]

        return AdvisoryResult(
            advisory=True,
            label=label,
            score=anomaly_score,
            top_transitions=top_anomalous_transitions,
            reason=reason,
            evidence=evidence_str,
            model_version="markov-v1"
        )
