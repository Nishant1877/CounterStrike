"""
Rule DSL Condition Evaluator (A-03, Section 11.2).
Evaluates nested boolean syntax trees over standardized SignalResults and AdvisoryResult.
"""

from typing import Dict, Any, Optional
from core.contracts import SignalResult, AdvisoryResult, SignalStatus


def evaluate_condition_node(
    node: Dict[str, Any],
    signals: Dict[str, SignalResult],
    advisory: Optional[AdvisoryResult] = None,
    extra_context: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Recursively evaluates a condition node in the rule AST.
    Supported primitives:
      - all: [list of conditions]
      - any: [list of conditions]
      - not: condition
      - signal: <name>, is: <status>
      - advisory: sequence_anomalous, is: true/false
      - challenge_result: <status>, is: true/false
    """
    ctx = extra_context or {}

    if "all" in node:
        return all(
            evaluate_condition_node(child, signals, advisory, ctx)
            for child in node["all"]
        )

    if "any" in node:
        return any(
            evaluate_condition_node(child, signals, advisory, ctx)
            for child in node["any"]
        )

    if "not" in node:
        return not evaluate_condition_node(node["not"], signals, advisory, ctx)

    # Deterministic signal evaluation
    if "signal" in node:
        sig_name = node["signal"]
        expected_status = str(node.get("is", "triggered")).lower()

        sig_result = signals.get(sig_name)
        if not sig_result:
            return False

        return sig_result.status.value.lower() == expected_status

    # Advisory condition evaluation
    if "advisory" in node:
        adv_cond = node["advisory"]
        expected_val = node.get("is", True)

        if adv_cond == "sequence_anomalous":
            if not advisory or advisory.label == "not evaluable":
                is_anomalous = False
            else:
                is_anomalous = advisory.label in {"unusual", "suspicious"}
            return is_anomalous == expected_val

    # Action or login check (for login-specific rules R-01, R-03, R-04, R-07)
    if "is_login" in node:
        actual_is_login = (ctx.get("action") == "login")
        return actual_is_login == node.get("is_login", True)

    if "action" in node:
        expected_action = node["action"]
        actual_action = ctx.get("action")
        return (actual_action == expected_action) == node.get("is", True)

    # Challenge result condition (e.g. for Rule R-10)
    if "challenge_result" in node:
        expected_status = node["challenge_result"]
        actual_status = ctx.get("challenge_result")
        is_match = (actual_status == expected_status)
        return is_match == node.get("is", True)

    return False
