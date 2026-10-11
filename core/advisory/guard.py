"""
AI Advisory Anti-Bypass Guards (A-03, Section 11.5, 11.6, 13.3 & Requirement R9).
Enforces strict boundaries ensuring AI models can never trigger a security response alone.
"""

from typing import Dict, List, Set, Tuple, Any, Optional
from core.contracts import ResponseAction


class RuleValidationError(Exception):
    """Raised when a rule set violates validation or the AI advisory boundary."""
    pass


VALID_RESPONSES = {
    ResponseAction.NO_ACTION,
    ResponseAction.STEP_UP,
    ResponseAction.ANALYST_REVIEW,
    ResponseAction.REVOKE
}

KNOWN_SIGNALS = {
    "unfamiliar_device",
    "implausible_location_change",
    "unusual_hour",
    "sensitive_after_unfamiliar_login",
    "unfamiliar_location",
    "sensitive_action_chain",
    "failed_login_burst"
}


def extract_referenced_conditions(condition_dict: Dict[str, Any]) -> Tuple[Set[str], bool]:
    """
    Recursively extracts referenced signals and checks if advisory is referenced.
    Returns: (set_of_referenced_signals, has_advisory)
    """
    signals: Set[str] = set()
    has_advisory = False

    if "all" in condition_dict:
        for item in condition_dict["all"]:
            sigs, adv = extract_referenced_conditions(item)
            signals.update(sigs)
            has_advisory = has_advisory or adv

    if "any" in condition_dict:
        for item in condition_dict["any"]:
            sigs, adv = extract_referenced_conditions(item)
            signals.update(sigs)
            has_advisory = has_advisory or adv

    if "not" in condition_dict:
        sigs, adv = extract_referenced_conditions(condition_dict["not"])
        signals.update(sigs)
        has_advisory = has_advisory or adv

    if "signal" in condition_dict:
        signals.add(condition_dict["signal"])

    if "advisory" in condition_dict:
        has_advisory = True

    return signals, has_advisory


def validate_rule_set(rule_set_data: Dict[str, Any]) -> List[str]:
    """
    Section 11.5: Validates a rule set at load time.
    Rejects any rule violating R9 (advisory-only trigger).
    Returns a list of non-fatal warnings (e.g. shadowed rules).
    """
    rules = rule_set_data.get("rules", [])
    if not rules:
        raise RuleValidationError("Rule set contains no rules.")

    seen_ids: Set[str] = set()
    warnings: List[str] = []

    for rule in rules:
        r_id = rule.get("id")
        if not r_id:
            raise RuleValidationError("Rule missing required 'id' attribute.")
        if r_id in seen_ids:
            raise RuleValidationError(f"Duplicate rule id '{r_id}' found.")
        seen_ids.add(r_id)

        # Validate response action
        raw_resp = rule.get("response")
        try:
            resp_action = ResponseAction(raw_resp)
        except ValueError:
            raise RuleValidationError(
                f"Rule {r_id} has invalid response '{raw_resp}'. Must be one of {[r.value for r in VALID_RESPONSES]}."
            )

        if resp_action not in VALID_RESPONSES:
            raise RuleValidationError(f"Rule {r_id} has unsupported response action '{resp_action}'.")

        # Validate conditions
        when = rule.get("when", {})
        if not when:
            raise RuleValidationError(f"Rule {r_id} has no 'when' conditions.")

        signals_ref, has_advisory = extract_referenced_conditions(when)

        # R9 Compile-Time Advisory Guard
        # A rule that mentions the advisory must include at least one deterministic signal condition!
        if has_advisory and len(signals_ref) == 0:
            raise RuleValidationError(
                f"Rule {r_id} violates Requirement R9: mentions AI advisory but includes NO deterministic signals. "
                "AI cannot decide alone."
            )

        # Verify referenced signals exist
        for s in signals_ref:
            if s not in KNOWN_SIGNALS:
                raise RuleValidationError(f"Rule {r_id} references unknown signal '{s}'.")

    return warnings


class RuntimeAdvisoryGuard:
    """
    Section 11.6: Run-time advisory circuit breaker.
    Verifies that no decision was made solely because of the AI advisory.
    """

    @staticmethod
    def verify_runtime_execution(
        fired_rule_id: Optional[str],
        matched_conditions: Dict[str, bool],
        deterministic_signals_triggered: List[str]
    ) -> Tuple[bool, Optional[str]]:
        """
        Returns: (is_valid, suppression_reason)
        If invalid, response must be forced to no_action and recorded.
        """
        if not fired_rule_id:
            return True, None

        has_advisory_match = matched_conditions.get("advisory:sequence_anomalous", False)

        # If advisory matched, verify that at least one deterministic signal supported the firing
        if has_advisory_match and len(deterministic_signals_triggered) == 0:
            return False, "Advisory-only match suppressed: rule firing lacked deterministic signal support (R9 violation prevented)."

        return True, None
