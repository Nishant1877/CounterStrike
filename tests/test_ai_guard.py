"""
Unit tests for AI Advisory Markov Model & Anti-Bypass Guard (Requirement R9).
Verifies that AI models can never trigger a response alone (at compile-time and runtime).
"""

import pytest
from core.advisory import MarkovSequenceAdvisor, validate_rule_set, RuntimeAdvisoryGuard, RuleValidationError
from core.contracts import AdvisoryResult, ResponseAction


def test_markov_advisor_typical_sequence():
    advisor = MarkovSequenceAdvisor()
    # Typical sequence: login -> view_balance -> view_statement
    actions = ["login", "view_balance", "view_statement"]
    user_transitions = {
        "login": {"view_balance": 15},
        "view_balance": {"view_statement": 10}
    }
    result = advisor.evaluate_sequence(actions, user_session_count=10, user_transitions=user_transitions)
    assert result.advisory is True
    assert result.label in {"typical", "unusual"}
    assert result.score < 0.70


def test_markov_advisor_suspicious_chain():
    advisor = MarkovSequenceAdvisor()
    # High-risk attack chain: change_email -> request_transfer
    actions = ["login", "change_email", "request_transfer"]
    user_transitions = {
        "login": {"change_email": 1},
        "change_email": {"view_profile": 10}  # Never followed by transfer
    }
    result = advisor.evaluate_sequence(actions, user_session_count=15, user_transitions=user_transitions)
    assert result.advisory is True
    assert result.label == "suspicious"
    assert result.score >= 0.75
    assert "known high-risk attack sequence pattern" in result.reason or "request_transfer" in result.reason


def test_markov_advisor_cold_start_not_evaluable():
    advisor = MarkovSequenceAdvisor(min_sessions_for_evidence=3)
    actions = ["login", "change_email"]
    # Only 1 prior session
    result = advisor.evaluate_sequence(actions, user_session_count=1, user_transitions={})
    assert result.label == "not evaluable"
    assert result.score == 0.0


def test_compile_time_guard_rejects_advisory_only_rule():
    # An unauthorized rule trying to trigger revoke solely based on the AI advisory
    bad_rule_set = {
        "version": "test",
        "rules": [
            {
                "id": "R-HACK",
                "name": "Bypass Rule",
                "when": {
                    "all": [
                        {"advisory": "sequence_anomalous", "is": True}
                    ]
                },
                "response": "revoke"
            }
        ]
    }
    with pytest.raises(RuleValidationError) as exc_info:
        validate_rule_set(bad_rule_set)
    assert "violates Requirement R9: mentions AI advisory but includes NO deterministic signals" in str(exc_info.value)


def test_compile_time_guard_permits_supported_advisory_rule():
    # Valid rule: mentions advisory AND at least one deterministic signal (R9 compliant)
    valid_rule_set = {
        "version": "test",
        "rules": [
            {
                "id": "R-09-TEST",
                "name": "Supported Advisory Rule",
                "when": {
                    "all": [
                        {"advisory": "sequence_anomalous", "is": True},
                        {"signal": "unfamiliar_device", "is": "triggered"}
                    ]
                },
                "response": "analyst_review"
            }
        ]
    }
    warnings = validate_rule_set(valid_rule_set)
    assert len(warnings) == 0


def test_runtime_guard_suppresses_advisory_firing_without_deterministic_support():
    matched_conditions = {"advisory:sequence_anomalous": True}
    # Zero deterministic signals triggered
    is_valid, reason = RuntimeAdvisoryGuard.verify_runtime_execution(
        fired_rule_id="R-TEST",
        matched_conditions=matched_conditions,
        deterministic_signals_triggered=[]
    )
    assert is_valid is False
    assert "Advisory-only match suppressed" in reason
    assert "R9 violation prevented" in reason
