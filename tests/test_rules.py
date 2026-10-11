"""
Unit tests for Declarative Rule Engine, Precedence, Fallbacks & Explanations (Stage 2).
"""

import pytest
from core.contracts import (
    SignalResult,
    SignalStatus,
    EvidenceLevel,
    ResponseAction,
    AdvisoryResult
)
from core.profile import UserProfile
from core.rules import RuleEngine
from core.explain import ExplanationGenerator


@pytest.fixture
def rule_engine():
    return RuleEngine("config/rules.yaml")


def make_dummy_signal(sig_id: str, name: str, status: SignalStatus, reason: str = "") -> SignalResult:
    return SignalResult(
        signal_id=sig_id,
        name=name,
        status=status,
        value=None,
        reference=None,
        reason=reason,
        evidence=EvidenceLevel.SUFFICIENT,
        inputs=[]
    )


def test_rule_engine_loads_default_yaml(rule_engine):
    assert len(rule_engine.rules) >= 11
    rule_ids = [r["id"] for r in rule_engine.rules]
    assert "R-01" in rule_ids
    assert "R-06" in rule_ids
    assert "R-11" in rule_ids


def test_r01_unfamiliar_device_alone_no_action(rule_engine):
    # Traveller or new device without second signal -> R-01 matches -> NO_ACTION
    signals = {
        "unfamiliar_device": make_dummy_signal("unfamiliar_device", "Unfamiliar device", SignalStatus.TRIGGERED, "Device never seen"),
        "implausible_location_change": make_dummy_signal("implausible_location_change", "Speed", SignalStatus.NOT_TRIGGERED),
        "unusual_hour": make_dummy_signal("unusual_hour", "Hour", SignalStatus.NOT_TRIGGERED),
        "sensitive_after_unfamiliar_login": make_dummy_signal("sensitive_after_unfamiliar_login", "Sensitive", SignalStatus.NOT_TRIGGERED)
    }
    res = rule_engine.evaluate(signals, evidence_level=EvidenceLevel.SUFFICIENT, extra_context={"action": "login"})
    assert res.deciding_rule_id == "R-01"
    assert res.final_response == ResponseAction.NO_ACTION


def test_r06_takeover_revoke_on_sufficient_evidence(rule_engine):
    # Sensitive action + speed violation on sufficient evidence -> R-06 fires -> REVOKE
    signals = {
        "sensitive_after_unfamiliar_login": make_dummy_signal(
            "sensitive_after_unfamiliar_login", "Sensitive action", SignalStatus.TRIGGERED, "change_email 4 min after login"
        ),
        "implausible_location_change": make_dummy_signal(
            "implausible_location_change", "Speed", SignalStatus.TRIGGERED, "Pune to London in 30 min (14,400 km/h)"
        ),
        "unusual_hour": make_dummy_signal("unusual_hour", "Hour", SignalStatus.NOT_TRIGGERED),
        "unfamiliar_device": make_dummy_signal("unfamiliar_device", "Device", SignalStatus.TRIGGERED)
    }
    res = rule_engine.evaluate(signals, evidence_level=EvidenceLevel.SUFFICIENT, extra_context={"action": "change_email"})
    assert res.deciding_rule_id == "R-06"
    assert res.final_response == ResponseAction.REVOKE
    assert res.also_open_review is True


def test_r06_fallback_to_analyst_review_on_limited_evidence(rule_engine):
    # Same takeover pattern BUT evidence is LIMITED -> R-06 downgrades to ANALYST_REVIEW (Section 11.4 & R4, R7)
    signals = {
        "sensitive_after_unfamiliar_login": make_dummy_signal(
            "sensitive_after_unfamiliar_login", "Sensitive action", SignalStatus.TRIGGERED, "change_email 4 min after login"
        ),
        "implausible_location_change": make_dummy_signal(
            "implausible_location_change", "Speed", SignalStatus.TRIGGERED, "Pune to London in 30 min (14,400 km/h)"
        ),
        "unusual_hour": make_dummy_signal("unusual_hour", "Hour", SignalStatus.NOT_TRIGGERED),
        "unfamiliar_device": make_dummy_signal("unfamiliar_device", "Device", SignalStatus.TRIGGERED)
    }
    res = rule_engine.evaluate(signals, evidence_level=EvidenceLevel.LIMITED, extra_context={"action": "change_email"})
    assert res.deciding_rule_id == "R-06"
    assert res.final_response == ResponseAction.ANALYST_REVIEW
    assert any("lowered to analyst_review" in note for note in res.evidence_notes)


def test_precedence_revoke_over_step_up(rule_engine):
    # Both R-03 (step_up) and R-07 (revoke) conditions match on unfamiliar device + speed violation on login
    signals = {
        "unfamiliar_device": make_dummy_signal("unfamiliar_device", "Device", SignalStatus.TRIGGERED),
        "implausible_location_change": make_dummy_signal("implausible_location_change", "Speed", SignalStatus.TRIGGERED),
        "unusual_hour": make_dummy_signal("unusual_hour", "Hour", SignalStatus.NOT_TRIGGERED),
        "sensitive_after_unfamiliar_login": make_dummy_signal("sensitive_after_unfamiliar_login", "Sensitive", SignalStatus.NOT_TRIGGERED)
    }
    res = rule_engine.evaluate(signals, evidence_level=EvidenceLevel.SUFFICIENT, extra_context={"action": "login"})
    assert "R-03" in res.rules_fired
    assert "R-07" in res.rules_fired
    assert res.deciding_rule_id == "R-07"
    assert res.final_response == ResponseAction.REVOKE


def test_explanation_generator(rule_engine):
    profile = UserProfile(user="asha", total_events=212, active_days={"day1", "day2", "day3", "day4", "day5"})
    signals = {
        "sensitive_after_unfamiliar_login": make_dummy_signal("sensitive_after_unfamiliar_login", "Sensitive", SignalStatus.TRIGGERED, "change_email was performed 4 minutes after login."),
        "implausible_location_change": make_dummy_signal("implausible_location_change", "Speed", SignalStatus.TRIGGERED, "Pune to London is 7,200 km in 30 min (14,400 km/h).")
    }
    res = rule_engine.evaluate(signals, evidence_level=EvidenceLevel.SUFFICIENT)

    ev_statement = ExplanationGenerator.generate_evidence_statement(profile, EvidenceLevel.SUFFICIENT, signals)
    assert "212 earlier events over 5 active days" in ev_statement

    rule_trace = ExplanationGenerator.generate_rule_trace(res, signals)
    assert "Rule R-06" in rule_trace
    assert "matched because" in rule_trace

    decision_summary = ExplanationGenerator.generate_decision_summary(
        action="change_email",
        user="asha",
        response=res.final_response,
        rule_result=res,
        signals=signals,
        evidence_statement=ev_statement
    )
    assert "Session revoked by rule R-06." in decision_summary
    assert "Pune to London is 7,200 km" in decision_summary
    assert "212 earlier events" in decision_summary
