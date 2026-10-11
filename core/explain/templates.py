"""
Deterministic Plain-English Explanation Generator (A-03, Section 17 & R7).
Transforms rule matches and measured signal values into exact, consistent natural language explanations.
"""

from typing import Dict, List, Optional
from core.contracts import (
    SignalResult,
    AdvisoryResult,
    ResponseAction,
    EvidenceLevel,
    SignalStatus
)
from core.profile import UserProfile
from core.rules.engine import RuleEvaluationResult


class ExplanationGenerator:
    """Generates multi-layer human-readable audit explanations from deterministic templates."""

    @staticmethod
    def generate_evidence_statement(
        profile: UserProfile,
        evidence_level: EvidenceLevel,
        signals: Dict[str, SignalResult]
    ) -> str:
        """Section 10.4: Generates prominent evidence sufficiency statement."""
        not_eval_names = [
            s.name for s in signals.values()
            if s.status == SignalStatus.NOT_EVALUABLE
        ]
        caveat = ""
        if not_eval_names:
            caveat = f" ({', '.join(not_eval_names)} could not be evaluated)."

        if evidence_level == EvidenceLevel.NONE:
            return f"Judgement rests on no earlier history: first-ever event for this user{caveat}."
        elif evidence_level == EvidenceLevel.LIMITED:
            days = len(profile.active_days)
            return (
                f"Judgement rests on limited information: {profile.total_events} earlier events "
                f"over {days} active days{caveat}."
            )
        else:
            days = len(profile.active_days)
            return (
                f"Judgement rests on sufficient history: {profile.total_events} earlier events "
                f"over {days} active days."
            )

    @staticmethod
    def generate_rule_trace(rule_result: RuleEvaluationResult, signals: Dict[str, SignalResult]) -> str:
        """Section 17.1 Layer 2: Rule trace."""
        if not rule_result.deciding_rule_id:
            return "No security rule conditions were triggered."

        deciding_id = rule_result.deciding_rule_id
        matched_detail = next(
            (m for m in rule_result.matched_details if m.rule_id == deciding_id), None
        )
        rule_name = matched_detail.name if matched_detail else deciding_id

        # Collect triggered signals
        triggered_reasons = [
            f"{s.name} ({s.status.value})" for s in signals.values()
            if s.status == SignalStatus.TRIGGERED
        ]
        triggered_str = ", ".join(triggered_reasons) if triggered_reasons else "baseline criteria"

        return f"Rule {deciding_id} ('{rule_name}') matched because: {triggered_str}."

    @staticmethod
    def generate_decision_summary(
        action: str,
        user: str,
        response: ResponseAction,
        rule_result: RuleEvaluationResult,
        signals: Dict[str, SignalResult],
        evidence_statement: str,
        advisory: Optional[AdvisoryResult] = None
    ) -> str:
        """Section 17.1 Layer 3 & Section 17.2: Decision summary paragraph."""
        deciding_id = rule_result.deciding_rule_id

        if response == ResponseAction.NO_ACTION:
            if not deciding_id or deciding_id == "R-11":
                return f"No security action required for user {user} performing '{action}'. {evidence_statement}"
            return f"Event permitted under rule {deciding_id}. {evidence_statement}"

        # Collect signal explanations
        signal_sentences = [
            s.reason for s in signals.values()
            if s.status == SignalStatus.TRIGGERED and s.reason
        ]
        signal_details_text = " ".join(signal_sentences)

        action_phrase = {
            ResponseAction.REVOKE: f"Session revoked by rule {deciding_id}.",
            ResponseAction.STEP_UP: f"Step-up verification challenge opened by rule {deciding_id}.",
            ResponseAction.ANALYST_REVIEW: f"Analyst review case opened by rule {deciding_id}.",
            ResponseAction.REFUSED_SESSION_REVOKED: "Action refused: session was previously revoked."
        }.get(response, f"Action evaluated with outcome {response.value}.")

        advisory_note = ""
        if advisory and advisory.label in {"unusual", "suspicious"}:
            advisory_note = f" The AI advisory sequence model also observed: {advisory.reason}"

        fallback_note = ""
        if rule_result.evidence_notes:
            fallback_note = " " + " ".join(rule_result.evidence_notes)

        return f"{action_phrase} {signal_details_text} {evidence_statement}{advisory_note}{fallback_note}".strip()
