"""
Deterministic Rule Engine & Precedence Evaluator (A-03, Section 11).
Matches signals against declarative YAML rules and enforces evidence-aware response hierarchies.
"""

from __future__ import annotations
import os
import yaml
from typing import Dict, List, Optional, Tuple, Any
from core.contracts import (
    SignalResult,
    AdvisoryResult,
    ResponseAction,
    EvidenceLevel,
    SignalStatus
)
from core.advisory.guard import validate_rule_set, RuntimeAdvisoryGuard, RuleValidationError
from core.rules.dsl import evaluate_condition_node

EVIDENCE_RANK = {
    EvidenceLevel.NONE: 0,
    EvidenceLevel.LIMITED: 1,
    EvidenceLevel.SUFFICIENT: 2
}

DEFAULT_PRECEDENCE = [
    ResponseAction.REVOKE,
    ResponseAction.STEP_UP,
    ResponseAction.ANALYST_REVIEW,
    ResponseAction.NO_ACTION
]


class MatchedRuleDetail:
    def __init__(
        self,
        rule_id: str,
        name: str,
        nominal_response: ResponseAction,
        applied_response: ResponseAction,
        requires_evidence: EvidenceLevel,
        evidence_met: bool,
        also_open_review: bool,
        audit_note: Optional[str] = None
    ):
        self.rule_id = rule_id
        self.name = name
        self.nominal_response = nominal_response
        self.applied_response = applied_response
        self.requires_evidence = requires_evidence
        self.evidence_met = evidence_met
        self.also_open_review = also_open_review
        self.audit_note = audit_note


class RuleEvaluationResult:
    def __init__(
        self,
        deciding_rule_id: Optional[str],
        final_response: ResponseAction,
        rules_fired: List[str],
        matched_details: List[MatchedRuleDetail],
        evidence_level: EvidenceLevel,
        evidence_notes: List[str],
        also_open_review: bool = False
    ):
        self.deciding_rule_id = deciding_rule_id
        self.final_response = final_response
        self.rules_fired = rules_fired
        self.matched_details = matched_details
        self.evidence_level = evidence_level
        self.evidence_notes = evidence_notes
        self.also_open_review = also_open_review


class RuleEngine:
    """Evaluates declarative rules over computed signals and advisory results."""

    def __init__(self, rules_yaml_path: Optional[str] = None):
        self.version = "v1.0"
        self.precedence = DEFAULT_PRECEDENCE
        self.rules: List[Dict[str, Any]] = []
        if rules_yaml_path and os.path.exists(rules_yaml_path):
            self.load_rules(rules_yaml_path)

    def load_rules(self, yaml_path: str) -> None:
        with open(yaml_path, mode="r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # Compile-time validation (including R9 AI Advisory guard)
        validate_rule_set(data)

        self.version = data.get("version", "v1.0")
        raw_prec = data.get("precedence", [])
        if raw_prec:
            self.precedence = [ResponseAction(p) for p in raw_prec]

        self.rules = data.get("rules", [])

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleEngine":
        """Instantiate RuleEngine directly from a validated rule dictionary."""
        validate_rule_set(data)
        engine = cls()
        engine.version = data.get("version", "candidate-v1")
        raw_prec = data.get("precedence", [])
        if raw_prec:
            engine.precedence = [ResponseAction(p) for p in raw_prec]
        engine.rules = data.get("rules", [])
        return engine

    def evaluate(
        self,
        signals: Dict[str, SignalResult],
        evidence_level: EvidenceLevel,
        advisory: Optional[AdvisoryResult] = None,
        extra_context: Optional[Dict[str, Any]] = None
    ) -> RuleEvaluationResult:
        """
        Evaluates active rules over signals and returns winning response and all fired rules.
        """
        matched_rules: List[MatchedRuleDetail] = []
        evidence_notes: List[str] = []

        # Find triggered deterministic signals
        triggered_det_signals = [
            s_id for s_id, s_res in signals.items()
            if s_res.status == SignalStatus.TRIGGERED
        ]

        current_evidence_rank = EVIDENCE_RANK[evidence_level]

        for rule in self.rules:
            r_id = rule["id"]
            r_name = rule.get("name", r_id)
            nominal_resp = ResponseAction(rule["response"])
            when_node = rule.get("when", {})
            also_open_rev = rule.get("also_open_review", False)

            # Evaluate AST conditions
            is_match = evaluate_condition_node(when_node, signals, advisory, extra_context)
            if not is_match:
                continue

            # R9 Runtime Circuit Breaker
            matched_cond_dict = {"advisory:sequence_anomalous": (advisory is not None and advisory.label in {"unusual", "suspicious"})}
            is_valid_runtime, suppression_reason = RuntimeAdvisoryGuard.verify_runtime_execution(
                r_id, matched_cond_dict, triggered_det_signals
            )

            if not is_valid_runtime:
                # Suppress advisory-only match
                evidence_notes.append(f"{r_id}: {suppression_reason}")
                continue

            # Evidence evaluation and fallback handling (Section 11.4)
            req_ev_str = rule.get("requires_evidence")
            req_ev = EvidenceLevel(req_ev_str) if req_ev_str and req_ev_str != "none" else EvidenceLevel.NONE
            req_ev_rank = EVIDENCE_RANK[req_ev]

            applied_resp = nominal_resp
            audit_note = None

            if current_evidence_rank < req_ev_rank:
                # History is thinner than required
                evidence_met = False
                fallback_resp_str = rule.get("if_evidence_lower")
                if fallback_resp_str:
                    applied_resp = ResponseAction(fallback_resp_str)
                    audit_note = (
                        f"{r_id} matched but history was {evidence_level.value}, "
                        f"so the response was lowered to {applied_resp.value}."
                    )
                    evidence_notes.append(audit_note)
            else:
                evidence_met = True

            matched_rules.append(
                MatchedRuleDetail(
                    rule_id=r_id,
                    name=r_name,
                    nominal_response=nominal_resp,
                    applied_response=applied_resp,
                    requires_evidence=req_ev,
                    evidence_met=evidence_met,
                    also_open_review=also_open_rev,
                    audit_note=audit_note
                )
            )

        # If no rules matched, default to no_action
        if not matched_rules:
            return RuleEvaluationResult(
                deciding_rule_id=None,
                final_response=ResponseAction.NO_ACTION,
                rules_fired=[],
                matched_details=[],
                evidence_level=evidence_level,
                evidence_notes=evidence_notes,
                also_open_review=False
            )

        # Sort matched rules by response precedence
        def precedence_key(m: MatchedRuleDetail) -> int:
            try:
                return self.precedence.index(m.applied_response)
            except ValueError:
                return 999

        sorted_matches = sorted(matched_rules, key=precedence_key)
        winning_rule = sorted_matches[0]
        final_response = winning_rule.applied_response

        # Check if any rule requested also_open_review
        any_also_open_review = any(m.also_open_review for m in matched_rules)

        return RuleEvaluationResult(
            deciding_rule_id=winning_rule.rule_id,
            final_response=final_response,
            rules_fired=[m.rule_id for m in matched_rules],
            matched_details=matched_rules,
            evidence_level=evidence_level,
            evidence_notes=evidence_notes,
            also_open_review=any_also_open_review
        )
