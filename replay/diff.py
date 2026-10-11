"""
Replay Difference and Comparison Engine for IdentityGuard (A-03, Section 14.2 & 14.4).
Compares two decision sequences (e.g., live baseline vs candidate rule set replay)
and categorizes deltas into:
  - stricter: e.g., no_action -> step_up/revoke
  - weaker: e.g., revoke -> step_up/no_action
  - unchanged: identical response action
"""

from typing import List, Dict, Any, Optional
from core.contracts import ResponseAction, Decision


RESPONSE_SEVERITY_ORDER = {
    ResponseAction.NO_ACTION: 0,
    ResponseAction.STEP_UP: 1,
    ResponseAction.ANALYST_REVIEW: 2,
    ResponseAction.REVOKE: 3,
    ResponseAction.REFUSED_SESSION_REVOKED: 4
}


class ReplayDiffCalculator:
    """
    Computes fine-grained differential comparison between baseline and candidate decisions.
    """

    @classmethod
    def compare(
        cls,
        baseline_decisions: List[Decision],
        replay_decisions: List[Decision]
    ) -> Dict[str, Any]:
        """
        Compares baseline decision stream with replay decision stream by matching event_id.
        """
        baseline_map = {d.event_id: d for d in baseline_decisions}
        replay_map = {d.event_id: d for d in replay_decisions}

        all_event_ids = list(baseline_map.keys())
        for eid in replay_map.keys():
            if eid not in baseline_map:
                all_event_ids.append(eid)

        stricter = []
        weaker = []
        unchanged = []
        rule_shift = []

        for eid in all_event_ids:
            base_d = baseline_map.get(eid)
            rep_d = replay_map.get(eid)

            if not base_d or not rep_d:
                continue

            base_action = base_d.response
            rep_action = rep_d.response
            base_sev = RESPONSE_SEVERITY_ORDER.get(base_action, 0)
            rep_sev = RESPONSE_SEVERITY_ORDER.get(rep_action, 0)

            delta_entry = {
                "event_id": eid,
                "session_id": rep_d.session_id,
                "user": rep_d.user,
                "baseline_response": base_action.value,
                "replay_response": rep_action.value,
                "baseline_rule": base_d.deciding_rule,
                "replay_rule": rep_d.deciding_rule,
                "baseline_rules_fired": base_d.rules_fired,
                "replay_rules_fired": rep_d.rules_fired,
                "explanation": rep_d.explanation_text
            }

            if rep_sev > base_sev:
                delta_entry["classification"] = "stricter"
                stricter.append(delta_entry)
            elif rep_sev < base_sev:
                delta_entry["classification"] = "weaker"
                weaker.append(delta_entry)
            else:
                delta_entry["classification"] = "unchanged"
                unchanged.append(delta_entry)
                if base_d.deciding_rule != rep_d.deciding_rule:
                    rule_shift.append(delta_entry)

        total_compared = len(stricter) + len(weaker) + len(unchanged)
        impact_percentage = (
            round(((len(stricter) + len(weaker)) / total_compared) * 100, 2)
            if total_compared > 0 else 0.0
        )

        return {
            "total_events": total_compared,
            "stricter_count": len(stricter),
            "weaker_count": len(weaker),
            "unchanged_count": len(unchanged),
            "rule_shift_count": len(rule_shift),
            "impact_percentage": impact_percentage,
            "stricter": stricter,
            "weaker": weaker,
            "unchanged": unchanged,
            "rule_shifts": rule_shift
        }
