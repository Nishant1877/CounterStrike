"""
Supporting Signals S5, S6, S7 (A-03, Section 9.6).
Provides corroborating evidence without triggering disruptive false alarms alone.
"""

from typing import Optional, Dict, Any, List
from core.contracts import SignalResult, SignalStatus, EvidenceLevel, NormalizedEvent
from core.profile import UserProfile
from core.normalize import LocationDatabase
from core.signals.base import BaseSignalDetector
from core.signals.s4_sensitive import DEFAULT_SENSITIVE_ACTIONS


class UnfamiliarLocationDetector(BaseSignalDetector):
    """S5: Location label has never appeared for this user."""
    signal_id = "unfamiliar_location"
    name = "Unfamiliar location"

    def evaluate(
        self,
        event: NormalizedEvent,
        profile: UserProfile,
        location_db: LocationDatabase,
        session_info: Optional[Dict[str, Any]] = None,
        thresholds: Optional[Dict[str, Any]] = None
    ) -> SignalResult:
        loc = event.location_label_norm
        evidence = profile.get_evidence_level()

        if loc == "UNKNOWN":
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_EVALUABLE,
                value=None,
                reference="first time seen",
                reason="Current location label is UNKNOWN.",
                evidence=evidence,
                inputs=[event.event_id]
            )

        count = profile.location_counts.get(loc, 0)
        if count == 0 and profile.total_events > 0:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.TRIGGERED,
                value={"earlier_events_at_location": 0, "location": loc},
                reference="first time seen",
                reason=f"Location '{loc}' has never appeared in any of this user's earlier events.",
                evidence=evidence,
                inputs=[event.event_id]
            )

        return SignalResult(
            signal_id=self.signal_id,
            name=self.name,
            status=SignalStatus.NOT_TRIGGERED,
            value={"earlier_events_at_location": count, "location": loc},
            reference="first time seen",
            reason=f"Location '{loc}' has appeared {count} times before for this user.",
            evidence=evidence,
            inputs=[event.event_id]
        )


class SensitiveActionChainDetector(BaseSignalDetector):
    """S6: Two or more sensitive actions in one session within configured window."""
    signal_id = "sensitive_action_chain"
    name = "Sensitive-action chain"

    def evaluate(
        self,
        event: NormalizedEvent,
        profile: UserProfile,
        location_db: LocationDatabase,
        session_info: Optional[Dict[str, Any]] = None,
        thresholds: Optional[Dict[str, Any]] = None
    ) -> SignalResult:
        thresh = thresholds or {}
        sensitive_set = thresh.get("sensitive_actions", DEFAULT_SENSITIVE_ACTIONS)
        evidence = profile.get_evidence_level()

        if not session_info:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_EVALUABLE,
                value=None,
                reference="2+ sensitive actions in session",
                reason="No active session context available.",
                evidence=evidence,
                inputs=[event.event_id]
            )

        sensitive_history: List[Dict[str, Any]] = session_info.get("sensitive_actions_in_session", [])

        # Check if current action is sensitive
        if event.action in sensitive_set:
            if len(sensitive_history) >= 1:
                actions_list = [h["action"] for h in sensitive_history] + [event.action]
                return SignalResult(
                    signal_id=self.signal_id,
                    name=self.name,
                    status=SignalStatus.TRIGGERED,
                    value={"chain": actions_list, "count": len(actions_list)},
                    reference="2+ sensitive actions in session",
                    reason=f"Multiple sensitive actions chained in session: {' -> '.join(actions_list)}.",
                    evidence=evidence,
                    inputs=[event.event_id]
                )

        return SignalResult(
            signal_id=self.signal_id,
            name=self.name,
            status=SignalStatus.NOT_TRIGGERED,
            value={"count": len(sensitive_history)},
            reference="2+ sensitive actions in session",
            reason="No sensitive action chain detected in this session.",
            evidence=evidence,
            inputs=[event.event_id]
        )
