"""
Signal S4: Sensitive action shortly after a login from an unfamiliar device (A-03, Section 9.5).
Correlates sensitive post-login actions within a window W (default 30m) when the login device was unfamiliar.
"""

from datetime import datetime
from typing import Optional, Dict, Any, Set
from core.contracts import SignalResult, SignalStatus, EvidenceLevel, NormalizedEvent
from core.profile import UserProfile
from core.normalize import LocationDatabase
from core.signals.base import BaseSignalDetector

DEFAULT_SENSITIVE_ACTIONS: Set[str] = {
    "change_email",
    "change_password",
    "change_phone",
    "add_payee",
    "request_transfer",
    "export_data"
}


class SensitiveAfterUnfamiliarLoginDetector(BaseSignalDetector):
    signal_id = "sensitive_after_unfamiliar_login"
    name = "Sensitive action after unfamiliar login"

    def evaluate(
        self,
        event: NormalizedEvent,
        profile: UserProfile,
        location_db: LocationDatabase,
        session_info: Optional[Dict[str, Any]] = None,
        thresholds: Optional[Dict[str, Any]] = None
    ) -> SignalResult:
        thresh = thresholds or {}
        window_minutes = thresh.get("sensitive_window_minutes", 30)
        sensitive_set = thresh.get("sensitive_actions", DEFAULT_SENSITIVE_ACTIONS)
        evidence = profile.get_evidence_level()

        # Check if the current action is classified as sensitive
        if event.action not in sensitive_set:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_TRIGGERED,
                value={"action": event.action, "is_sensitive": False},
                reference=f"Within {window_minutes}m of unfamiliar login",
                reason=f"Action '{event.action}' is routine, not in sensitive actions vocabulary.",
                evidence=evidence,
                inputs=[event.event_id]
            )

        # Check session info
        if not session_info or "login_event_ts" not in session_info:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_EVALUABLE,
                value=None,
                reference=f"Within {window_minutes}m of unfamiliar login",
                reason="Session has no explicit login event (action occurred in inferred session).",
                evidence=evidence,
                inputs=[event.event_id]
            )

        login_ts: datetime = session_info["login_event_ts"]
        login_device_unfamiliar: bool = session_info.get("login_device_unfamiliar", False)
        step_up_passed: bool = session_info.get("step_up_passed", False)

        # If user passed step-up during this session, device is verified from that moment (Section 9.5 & 12.3)
        if step_up_passed:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_TRIGGERED,
                value={"step_up_passed": True},
                reference=f"Within {window_minutes}m of unfamiliar login",
                reason="Step-up verification was passed earlier in this session, so device is verified.",
                evidence=evidence,
                inputs=[event.event_id]
            )

        if not login_device_unfamiliar:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_TRIGGERED,
                value={"login_device_unfamiliar": False},
                reference=f"Within {window_minutes}m of unfamiliar login",
                reason="The login for this session came from a familiar/known device.",
                evidence=evidence,
                inputs=[event.event_id]
            )

        # Ensure both timestamps are timezone-aware UTC before subtraction
        from datetime import timezone
        if login_ts.tzinfo is None:
            login_ts_utc = login_ts.replace(tzinfo=timezone.utc)
        else:
            login_ts_utc = login_ts.astimezone(timezone.utc)

        if event.event_ts.tzinfo is None:
            event_ts_utc = event.event_ts.replace(tzinfo=timezone.utc)
        else:
            event_ts_utc = event.event_ts.astimezone(timezone.utc)

        elapsed_seconds = (event_ts_utc - login_ts_utc).total_seconds()
        if elapsed_seconds < 0:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_EVALUABLE,
                value={"elapsed_seconds": elapsed_seconds},
                reference=f"Within {window_minutes}m of unfamiliar login",
                reason="Sensitive action has earlier timestamp than its session login (action_without_login anomaly).",
                evidence=evidence,
                inputs=[event.event_id, session_info.get("login_event_id", "")]
            )

        elapsed_minutes = int(elapsed_seconds / 60)

        value_dict = {
            "action": event.action,
            "minutes_since_login": elapsed_minutes,
            "device_id": event.device_id,
            "login_device_unfamiliar": True
        }

        inputs_list = [event.event_id]
        login_evt_id = session_info.get("login_event_id")
        if login_evt_id:
            inputs_list.append(str(login_evt_id))

        if 0 <= elapsed_minutes <= window_minutes:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.TRIGGERED,
                value=value_dict,
                reference=f"Within {window_minutes}m of unfamiliar login",
                reason=(
                    f"{event.action} was performed {elapsed_minutes} minutes after a login from device "
                    f"{event.device_id}, which this user had never used before."
                ),
                evidence=evidence,
                inputs=inputs_list
            )

        return SignalResult(
            signal_id=self.signal_id,
            name=self.name,
            status=SignalStatus.NOT_TRIGGERED,
            value=value_dict,
            reference=f"Within {window_minutes}m of unfamiliar login",
            reason=(
                f"Action occurred {elapsed_minutes} minutes after login (exceeds the {window_minutes}-minute risk window)."
            ),
            evidence=evidence,
            inputs=inputs_list
        )
