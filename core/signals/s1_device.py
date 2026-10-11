"""
Signal S1: Unfamiliar Device (A-03, Section 9.2).
Checks if the device identifier appears in the user's earlier events and whether it is trusted.
"""

from typing import Optional, Dict, Any
from core.contracts import SignalResult, SignalStatus, EvidenceLevel, DeviceState, NormalizedEvent
from core.profile import UserProfile
from core.normalize import LocationDatabase
from core.signals.base import BaseSignalDetector


class UnfamiliarDeviceDetector(BaseSignalDetector):
    signal_id = "unfamiliar_device"
    name = "Unfamiliar device"

    def evaluate(
        self,
        event: NormalizedEvent,
        profile: UserProfile,
        location_db: LocationDatabase,
        session_info: Optional[Dict[str, Any]] = None,
        thresholds: Optional[Dict[str, Any]] = None
    ) -> SignalResult:
        dev_id = event.device_id
        thresh = thresholds or {}
        required_logins = thresh.get("new_device_logins_to_trust", 3)

        # 1. Check not evaluable cases
        if dev_id == "UNKNOWN_DEVICE":
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_EVALUABLE,
                value=None,
                reference=required_logins,
                reason="Device identifier is missing or unknown.",
                evidence=EvidenceLevel.NONE,
                inputs=[]
            )

        if profile.total_events == 0:
            # First-ever user event: baseline device, not unfamiliar (Section 8.2 & 9.2)
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_TRIGGERED,
                value=0,
                reference="first_device_baseline",
                reason="This is the user's first-ever event; device is established as baseline.",
                evidence=EvidenceLevel.NONE,
                inputs=[event.event_id]
            )

        # 2. Check if device is in profile
        dev_rec = profile.known_devices.get(dev_id)
        evidence = profile.get_evidence_level()

        if dev_rec is None:
            # Never seen before
            earlier_count = profile.total_events
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.TRIGGERED,
                value={"earlier_events_from_device": 0, "state": "never_seen"},
                reference=f">={required_logins} logins to trust",
                reason=f"Device {dev_id} has not appeared in any of this user's {earlier_count} earlier events.",
                evidence=evidence,
                inputs=[event.event_id]
            )

        # Seen before: check if trusted
        if dev_rec.state == DeviceState.UNFAMILIAR:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.TRIGGERED,
                value={"earlier_events_from_device": dev_rec.event_count, "logins": dev_rec.login_count, "state": dev_rec.state.value},
                reference=f">={required_logins} logins to trust",
                reason=f"Device {dev_id} has only {dev_rec.login_count} earlier logins ({required_logins} needed to trust).",
                evidence=evidence,
                inputs=[event.event_id]
            )

        # Known or verified
        return SignalResult(
            signal_id=self.signal_id,
            name=self.name,
            status=SignalStatus.NOT_TRIGGERED,
            value={"earlier_events_from_device": dev_rec.event_count, "state": dev_rec.state.value},
            reference=f">={required_logins} logins to trust",
            reason=f"Device {dev_id} is recognized ({dev_rec.state.value}) with {dev_rec.event_count} earlier events.",
            evidence=evidence,
            inputs=[event.event_id]
        )
