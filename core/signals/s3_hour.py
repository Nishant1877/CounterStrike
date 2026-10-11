"""
Signal S3: Unusual activity hour for this user (A-03, Section 9.4).
Checks smoothed activity probability density in the user's primary timezone against baseline.
"""

from typing import Optional, Dict, Any, List
from zoneinfo import ZoneInfo
from core.contracts import SignalResult, SignalStatus, EvidenceLevel, NormalizedEvent
from core.profile import UserProfile
from core.normalize import LocationDatabase
from core.signals.base import BaseSignalDetector


class UnusualHourDetector(BaseSignalDetector):
    signal_id = "unusual_hour"
    name = "Unusual activity hour"

    def evaluate(
        self,
        event: NormalizedEvent,
        profile: UserProfile,
        location_db: LocationDatabase,
        session_info: Optional[Dict[str, Any]] = None,
        thresholds: Optional[Dict[str, Any]] = None
    ) -> SignalResult:
        thresh = thresholds or {}
        rare_hour_share = thresh.get("rare_hour_share", 0.02)
        min_active_days = thresh.get("min_active_days_hours_signal", 5)
        evidence = profile.get_evidence_level()

        # Check sufficiency of active days
        if len(profile.active_days) < min_active_days:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_EVALUABLE,
                value=None,
                reference=f">={min_active_days} active days",
                reason=(
                    f"User has only {len(profile.active_days)} active days ({min_active_days} required). "
                    "Cannot establish meaningful diurnal hour baseline."
                ),
                evidence=evidence,
                inputs=[event.event_id]
            )

        # Convert event time to user's home timezone
        home_tz_name = profile.home_timezone or "UTC"
        try:
            tz = ZoneInfo(home_tz_name)
            local_dt = event.event_ts.astimezone(tz)
        except Exception:
            local_dt = event.event_ts
            home_tz_name = "UTC"

        hour = local_dt.hour
        smoothed_dist = profile.get_smoothed_hour_distribution()
        hour_share = smoothed_dist[hour]

        # Find busiest hours for explanation context
        top_hours = sorted(range(24), key=lambda h: smoothed_dist[h], reverse=True)[:3]
        top_hours_str = ", ".join([f"{h:02d}:00" for h in top_hours])

        value_dict = {
            "local_hour": f"{hour:02d}:00",
            "home_timezone": home_tz_name,
            "share_percentage": round(hour_share * 100, 2),
            "busiest_hours": [f"{h:02d}:00" for h in top_hours]
        }

        if hour_share < rare_hour_share:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.TRIGGERED,
                value=value_dict,
                reference=f"< {rare_hour_share * 100:.1f}%",
                reason=(
                    f"Only {hour_share * 100:.1f} percent of this user's earlier activity happened around "
                    f"{hour:02d}:00 local time (home time zone {home_tz_name}); their usual hours are {top_hours_str}."
                ),
                evidence=evidence,
                inputs=[event.event_id]
            )

        return SignalResult(
            signal_id=self.signal_id,
            name=self.name,
            status=SignalStatus.NOT_TRIGGERED,
            value=value_dict,
            reference=f"< {rare_hour_share * 100:.1f}%",
            reason=(
                f"Activity at {hour:02d}:00 local time ({home_tz_name}) accounts for "
                f"{hour_share * 100:.1f}% of historical activity (within normal pattern)."
            ),
            evidence=evidence,
            inputs=[event.event_id]
        )
