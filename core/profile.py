"""
Point-in-Time User Profile Engine for IdentityGuard (A-03).
Adheres to R2, R4, R7, and Section 8.
Constructs and maintains user pattern summaries derived strictly from earlier events.
"""

from __future__ import annotations
from datetime import datetime, timezone, date
from typing import Dict, List, Optional, Set, Tuple
from zoneinfo import ZoneInfo
from pydantic import BaseModel, Field

from core.contracts import EvidenceLevel, DeviceState, NormalizedEvent


class DeviceRecord(BaseModel):
    device_id: str
    first_seen: datetime
    last_seen: datetime
    event_count: int = 1
    login_count: int = 0
    state: DeviceState = DeviceState.UNFAMILIAR


class UserProfile(BaseModel):
    user: str
    known_devices: Dict[str, DeviceRecord] = Field(default_factory=dict)
    hour_counts: List[int] = Field(default_factory=lambda: [0] * 24)
    location_counts: Dict[str, int] = Field(default_factory=dict)
    home_location: str = "UNKNOWN"
    home_timezone: str = "UTC"
    last_known_location: Optional[str] = None
    last_known_location_ts: Optional[datetime] = None
    action_transitions: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    active_days: Set[str] = Field(default_factory=set)
    total_events: int = 0
    total_sessions: int = 0
    first_event_ts: Optional[datetime] = None
    last_event_ts: Optional[datetime] = None

    def get_evidence_level(self, min_events: int = 20, min_days: int = 5) -> EvidenceLevel:
        """
        R4, R7, Section 8.6: Computes data sufficiency level.
        """
        if self.total_events == 0:
            return EvidenceLevel.NONE
        if self.total_events < min_events or len(self.active_days) < min_days:
            return EvidenceLevel.LIMITED
        return EvidenceLevel.SUFFICIENT

    def get_smoothed_hour_distribution(self) -> List[float]:
        """
        Section 8.1: 24-bin histogram smoothed with circular neighbouring hours:
        P(h) = 0.25*P(h-1) + 0.5*P(h) + 0.25*P(h+1)
        """
        total = sum(self.hour_counts)
        if total == 0:
            return [1.0 / 24.0] * 24

        raw_shares = [c / total for c in self.hour_counts]
        smoothed = [0.0] * 24
        for h in range(24):
            prev_h = (h - 1) % 24
            next_h = (h + 1) % 24
            smoothed[h] = 0.25 * raw_shares[prev_h] + 0.5 * raw_shares[h] + 0.25 * raw_shares[next_h]
        return smoothed


class ProfileManager:
    """Derives user patterns and maintains in-memory profiles."""

    def __init__(
        self,
        min_events_sufficient: int = 20,
        min_active_days_sufficient: int = 5,
        new_device_logins_to_trust: int = 3
    ):
        self.min_events_sufficient = min_events_sufficient
        self.min_active_days_sufficient = min_active_days_sufficient
        self.new_device_logins_to_trust = new_device_logins_to_trust
        self.profiles: Dict[str, UserProfile] = {}

    def get_or_create(self, user: str) -> UserProfile:
        if user not in self.profiles:
            self.profiles[user] = UserProfile(user=user)
        return self.profiles[user]

    def update_from_event(
        self,
        event: NormalizedEvent,
        location_timezone: str = "UTC",
        is_resolvable_location: bool = True
    ) -> None:
        """
        Section 8.4: Updates the user profile.
        Only called for eligible events (non-revoked, legitimate).
        """
        prof = self.get_or_create(event.user)
        is_first_user_event = (prof.total_events == 0)

        prof.total_events += 1
        if prof.first_event_ts is None:
            prof.first_event_ts = event.event_ts
        prof.last_event_ts = event.event_ts

        # Active days tracking
        day_str = event.event_ts.strftime("%Y-%m-%d")
        prof.active_days.add(day_str)

        # 1. Device tracking (Section 8.2 & 5.1: UNKNOWN_DEVICE is not learned into device profiles)
        dev_id = event.device_id
        is_login = (event.action == "login")
        if dev_id != "UNKNOWN_DEVICE":
            if dev_id not in prof.known_devices:
                if is_first_user_event:
                    # User's very first device is treated as baseline, not unfamiliar (Section 8.2)
                    initial_state = DeviceState.KNOWN
                else:
                    initial_state = DeviceState.UNFAMILIAR

                prof.known_devices[dev_id] = DeviceRecord(
                    device_id=dev_id,
                    first_seen=event.event_ts,
                    last_seen=event.event_ts,
                    event_count=1,
                    login_count=1 if is_login else 0,
                    state=initial_state
                )
            else:
                dev_rec = prof.known_devices[dev_id]
                if event.event_ts >= dev_rec.last_seen:
                    dev_rec.last_seen = event.event_ts
                dev_rec.event_count += 1
                if is_login:
                    dev_rec.login_count += 1
                    if (
                        dev_rec.state == DeviceState.UNFAMILIAR
                        and dev_rec.login_count >= self.new_device_logins_to_trust
                    ):
                        dev_rec.state = DeviceState.KNOWN

        # 2. Location tracking (Section 8.1, 8.3 & 10.3)
        loc = event.location_label_norm
        if is_resolvable_location and loc != "UNKNOWN":
            prof.location_counts[loc] = prof.location_counts.get(loc, 0) + 1
            # Only update last known location if event is on-time or newer
            if prof.last_known_location_ts is None or event.event_ts >= prof.last_known_location_ts:
                prof.last_known_location = loc
                prof.last_known_location_ts = event.event_ts
            # Recompute home location (most frequent)
            best_loc = max(prof.location_counts, key=prof.location_counts.get)
            prof.home_location = best_loc
            prof.home_timezone = location_timezone

        # 3. Hour histogram tracking in home timezone
        try:
            tz = ZoneInfo(prof.home_timezone)
            local_dt = event.event_ts.astimezone(tz)
        except Exception:
            local_dt = event.event_ts
        hour = local_dt.hour
        prof.hour_counts[hour] += 1
