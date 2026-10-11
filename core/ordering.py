"""
Ordering and Temporal Anomaly Handler for IdentityGuard (A-03).
Addresses requirement R6 (out-of-order timestamps, duplicates, ties, late events).
"""

from __future__ import annotations
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Set
from enum import Enum

from core.contracts import NormalizedEvent


class OrderingClassification(str, Enum):
    ON_TIME = "on_time"
    LATE = "late_event"
    DUPLICATE = "duplicate"
    TIE = "tie"
    FUTURE = "clock_skew"


class OrderingHandler:
    """Tracks per-user event temporal order and detects late or duplicate events."""

    def __init__(self, future_tolerance_minutes: float = 5.0):
        self.future_tolerance = timedelta(minutes=future_tolerance_minutes)
        # Tracks latest processed event time per user
        self.user_latest_event_ts: Dict[str, datetime] = {}
        # Tracks seen event IDs for deduplication
        self.seen_event_ids: Set[str] = set()

    def check_ordering(self, event: NormalizedEvent) -> Tuple[OrderingClassification, Optional[float]]:
        """
        Assesses event arrival order relative to the user's latest recorded event time.
        Returns: (OrderingClassification, lateness_seconds)
        """
        # Deduplication check
        if event.event_id in self.seen_event_ids:
            return OrderingClassification.DUPLICATE, None

        self.seen_event_ids.add(event.event_id)
        user = event.user
        last_ts = self.user_latest_event_ts.get(user)

        if last_ts is None:
            # First event for this user
            self.user_latest_event_ts[user] = event.event_ts
            return OrderingClassification.ON_TIME, None

        # Compare event_ts with last_ts
        delta = (event.event_ts - last_ts).total_seconds()

        if delta < 0:
            # Event happened earlier than the latest processed event
            lateness_seconds = abs(delta)
            return OrderingClassification.LATE, lateness_seconds
        elif delta == 0:
            return OrderingClassification.TIE, 0.0
        else:
            # Update latest seen event time
            self.user_latest_event_ts[user] = event.event_ts
            return OrderingClassification.ON_TIME, None
