"""
Base Protocol for Signal Detectors (A-03, Section 9.1).
Every detector produces a strictly compliant SignalResult object.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from core.contracts import SignalResult, NormalizedEvent
from core.profile import UserProfile
from core.normalize import LocationDatabase


class BaseSignalDetector(ABC):
    signal_id: str
    name: str

    @abstractmethod
    def evaluate(
        self,
        event: NormalizedEvent,
        profile: UserProfile,
        location_db: LocationDatabase,
        session_info: Optional[Dict[str, Any]] = None,
        thresholds: Optional[Dict[str, Any]] = None
    ) -> SignalResult:
        """Evaluates event against user profile and returns standardized SignalResult."""
        pass
