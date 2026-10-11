"""
Signal S2: Implausible location change for the time elapsed (A-03, Section 9.3).
Computes Great-Circle Haversine distance and implied travel speed against airliner threshold.
"""

from typing import Optional, Dict, Any
from core.contracts import SignalResult, SignalStatus, EvidenceLevel, NormalizedEvent
from core.profile import UserProfile
from core.normalize import LocationDatabase, haversine_distance_km
from core.signals.base import BaseSignalDetector


class ImplausibleLocationChangeDetector(BaseSignalDetector):
    signal_id = "implausible_location_change"
    name = "Implausible location change"

    def evaluate(
        self,
        event: NormalizedEvent,
        profile: UserProfile,
        location_db: LocationDatabase,
        session_info: Optional[Dict[str, Any]] = None,
        thresholds: Optional[Dict[str, Any]] = None
    ) -> SignalResult:
        thresh = thresholds or {}
        speed_limit = thresh.get("travel_speed_kmh", 900.0)
        min_distance = thresh.get("travel_min_distance_km", 50.0)
        evidence = profile.get_evidence_level()

        curr_loc_norm = event.location_label_norm

        # Check current location resolvability
        if curr_loc_norm == "UNKNOWN":
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_EVALUABLE,
                value=None,
                reference=f"{speed_limit} km/h",
                reason="Current location label is UNKNOWN or missing coordinates.",
                evidence=evidence,
                inputs=[event.event_id]
            )

        curr_canon, curr_rec, curr_unk = location_db.resolve(curr_loc_norm)
        if curr_rec is None:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_EVALUABLE,
                value=None,
                reference=f"{speed_limit} km/h",
                reason=f"Location label '{curr_loc_norm}' could not be resolved in the location coordinates database.",
                evidence=evidence,
                inputs=[event.event_id]
            )

        # Check previous location
        prev_loc = profile.last_known_location
        prev_ts = profile.last_known_location_ts

        if not prev_loc or not prev_ts:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_EVALUABLE,
                value=None,
                reference=f"{speed_limit} km/h",
                reason="No previous resolvable location exists in this user's history.",
                evidence=evidence,
                inputs=[event.event_id]
            )

        prev_canon, prev_rec, _ = location_db.resolve(prev_loc)
        if prev_rec is None:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_EVALUABLE,
                value=None,
                reference=f"{speed_limit} km/h",
                reason=f"Previous location '{prev_loc}' has no coordinates.",
                evidence=evidence,
                inputs=[event.event_id]
            )

        # Same location check
        if curr_canon.lower() == prev_canon.lower():
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.NOT_TRIGGERED,
                value={"distance_km": 0.0, "speed_kmh": 0.0},
                reference=f"{speed_limit} km/h",
                reason=f"Activity remained in {curr_canon}.",
                evidence=evidence,
                inputs=[event.event_id]
            )

        # Calculate distance
        distance_km = haversine_distance_km(
            prev_rec.latitude, prev_rec.longitude, curr_rec.latitude, curr_rec.longitude
        )

        elapsed_seconds = (event.event_ts - prev_ts).total_seconds()

        # Handle zero or negative elapsed time (e.g. tie or out-of-order)
        if elapsed_seconds <= 0:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.TRIGGERED,
                value={"distance_km": round(distance_km, 1), "elapsed_seconds": elapsed_seconds, "speed_kmh": float("inf")},
                reference=f"{speed_limit} km/h",
                reason=f"Zero elapsed time between distinct locations ({prev_canon} to {curr_canon}, {distance_km:.0f} km).",
                evidence=evidence,
                inputs=[event.event_id]
            )

        elapsed_hours = elapsed_seconds / 3600.0
        implied_speed = distance_km / elapsed_hours
        elapsed_minutes = int(elapsed_seconds / 60)

        value_dict = {
            "distance_km": round(distance_km, 1),
            "elapsed_minutes": elapsed_minutes,
            "speed_kmh": round(implied_speed, 1),
            "from_location": prev_canon,
            "to_location": curr_canon
        }

        # Check threshold
        if implied_speed > speed_limit and distance_km > min_distance:
            return SignalResult(
                signal_id=self.signal_id,
                name=self.name,
                status=SignalStatus.TRIGGERED,
                value=value_dict,
                reference=f"{speed_limit} km/h",
                reason=(
                    f"Previous activity was in {prev_canon} {elapsed_minutes} minutes earlier; "
                    f"{prev_canon} to {curr_canon} is about {distance_km:,.0f} km, "
                    f"which would need about {implied_speed:,.0f} km/h. The limit is {speed_limit:.0f} km/h."
                ),
                evidence=evidence,
                inputs=[event.event_id]
            )

        return SignalResult(
            signal_id=self.signal_id,
            name=self.name,
            status=SignalStatus.NOT_TRIGGERED,
            value=value_dict,
            reference=f"{speed_limit} km/h",
            reason=(
                f"Travel from {prev_canon} to {curr_canon} ({distance_km:,.0f} km in {elapsed_hours:.1f} hours, "
                f"{implied_speed:,.0f} km/h) is plausible (below {speed_limit:.0f} km/h limit)."
            ),
            evidence=evidence,
            inputs=[event.event_id]
        )
