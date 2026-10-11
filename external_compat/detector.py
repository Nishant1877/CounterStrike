import math
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any
from external_compat.models import SecurityEvent, RiskSignal, EvaluationResult, RiskTier, ResponseAction, PolicyConfig

# Approximate coordinates for key cities to compute Haversine distance & travel velocity
COORDINATES: Dict[str, Tuple[float, float]] = {
    "Pune, IN": (18.5204, 73.8567),
    "Mumbai, IN": (19.0760, 72.8777),
    "Delhi, IN": (28.6139, 77.2090),
    "Bengaluru, IN": (12.9716, 77.5946),
    "London, UK": (51.5074, -0.1278),
    "New York, US": (40.7128, -74.0060),
    "San Francisco, US": (37.7749, -122.4194),
    "Lagos, NG": (6.5244, 3.3792),
    "Moscow, RU": (55.7558, 37.6173),
    "Singapore, SG": (1.3521, 103.8198),
    "Dubai, AE": (25.2048, 55.2708),
    "Sydney, AU": (-33.8688, 151.2093),
}

SENSITIVE_ACTIONS = {
    "change_email",
    "change_password",
    "transfer_funds",
    "delete_account",
    "generate_api_key",
    "disable_mfa",
    "add_beneficiary"
}

def haversine_distance_km(coord1: Tuple[float, float], coord2: Tuple[float, float]) -> float:
    """Calculate the great circle distance in kilometers between two points."""
    lat1, lon1 = math.radians(coord1[0]), math.radians(coord1[1])
    lat2, lon2 = math.radians(coord2[0]), math.radians(coord2[1])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
    c = 2 * math.asin(math.sqrt(a))
    return 6371.0 * c  # Earth radius in km

class UserHistory:
    def __init__(self, user: str):
        self.user = user
        self.known_devices: set = set()
        self.known_locations: set = set()
        self.typical_hours: List[int] = []  # hours 0-23
        self.events: List[SecurityEvent] = []

    def add_baseline_event(self, event: SecurityEvent):
        self.known_devices.add(event.device_id)
        self.known_locations.add(event.location_label)
        hour = datetime.fromtimestamp(event.timestamp, tz=timezone.utc).hour
        self.typical_hours.append(hour)
        self.events.append(event)
        # Keep events sorted by timestamp
        self.events.sort(key=lambda x: x.timestamp)

class IdentityGuardEngine:
    def __init__(self, policy: Optional[PolicyConfig] = None):
        self.policy = policy or PolicyConfig()
        self.user_histories: Dict[str, UserHistory] = {}
        self.revoked_sessions: set = set()  # Store revoked session_ids
        self.session_events: Dict[str, List[SecurityEvent]] = {}
        self.session_unfamiliar_logins: Dict[str, SecurityEvent] = {}  # session_id -> login SecurityEvent
        self.all_audit_logs: List[EvaluationResult] = []

    def get_or_create_history(self, user: str) -> UserHistory:
        if user not in self.user_histories:
            self.user_histories[user] = UserHistory(user)
        return self.user_histories[user]

    def reset_state(self):
        """Reset all in-memory histories and revocations."""
        self.user_histories.clear()
        self.revoked_sessions.clear()
        self.session_events.clear()
        self.session_unfamiliar_logins.clear()
        self.all_audit_logs.clear()

    def evaluate_event(self, event: SecurityEvent, ai_pattern_note: Optional[str] = None) -> EvaluationResult:
        # 1. HARD ENFORCEMENT: If session is already revoked, immediately refuse any action!
        if event.session_id in self.revoked_sessions:
            revocation_signal = RiskSignal(
                signal_name="REVOKED_SESSION_BLOCKED",
                score_contribution=100,
                severity="danger",
                reason=f"Session '{event.session_id}' has already been REVOKED due to prior compromise. Action blocked.",
                evidence={"session_id": event.session_id, "action_attempted": event.action}
            )
            result = EvaluationResult(
                event=event,
                risk_score=100,
                risk_tier=RiskTier.CRITICAL,
                recommended_action=ResponseAction.SESSION_REVOCATION,
                action_enforced=ResponseAction.SESSION_REVOCATION,
                signals=[revocation_signal],
                confidence_level="high",
                ai_sequence_note=ai_pattern_note,
                session_is_revoked=True,
                rejection_reason=f"Access Denied: Session '{event.session_id}' was previously revoked. No further actions permitted."
            )
            self.all_audit_logs.append(result)
            return result

        history = self.get_or_create_history(event.user)
        signals: List[RiskSignal] = []
        confidence_level = "high"

        # Check for sparse history (Cold Start)
        if len(history.events) < 3:
            confidence_level = "limited_information (cold start)"
            signals.append(RiskSignal(
                signal_name="SPARSE_USER_HISTORY",
                score_contribution=5,
                severity="info",
                reason=f"User '{event.user}' has only {len(history.events)} past recorded events. Baseline confidence is tentative.",
                evidence={"historical_event_count": len(history.events)}
            ))

        # Check for out-of-order timestamp
        if history.events and event.timestamp < history.events[-1].timestamp:
            time_diff = history.events[-1].timestamp - event.timestamp
            signals.append(RiskSignal(
                signal_name="OUT_OF_ORDER_TIMESTAMP",
                score_contribution=15,
                severity="warning",
                reason=f"Event timestamp is {int(time_diff)}s earlier than most recent logged event for this user.",
                evidence={"skew_seconds": time_diff, "last_timestamp": history.events[-1].timestamp}
            ))

        # Check unknown location label
        location_known = event.location_label in COORDINATES
        if not location_known:
            signals.append(RiskSignal(
                signal_name="UNMAPPED_LOCATION",
                score_contribution=10,
                severity="warning",
                reason=f"Location label '{event.location_label}' is unmapped in coordinate registry. Velocity check degraded.",
                evidence={"location_label": event.location_label}
            ))

        # SIGNAL 1: Unfamiliar Device
        if history.events and event.device_id not in history.known_devices:
            signals.append(RiskSignal(
                signal_name="UNFAMILIAR_DEVICE",
                score_contribution=25,
                severity="warning",
                reason=f"Device '{event.device_id}' has never been used by user '{event.user}'.",
                evidence={"device_id": event.device_id, "known_devices": list(history.known_devices)}
            ))

        # SIGNAL 2: Implausible Location Change (Impossible Travel Velocity)
        if history.events and location_known:
            last_event = history.events[-1]
            last_loc = last_event.location_label
            if last_loc in COORDINATES and last_loc != event.location_label:
                dist_km = haversine_distance_km(COORDINATES[last_loc], COORDINATES[event.location_label])
                time_elapsed_hours = max((event.timestamp - last_event.timestamp) / 3600.0, 0.001)
                speed_kmh = dist_km / time_elapsed_hours

                if speed_kmh > self.policy.impossible_travel_speed_kmh:
                    signals.append(RiskSignal(
                        signal_name="IMPLAUSIBLE_TRAVEL_VELOCITY",
                        score_contribution=50,
                        severity="danger",
                        reason=(
                            f"Implausible location change from '{last_loc}' to '{event.location_label}' "
                            f"({int(dist_km)} km in {int(time_elapsed_hours * 60)} mins = {int(speed_kmh)} km/h). "
                            f"Exceeds max travel threshold ({int(self.policy.impossible_travel_speed_kmh)} km/h)."
                        ),
                        evidence={
                            "from_location": last_loc,
                            "to_location": event.location_label,
                            "distance_km": round(dist_km, 1),
                            "elapsed_minutes": round(time_elapsed_hours * 60, 1),
                            "speed_kmh": round(speed_kmh, 1)
                        }
                    ))
                elif event.location_label not in history.known_locations:
                    signals.append(RiskSignal(
                        signal_name="UNFAMILIAR_LOCATION",
                        score_contribution=15,
                        severity="info",
                        reason=f"Location '{event.location_label}' has not been seen in user's historical profile.",
                        evidence={"location": event.location_label}
                    ))

        # SIGNAL 3: Unusual Activity Hours
        event_hour = datetime.fromtimestamp(event.timestamp, tz=timezone.utc).hour
        if history.typical_hours and len(history.typical_hours) >= 5:
            # Check if this hour is outside user's usual window (e.g. within 2 hours of typical activity)
            is_unusual = True
            for h in history.typical_hours:
                # Circular distance on 24hr clock
                hour_diff = min(abs(event_hour - h), 24 - abs(event_hour - h))
                if hour_diff <= 3:
                    is_unusual = False
                    break
            if is_unusual:
                signals.append(RiskSignal(
                    signal_name="UNUSUAL_ACTIVITY_HOURS",
                    score_contribution=15,
                    severity="warning",
                    reason=f"Event occurred at {event_hour}:00 UTC, which deviates substantially from user's typical login times.",
                    evidence={"event_hour_utc": event_hour, "typical_hours": sorted(list(set(history.typical_hours)))}
                ))

        # Track unfamiliar login
        if event.action.lower() == "login" and history.events and event.device_id not in history.known_devices:
            self.session_unfamiliar_logins[event.session_id] = event

        # SIGNAL 4: Sensitive Action Shortly After Unfamiliar Device Login
        if event.action.lower() in SENSITIVE_ACTIONS:
            unfamiliar_login = self.session_unfamiliar_logins.get(event.session_id)

            if unfamiliar_login:
                time_since_login = event.timestamp - unfamiliar_login.timestamp
                if time_since_login <= self.policy.sensitive_window_seconds:
                    signals.append(RiskSignal(
                        signal_name="SENSITIVE_ACTION_AFTER_UNFAMILIAR_LOGIN",
                        score_contribution=45,
                        severity="danger",
                        reason=(
                            f"Sensitive action '{event.action}' requested only {int(time_since_login)} seconds "
                            f"after initial login from an unfamiliar device '{unfamiliar_login.device_id}'."
                        ),
                        evidence={
                            "action": event.action,
                            "seconds_since_login": int(time_since_login),
                            "login_device": unfamiliar_login.device_id
                        }
                    ))
                else:
                    signals.append(RiskSignal(
                        signal_name="SENSITIVE_ACTION",
                        score_contribution=20,
                        severity="warning",
                        reason=f"Sensitive account modification '{event.action}' requested.",
                        evidence={"action": event.action}
                    ))
            else:
                signals.append(RiskSignal(
                    signal_name="SENSITIVE_ACTION",
                    score_contribution=15,
                    severity="info",
                    reason=f"Sensitive account operation '{event.action}' performed on recognized device.",
                    evidence={"action": event.action}
                ))

        # Calculate Total Deterministic Risk Score (Capped 0 - 100)
        total_score = min(sum(s.score_contribution for s in signals), 100)

        # Categorize into Risk Tiers
        if total_score >= self.policy.critical_risk_threshold:
            risk_tier = RiskTier.CRITICAL
            recommended_action = ResponseAction.SESSION_REVOCATION
        elif total_score >= self.policy.high_risk_threshold:
            risk_tier = RiskTier.HIGH
            recommended_action = ResponseAction.ANALYST_REVIEW
        elif total_score >= self.policy.medium_risk_threshold:
            risk_tier = RiskTier.MEDIUM
            recommended_action = ResponseAction.STEP_UP_VERIFICATION
        else:
            risk_tier = RiskTier.LOW
            recommended_action = ResponseAction.NO_ACTION

        # Deterministic Policy Rule Enforcement
        # Rule 1: Impossible travel OR Sensitive action after unfamiliar device -> Automatic Revocation
        has_critical_signal = any(
            s.signal_name in ["IMPLAUSIBLE_TRAVEL_VELOCITY", "SENSITIVE_ACTION_AFTER_UNFAMILIAR_LOGIN"]
            for s in signals
        )
        if has_critical_signal:
            action_enforced = ResponseAction.SESSION_REVOCATION
            self.revoked_sessions.add(event.session_id)
            session_is_revoked = True
            rejection_reason = "CRITICAL RISK: Session automatically terminated to protect account."
        elif recommended_action == ResponseAction.SESSION_REVOCATION:
            action_enforced = ResponseAction.SESSION_REVOCATION
            self.revoked_sessions.add(event.session_id)
            session_is_revoked = True
            rejection_reason = f"Risk score ({total_score}) exceeded critical threshold ({self.policy.critical_risk_threshold}). Session revoked."
        else:
            action_enforced = recommended_action
            session_is_revoked = False
            rejection_reason = None

        # Record this event to state
        history.add_baseline_event(event)
        if event.session_id not in self.session_events:
            self.session_events[event.session_id] = []
        self.session_events[event.session_id].append(event)

        evaluation = EvaluationResult(
            event=event,
            risk_score=total_score,
            risk_tier=risk_tier,
            recommended_action=recommended_action,
            action_enforced=action_enforced,
            signals=signals,
            confidence_level=confidence_level,
            ai_sequence_note=ai_pattern_note,
            session_is_revoked=session_is_revoked,
            rejection_reason=rejection_reason
        )
        self.all_audit_logs.append(evaluation)
        return evaluation
