from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
import time

class ResponseAction(str, Enum):
    NO_ACTION = "no_action"
    STEP_UP_VERIFICATION = "step_up_verification"
    SESSION_REVOCATION = "session_revocation"
    ANALYST_REVIEW = "analyst_review"

class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityEvent(BaseModel):
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp of event")
    user: str = Field(..., description="Unique username or ID")
    session_id: str = Field(..., description="Unique session identifier")
    device_id: str = Field(..., description="Hardware / Browser device fingerprint")
    location_label: str = Field(..., description="City or Region label, e.g. 'Pune, IN'")
    action: str = Field(..., description="Action performed, e.g. login, view_dashboard, change_email, transfer_funds")
    details: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Metadata such as amount, ip, user_agent")

class RiskSignal(BaseModel):
    signal_name: str
    score_contribution: int
    severity: str  # info, warning, danger
    reason: str
    evidence: Dict[str, Any]

class EvaluationResult(BaseModel):
    event: SecurityEvent
    risk_score: int  # 0 to 100
    risk_tier: RiskTier
    recommended_action: ResponseAction
    action_enforced: ResponseAction
    signals: List[RiskSignal]
    confidence_level: str  # "high", "medium", "limited_information (cold start)"
    ai_sequence_note: Optional[str] = None
    session_is_revoked: bool = False
    rejection_reason: Optional[str] = None

class PolicyConfig(BaseModel):
    medium_risk_threshold: int = 35
    high_risk_threshold: int = 65
    critical_risk_threshold: int = 80
    impossible_travel_speed_kmh: float = 750.0  # Commercial flight max speed
    sensitive_window_seconds: int = 600  # 10 minutes
