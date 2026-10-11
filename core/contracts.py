"""
Data contracts for IdentityGuard (A-03).
Strictly adheres to requirement R1 (5-field input contract), R3, R4, R7, R8, R9, R11.
"""

from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class IngestStatus(str, Enum):
    ACCEPTED = "accepted"
    ACCEPTED_WITH_WARNINGS = "accepted_with_warnings"
    REJECTED = "rejected"
    REFUSED = "refused"


class SignalStatus(str, Enum):
    TRIGGERED = "triggered"
    NOT_TRIGGERED = "not_triggered"
    NOT_EVALUABLE = "not_evaluable"


class EvidenceLevel(str, Enum):
    NONE = "none"
    LIMITED = "limited"
    SUFFICIENT = "sufficient"


class ResponseAction(str, Enum):
    NO_ACTION = "no_action"
    STEP_UP = "step_up"
    ANALYST_REVIEW = "analyst_review"
    REVOKE = "revoke"
    REFUSED_SESSION_REVOKED = "refused_session_revoked"


class DeviceState(str, Enum):
    UNFAMILIAR = "unfamiliar"
    VERIFIED = "verified"
    KNOWN = "known"
    FLAGGED = "flagged"


class SessionState(str, Enum):
    ACTIVE = "active"
    PENDING_VERIFICATION = "pending_verification"
    REVOKED = "revoked"
    ENDED = "ended"


class RawEventInput(BaseModel):
    """
    R1: Strict 5-field event schema received by the engine.
    No IP, network data, device fingerprint or session ID required.
    """
    model_config = ConfigDict(extra="ignore")

    timestamp: Union[str, datetime] = Field(
        ..., description="ISO 8601 timestamp with offset or Z"
    )
    user: str = Field(..., description="User identifier")
    device_id: Optional[str] = Field(
        default=None, description="Device identifier (empty/missing accepted with warning)"
    )
    location_label: Optional[str] = Field(
        default=None, description="Location label e.g. city name (empty/missing accepted with warning)"
    )
    action: str = Field(..., description="Action name from action vocabulary")
    event_id: Optional[str] = Field(default=None, description="Sender-supplied event_id (optional)")
    session_id: Optional[str] = Field(default=None, description="Sender-supplied session_id (optional)")


class NormalizedEvent(BaseModel):
    """Normalized internal representation after validation and alias mapping."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: str
    received_at: datetime
    ingest_seq: int
    event_ts: datetime
    user: str
    device_id: str
    location_label_raw: str
    location_label_norm: str
    action: str
    session_id: str
    warnings: List[str] = Field(default_factory=list)
    ingest_status: IngestStatus = IngestStatus.ACCEPTED
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


class SignalResult(BaseModel):
    """
    R3, Section 9.1: Universal signal result structure.
    Every detector returns the exact same shape.
    """
    signal_id: str
    name: str
    status: SignalStatus
    value: Any
    reference: Any
    reason: str
    evidence: EvidenceLevel
    inputs: List[str] = Field(default_factory=list)


class AdvisoryResult(BaseModel):
    """
    R9, Section 13.2: AI sequence model advisory output.
    advisory is strictly True to avoid mixing with deterministic signals.
    """
    advisory: bool = True
    label: str  # typical, unusual, suspicious
    score: float  # 0.0 to 1.0 anomaly/rarity score
    top_transitions: List[Dict[str, Any]] = Field(default_factory=list)
    reason: str
    evidence: str
    model_version: str = "markov-v1"


class Decision(BaseModel):
    """
    R8, Section 6, 16.1: Immutable decision record per evaluated event.
    """
    decision_id: str
    event_id: str
    session_id: str
    user: str
    mode: str = "live"  # 'live' or 'replay'
    replay_run_id: Optional[str] = None
    rule_set_version: str = "v1"
    signals: List[SignalResult] = Field(default_factory=list)
    advisory: Optional[AdvisoryResult] = None
    rules_fired: List[str] = Field(default_factory=list)
    deciding_rule: Optional[str] = None
    response: ResponseAction
    evidence_level: EvidenceLevel
    evidence_statement: str
    explanation_text: str
    supersedes_decision_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.utcnow())
