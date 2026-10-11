"""
SQLAlchemy Database Models for IdentityGuard (A-03, Section 6).
Includes append-only event store, immutable decisions, session state machine,
step-up challenges, analyst reviews, quarantine, and hash-chained audit log.
"""

from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    create_engine,
    Index
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class EventModel(Base):
    """Append-only record of every received event (Section 6, Table events)."""
    __tablename__ = "events"

    event_id = Column(String(64), primary_key=True)
    ingest_seq = Column(Integer, nullable=False, index=True)
    received_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    event_ts = Column(DateTime, nullable=False, index=True)
    user = Column(String(128), nullable=False, index=True)
    device_id = Column(String(128), nullable=False)
    location_label_raw = Column(String(128), nullable=True)
    location_label_norm = Column(String(128), nullable=False)
    action = Column(String(64), nullable=False)
    session_id = Column(String(128), nullable=False, index=True)
    warnings_json = Column(Text, default="[]")
    ingest_status = Column(String(32), nullable=False, default="accepted")
    raw_payload_json = Column(Text, default="{}")

    def get_warnings(self) -> List[str]:
        try:
            return json.loads(self.warnings_json)
        except Exception:
            return []


class QuarantineModel(Base):
    """Rejected / malformed events (Section 5.5 & 6, Table quarantine)."""
    __tablename__ = "quarantine"

    id = Column(Integer, primary_key=True, autoincrement=True)
    raw_payload = Column(Text, nullable=False)
    reason = Column(String(256), nullable=False)
    received_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    resolved = Column(Boolean, default=False)


class SessionModel(Base):
    """Session state machine and enforcement (Section 6 & 12.1)."""
    __tablename__ = "sessions"

    session_id = Column(String(128), primary_key=True)
    user = Column(String(128), nullable=False, index=True)
    device_id = Column(String(128), nullable=False)
    started_at = Column(DateTime, nullable=False)
    last_event_at = Column(DateTime, nullable=False)
    status = Column(String(32), nullable=False, default="active")  # active, pending_verification, revoked, ended
    revoked_at = Column(DateTime, nullable=True)
    revoked_by = Column(String(128), nullable=True)  # rule_id or analyst username
    revoke_decision_id = Column(String(64), nullable=True)
    derived = Column(Boolean, default=True)  # Inferred session vs client-supplied
    login_device_unfamiliar = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class DecisionModel(Base):
    """Immutable decision record per judged event (Section 6, Table decisions)."""
    __tablename__ = "decisions"

    decision_id = Column(String(64), primary_key=True)
    event_id = Column(String(64), nullable=False, index=True)
    session_id = Column(String(128), nullable=False, index=True)
    user = Column(String(128), nullable=False, index=True)
    mode = Column(String(16), nullable=False, default="live")  # live or replay
    replay_run_id = Column(String(64), nullable=True, index=True)
    rule_set_version = Column(String(32), nullable=False, default="v1.0")
    signals_json = Column(Text, nullable=False, default="[]")
    advisory_json = Column(Text, nullable=True)
    rules_fired_json = Column(Text, nullable=False, default="[]")
    deciding_rule = Column(String(64), nullable=True)
    response = Column(String(32), nullable=False)
    evidence_level = Column(String(16), nullable=False)
    evidence_statement = Column(Text, nullable=False)
    explanation_text = Column(Text, nullable=False)
    supersedes_decision_id = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class StepUpChallengeModel(Base):
    """Step-up verification challenge records (Section 6 & 12.3)."""
    __tablename__ = "step_up_challenges"

    challenge_id = Column(String(64), primary_key=True)
    session_id = Column(String(128), nullable=False, index=True)
    decision_id = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="open")  # open, passed, failed, expired
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime, nullable=True)


class ReviewCaseModel(Base):
    """Analyst review queue cases (Section 6 & 11.1)."""
    __tablename__ = "review_cases"

    case_id = Column(String(64), primary_key=True)
    decision_id = Column(String(64), nullable=False, index=True)
    session_id = Column(String(128), nullable=False)
    user = Column(String(128), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="open")  # open, confirmed_attack, legitimate, needs_info
    analyst_note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime, nullable=True)


class AuditLogModel(Base):
    """Cryptographic hash-chained audit ledger (Section 6, Table audit_log)."""
    __tablename__ = "audit_log"

    audit_id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String(128), nullable=False)
    action = Column(String(64), nullable=False)
    target = Column(String(128), nullable=False)
    before_state = Column(Text, nullable=True)
    after_state = Column(Text, nullable=True)
    ts = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    prev_hash = Column(String(64), nullable=False)
    row_hash = Column(String(64), nullable=False)
