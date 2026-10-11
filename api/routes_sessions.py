"""
Session Management & Enforcement Endpoints (A-03, Section 12 & 16.2).
Provides session status verification for protected client apps and challenge resolution.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from store.db import default_db
from store.models import SessionModel, StepUpChallengeModel
from store.audit import AuditLedger
from core.contracts import SessionState, DeviceState

router = APIRouter(prefix="/v1", tags=["Sessions"])


def get_db():
    with default_db.session_scope() as session:
        yield session


class RevokeRequest(BaseModel):
    reason: str
    analyst: str = "analyst-1"


class ChallengeResultRequest(BaseModel):
    result: str  # pass, fail, or expire


@router.get("/sessions/{session_id}/status", response_model=Dict[str, Any])
def get_session_status(session_id: str, db: Session = Depends(get_db)):
    """
    GET /v1/sessions/{id}/status
    Enforcement endpoint called by protected applications before serving requests.
    Returns: active, pending_verification, revoked, or ended.
    """
    session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found."
        )

    return {
        "session_id": session.session_id,
        "user": session.user,
        "device_id": session.device_id,
        "status": session.status,
        "revoked_at": session.revoked_at.isoformat() if session.revoked_at else None,
        "revoked_by": session.revoked_by,
        "last_event_at": session.last_event_at.isoformat()
    }


@router.post("/sessions/{session_id}/revoke", response_model=Dict[str, Any])
def revoke_session_manually(
    session_id: str,
    req: RevokeRequest,
    db: Session = Depends(get_db)
):
    """POST /v1/sessions/{id}/revoke: Analyst manually revokes an active session."""
    session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")

    if session.status == SessionState.REVOKED.value:
        return {"session_id": session_id, "status": "already_revoked"}

    now_utc = datetime.now(timezone.utc)
    session.status = SessionState.REVOKED.value
    session.revoked_at = now_utc
    session.revoked_by = f"analyst:{req.analyst} ({req.reason})"
    db.commit()

    AuditLedger.append_entry(
        session=db,
        actor=req.analyst,
        action="manual_revocation",
        target=session_id,
        before_state="active",
        after_state=f"revoked: {req.reason}"
    )

    return {
        "session_id": session_id,
        "status": SessionState.REVOKED.value,
        "revoked_at": now_utc.isoformat(),
        "revoked_by": session.revoked_by
    }


@router.post("/challenges/{challenge_id}/result", response_model=Dict[str, Any])
def resolve_challenge(
    challenge_id: str,
    req: ChallengeResultRequest,
    db: Session = Depends(get_db)
):
    """
    POST /v1/challenges/{id}/result
    Simulates or receives 2FA/step-up outcome (pass, fail, expire).
    """
    challenge = db.query(StepUpChallengeModel).filter(
        StepUpChallengeModel.challenge_id == challenge_id
    ).first()
    if not challenge:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Challenge not found.")

    now_utc = datetime.now(timezone.utc)
    challenge.status = req.result.lower()
    challenge.resolved_at = now_utc

    # Update associated session
    session = db.query(SessionModel).filter(SessionModel.session_id == challenge.session_id).first()
    if session:
        if req.result.lower() == "pass":
            session.status = SessionState.ACTIVE.value
        elif req.result.lower() in {"fail", "expire"}:
            session.status = SessionState.REVOKED.value
            session.revoked_at = now_utc
            session.revoked_by = f"challenge_{req.result.lower()}"

    db.commit()

    AuditLedger.append_entry(
        session=db,
        actor="StepUpVerification",
        action=f"challenge_{req.result.lower()}",
        target=challenge.session_id,
        after_state=f"session_status_{session.status if session else 'unknown'}"
    )

    return {
        "challenge_id": challenge_id,
        "result": challenge.status,
        "session_status": session.status if session else "unknown"
    }
