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


# In-memory OTP storage for interactive challenge verification: {session_id: {"otp": str, "challenge_id": str, "expires_at": float, "attempts_left": int}}
_active_otps: Dict[str, Dict[str, Any]] = {}


class CreateChallengeRequest(BaseModel):
    decision_id: Optional[str] = "manual_step_up"


class VerifyOtpRequest(BaseModel):
    otp: str


@router.post("/sessions/{session_id}/challenge", response_model=Dict[str, Any])
def create_session_challenge(
    session_id: str,
    req: CreateChallengeRequest = CreateChallengeRequest(),
    db: Session = Depends(get_db)
):
    """
    POST /v1/sessions/{id}/challenge (Stage D)
    Generates a 6-digit OTP challenge for a session requiring step-up authentication.
    Sets session status to 'pending_verification'.
    """
    import secrets
    import time
    from core.streaming import broadcaster

    session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")

    if session.status == SessionState.REVOKED.value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot challenge a terminally revoked session.")

    challenge_id = f"chl_{secrets.token_hex(8)}"
    otp = f"{secrets.randbelow(900000) + 100000}"  # Secure 6-digit OTP
    now_utc = datetime.now(timezone.utc)

    # Transition session state
    session.status = SessionState.PENDING_VERIFICATION.value
    
    # Create challenge record
    db_challenge = StepUpChallengeModel(
        challenge_id=challenge_id,
        session_id=session_id,
        decision_id=req.decision_id or "manual_step_up",
        status="open",
        created_at=now_utc
    )
    db.add(db_challenge)
    db.commit()

    # Store OTP in active store with 5-minute expiry
    _active_otps[session_id] = {
        "otp": otp,
        "challenge_id": challenge_id,
        "expires_at": time.time() + 300,
        "attempts_left": 3
    }

    # Log audit entry
    AuditLedger.append_entry(
        session=db,
        actor="IdentityGuardStepUp",
        action="issue_2fa_challenge",
        target=session_id,
        before_state="active",
        after_state=f"pending_verification: challenge_id={challenge_id}"
    )

    # Broadcast event
    broadcaster.publish_nowait(
        event_type="challenge_issued",
        data={
            "session_id": session_id,
            "challenge_id": challenge_id,
            "user": session.user,
            "status": "pending_verification"
        }
    )

    return {
        "challenge_id": challenge_id,
        "session_id": session_id,
        "status": "pending_verification",
        "otp_demo": otp,  # Exposed for automated testing & demo UI convenience
        "expires_in_seconds": 300
    }


@router.get("/sessions/{session_id}/challenge", response_model=Dict[str, Any])
def get_session_active_challenge(session_id: str, db: Session = Depends(get_db)):
    """GET /v1/sessions/{id}/challenge: Check for pending 2FA challenge."""
    session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")

    otp_info = _active_otps.get(session_id)
    if not otp_info:
        return {"session_id": session_id, "has_active_challenge": False}

    return {
        "session_id": session_id,
        "has_active_challenge": True,
        "challenge_id": otp_info["challenge_id"],
        "attempts_left": otp_info["attempts_left"],
        "otp_demo": otp_info["otp"]
    }


@router.post("/sessions/{session_id}/verify-otp", response_model=Dict[str, Any])
def verify_session_otp(
    session_id: str,
    req: VerifyOtpRequest,
    db: Session = Depends(get_db)
):
    """
    POST /v1/sessions/{id}/verify-otp (Stage D)
    Verifies user-submitted 6-digit OTP.
    - If valid: transitions session from 'pending_verification' back to 'active' and marks challenge 'passed'.
    - If invalid (exceeded 3 attempts): immediately triggers R11 terminal revocation.
    """
    import time
    from core.streaming import broadcaster

    session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")

    if session.status == SessionState.REVOKED.value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Session is terminally revoked.")

    otp_info = _active_otps.get(session_id)
    if not otp_info:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No active challenge for this session.")

    if time.time() > otp_info["expires_at"]:
        # Expired challenge
        del _active_otps[session_id]
        session.status = SessionState.REVOKED.value
        session.revoked_at = datetime.now(timezone.utc)
        session.revoked_by = "challenge_expired"
        
        challenge = db.query(StepUpChallengeModel).filter(StepUpChallengeModel.challenge_id == otp_info["challenge_id"]).first()
        if challenge:
            challenge.status = "expired"
            challenge.resolved_at = datetime.now(timezone.utc)
        db.commit()

        AuditLedger.append_entry(
            session=db,
            actor="IdentityGuardStepUp",
            action="challenge_expired_revocation",
            target=session_id,
            before_state="pending_verification",
            after_state="revoked"
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="2FA Challenge expired. Session revoked.")

    challenge = db.query(StepUpChallengeModel).filter(StepUpChallengeModel.challenge_id == otp_info["challenge_id"]).first()

    # Verify code
    if req.otp.strip() == otp_info["otp"]:
        # Success! Transition to ACTIVE
        del _active_otps[session_id]
        now_utc = datetime.now(timezone.utc)
        session.status = SessionState.ACTIVE.value
        if challenge:
            challenge.status = "passed"
            challenge.resolved_at = now_utc
        db.commit()

        AuditLedger.append_entry(
            session=db,
            actor="IdentityGuardStepUp",
            action="challenge_passed",
            target=session_id,
            before_state="pending_verification",
            after_state="active"
        )

        broadcaster.publish_nowait(
            event_type="challenge_resolved",
            data={
                "session_id": session_id,
                "challenge_id": otp_info["challenge_id"],
                "status": "passed",
                "session_status": "active"
            }
        )

        return {
            "session_id": session_id,
            "status": "active",
            "message": "Step-up verification passed. Session restored to active status."
        }
    else:
        # Invalid OTP
        otp_info["attempts_left"] -= 1
        if otp_info["attempts_left"] <= 0:
            # Max attempts exceeded -> Hard terminal revocation!
            del _active_otps[session_id]
            now_utc = datetime.now(timezone.utc)
            session.status = SessionState.REVOKED.value
            session.revoked_at = now_utc
            session.revoked_by = "challenge_failed_attempts_exceeded"
            if challenge:
                challenge.status = "failed"
                challenge.resolved_at = now_utc
            db.commit()

            AuditLedger.append_entry(
                session=db,
                actor="IdentityGuardStepUp",
                action="challenge_failed_revocation",
                target=session_id,
                before_state="pending_verification",
                after_state="revoked: max_otp_attempts_exceeded"
            )

            broadcaster.publish_nowait(
                event_type="session_revoked",
                data={
                    "session_id": session_id,
                    "challenge_id": otp_info["challenge_id"],
                    "status": "failed",
                    "session_status": "revoked"
                }
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Verification failed. Maximum OTP attempts exceeded. Session terminally revoked."
            )

        return {
            "session_id": session_id,
            "status": "pending_verification",
            "error": "Invalid OTP code",
            "attempts_left": otp_info["attempts_left"]
        }

