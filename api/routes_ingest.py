"""
Ingestion Endpoints for IdentityGuard (A-03, Section 5.4 & 16.1).
Accepts 5-field events, executes the pipeline, and enforces the session revocation gate.
"""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from core.contracts import RawEventInput, Decision, ResponseAction
from core.pipeline import SecurityPipeline
from core.normalize import LocationDatabase
from core.rules.engine import RuleEngine
from store.db import default_db
from store.models import EventModel, DecisionModel

router = APIRouter(prefix="/v1/events", tags=["Ingestion"])

# Dependency instances
_loc_db = LocationDatabase("config/locations.csv")
_rule_engine = RuleEngine("config/rules.yaml")
_pipeline = SecurityPipeline(location_db=_loc_db, rule_engine=_rule_engine)


def get_db():
    with default_db.session_scope() as session:
        yield session


def get_pipeline():
    return _pipeline


@router.post("", response_model=Dict[str, Any])
def ingest_single_event(
    event: RawEventInput,
    db: Session = Depends(get_db),
    pipeline: SecurityPipeline = Depends(get_pipeline)
):
    """
    POST /v1/events
    Primary ingress: receives 5-field event, runs pipeline, returns decision.
    If session is revoked, returns HTTP 403 (R11 enforcement).
    """
    try:
        decision, is_refused = pipeline.process_event(raw_event=event, db=db, mode="live")
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )

    response_payload = {
        "status": "refused" if is_refused else "accepted",
        "decision_id": decision.decision_id,
        "rule_set_version": decision.rule_set_version,
        "response": decision.response.value,
        "session": {
            "session_id": decision.session_id,
            "status": "revoked" if is_refused or decision.response == ResponseAction.REVOKE else ("pending_verification" if decision.response == ResponseAction.STEP_UP else "active")
        },
        "signals": [s.model_dump() for s in decision.signals],

        "rules_fired": decision.rules_fired,
        "deciding_rule": decision.deciding_rule,
        "advisory": decision.advisory.model_dump() if decision.advisory else None,
        "evidence": {
            "level": decision.evidence_level.value,
            "statement": decision.evidence_statement
        },
        "explanation": decision.explanation_text
    }

    if decision.response == ResponseAction.STEP_UP:
        from api.routes_sessions import _active_otps
        import secrets, time
        otp = f"{secrets.randbelow(900000) + 100000}"
        _active_otps[decision.session_id] = {
            "otp": otp,
            "challenge_id": f"chal_auto_{decision.decision_id[:8]}",
            "expires_at": time.time() + 300,
            "attempts_left": 3
        }
        response_payload["otp_demo"] = otp

    if is_refused:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=response_payload
        )

    return response_payload



@router.post("/batch", response_model=Dict[str, Any])
def ingest_batch_events(
    events: List[RawEventInput],
    db: Session = Depends(get_db),
    pipeline: SecurityPipeline = Depends(get_pipeline)
):
    """POST /v1/events/batch: Bulk ingest events for dataset evaluation."""
    results = []
    refused_count = 0

    for raw in events:
        try:
            decision, is_refused = pipeline.process_event(raw_event=raw, db=db, mode="live")
            if is_refused:
                refused_count += 1
            results.append({
                "event_id": decision.event_id,
                "response": decision.response.value,
                "deciding_rule": decision.deciding_rule,
                "is_refused": is_refused
            })
        except Exception as e:
            results.append({"error": str(e)})

    return {
        "total_processed": len(events),
        "refused_count": refused_count,
        "decisions": results
    }


@router.get("/{event_id}", response_model=Dict[str, Any])
def get_event_detail(event_id: str, db: Session = Depends(get_db)):
    """GET /v1/events/{event_id}: Retrieve event record and its stored decision."""
    evt = db.query(EventModel).filter(EventModel.event_id == event_id).first()
    if not evt:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")

    dec = db.query(DecisionModel).filter(DecisionModel.event_id == event_id).first()
    return {
        "event": {
            "event_id": evt.event_id,
            "user": evt.user,
            "device_id": evt.device_id,
            "location": evt.location_label_norm,
            "action": evt.action,
            "timestamp": evt.event_ts.isoformat(),
            "warnings": evt.get_warnings()
        },
        "decision": {
            "decision_id": dec.decision_id if dec else None,
            "response": dec.response if dec else None,
            "deciding_rule": dec.deciding_rule if dec else None,
            "explanation": dec.explanation_text if dec else None
        } if dec else None
    }
