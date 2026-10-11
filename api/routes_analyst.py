"""
Analyst APIs for IdentityGuard (A-03, Section 15 & 16.3).
Powers the SOC dashboard: investigations, reviews, profile inspector, audit verification, and metrics.
"""

import json
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Query, status, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from store.db import default_db
from store.models import (
    DecisionModel,
    ReviewCaseModel,
    AuditLogModel,
    QuarantineModel,
    EventModel
)
from store.audit import AuditLedger
from api.routes_ingest import get_pipeline
from core.pipeline import SecurityPipeline
from core.streaming import broadcaster

router = APIRouter(prefix="/api", tags=["Analyst"])


@router.get("/stream/events")
async def stream_events():
    """
    GET /api/stream/events (Server-Sent Events)
    Delivers zero-latency live streams of decisions, threat detections, and metrics.
    No extra dependencies required; uses HTTP text/event-stream.
    """
    queue = await broadcaster.subscribe()

    async def event_generator():
        try:
            # Yield initial connection heartbeat
            initial_ping = json.dumps({"type": "connected", "timestamp": datetime.now(timezone.utc).isoformat()})
            yield f"event: connect\ndata: {initial_ping}\n\n"

            while True:
                try:
                    # Wait up to 15 seconds for next event, else send keep-alive comment
                    message = await asyncio.wait_for(queue.get(), timeout=15.0)
                    data_str = json.dumps(message)
                    event_type = message.get("type", "message")
                    yield f"event: {event_type}\ndata: {data_str}\n\n"
                except asyncio.TimeoutError:
                    # Heartbeat comment to keep connection alive through proxies
                    yield ": ping\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            await broadcaster.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """
    WebSocket endpoint for bi-directional live feeds.
    Clients receive real-time decisions, threat signals, and radar notifications.
    """
    await websocket.accept()
    queue = await broadcaster.subscribe()
    try:
        await websocket.send_json({"type": "connected", "timestamp": datetime.now(timezone.utc).isoformat()})
        while True:
            # Send events as they arrive or ping every 15s
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                await websocket.send_json(msg)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        await broadcaster.unsubscribe(queue)



def get_db():
    with default_db.session_scope() as session:
        yield session


class ReviewResolveRequest(BaseModel):
    status: str  # confirmed_attack, legitimate, needs_info
    analyst: str = "analyst-1"
    note: Optional[str] = None


@router.get("/decisions", response_model=List[Dict[str, Any]])
def list_decisions(
    user: Optional[str] = None,
    session_id: Optional[str] = None,
    response: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """GET /api/decisions: Retrieve logged decisions with optional filters."""
    query = db.query(DecisionModel).order_by(DecisionModel.created_at.desc())
    if user:
        query = query.filter(DecisionModel.user == user)
    if session_id:
        query = query.filter(DecisionModel.session_id == session_id)
    if response:
        query = query.filter(DecisionModel.response == response)

    decisions = query.limit(limit).all()
    results = []
    for d in decisions:
        results.append({
            "decision_id": d.decision_id,
            "event_id": d.event_id,
            "session_id": d.session_id,
            "user": d.user,
            "response": d.response,
            "deciding_rule": d.deciding_rule,
            "rules_fired": json.loads(d.rules_fired_json),
            "evidence_level": d.evidence_level,
            "evidence_statement": d.evidence_statement,
            "explanation": d.explanation_text,
            "signals": json.loads(d.signals_json),
            "created_at": d.created_at.isoformat()
        })
    return results


@router.get("/reviews", response_model=List[Dict[str, Any]])
def list_reviews(
    status_filter: Optional[str] = "open",
    db: Session = Depends(get_db)
):
    """GET /api/reviews: List cases in the analyst review queue."""
    query = db.query(ReviewCaseModel)
    if status_filter:
        query = query.filter(ReviewCaseModel.status == status_filter)
    cases = query.order_by(ReviewCaseModel.created_at.desc()).all()

    return [
        {
            "case_id": c.case_id,
            "decision_id": c.decision_id,
            "session_id": c.session_id,
            "user": c.user,
            "status": c.status,
            "analyst_note": c.analyst_note,
            "created_at": c.created_at.isoformat()
        }
        for c in cases
    ]


@router.post("/reviews/{case_id}/resolve", response_model=Dict[str, Any])
def resolve_review_case(
    case_id: str,
    req: ReviewResolveRequest,
    db: Session = Depends(get_db)
):
    """POST /api/reviews/{id}/resolve: Analyst confirms attack or approves legitimate activity."""
    case = db.query(ReviewCaseModel).filter(ReviewCaseModel.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Review case not found.")

    case.status = req.status
    case.analyst_note = f"[{req.analyst}] {req.note or ''}".strip()
    case.resolved_at = datetime.now(timezone.utc)
    db.commit()

    AuditLedger.append_entry(
        session=db,
        actor=req.analyst,
        action="resolve_review_case",
        target=case_id,
        before_state="open",
        after_state=f"{req.status}: {req.note or ''}"
    )

    return {
        "case_id": case_id,
        "status": case.status,
        "resolved_at": case.resolved_at.isoformat()
    }


@router.get("/users/{user_id}/profile", response_model=Dict[str, Any])
def get_user_profile(
    user_id: str,
    pipeline: SecurityPipeline = Depends(get_pipeline)
):
    """GET /api/users/{id}/profile: Reconstructs user diurnal pattern, trusted devices, and evidence."""
    prof = pipeline.profile_manager.get_or_create(user_id)
    smoothed_hours = prof.get_smoothed_hour_distribution()

    devices_list = [
        {
            "device_id": d.device_id,
            "state": d.state.value,
            "event_count": d.event_count,
            "login_count": d.login_count,
            "first_seen": d.first_seen.isoformat(),
            "last_seen": d.last_seen.isoformat()
        }
        for d in prof.known_devices.values()
    ]

    return {
        "user": prof.user,
        "total_events": prof.total_events,
        "active_days_count": len(prof.active_days),
        "home_location": prof.home_location,
        "home_timezone": prof.home_timezone,
        "evidence_level": prof.get_evidence_level().value,
        "hour_histogram": [round(s * 100, 2) for s in smoothed_hours],
        "devices": devices_list,
        "location_counts": prof.location_counts
    }


@router.get("/audit", response_model=Dict[str, Any])
def get_audit_trail(db: Session = Depends(get_db)):
    """GET /api/audit: Retrieve cryptographic audit log and chain integrity status."""
    is_valid, count, err = AuditLedger.verify_chain(db)
    logs = db.query(AuditLogModel).order_by(AuditLogModel.audit_id.desc()).limit(100).all()

    return {
        "integrity_verified": is_valid,
        "records_verified": count,
        "integrity_error": err,
        "logs": [
            {
                "audit_id": l.audit_id,
                "actor": l.actor,
                "action": l.action,
                "target": l.target,
                "before_state": l.before_state,
                "after_state": l.after_state,
                "ts": l.ts.isoformat(),
                "prev_hash": l.prev_hash,
                "row_hash": l.row_hash
            }
            for l in logs
        ]
    }


@router.get("/quality", response_model=Dict[str, Any])
def get_data_quality_metrics(db: Session = Depends(get_db)):
    """GET /api/quality: Operational counters for data hygiene (Section 15)."""
    quarantined = db.query(QuarantineModel).count()
    events = db.query(EventModel).all()

    unknown_locations = sum(1 for e in events if e.location_label_norm == "UNKNOWN")
    late_events = sum(1 for e in events if "late_event" in e.warnings_json)
    clock_skew_events = sum(1 for e in events if "clock_skew" in e.warnings_json)

    return {
        "total_events": len(events),
        "quarantined_events": quarantined,
        "unknown_location_events": unknown_locations,
        "late_events": late_events,
        "clock_skew_events": clock_skew_events
    }
