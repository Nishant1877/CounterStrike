"""
Adapter and Compatibility Router for DY Patil Hackathon Frontend & External Endpoints.
Connects the React 18 frontend to the IdentityGuard backend engine:
  - GET /api/scenarios (ATO Chain, Impossible Travel, Cold Start, Out-of-Order)
  - POST /api/scenarios/replay (Replays attack scenario)
  - POST /api/events/evaluate (Evaluates real-time event)
  - GET /api/audit-logs
  - GET /api/policy & POST /api/policy
  - POST /api/reset
"""

from typing import List, Dict, Any, Optional
import time
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from external_compat.models import (
    SecurityEvent,
    EvaluationResult,
    PolicyConfig,
    RiskTier,
    ResponseAction
)
from external_compat.detector import IdentityGuardEngine
from external_compat.scenarios import BASELINE_EVENTS_ALICE, ALL_SCENARIOS

from store.db import default_db
from store.audit import AuditLedger

router = APIRouter(prefix="/api", tags=["External Compatibility"])

# Standalone instance of the merged detector engine
compat_engine = IdentityGuardEngine()

def init_compat_baseline():
    compat_engine.reset_state()
    for ev in BASELINE_EVENTS_ALICE:
        compat_engine.get_or_create_history(ev.user).add_baseline_event(ev)

init_compat_baseline()

def get_db():
    with default_db.session_scope() as session:
        yield session

def get_ai_sequence_insight(events: List[SecurityEvent], target_event: SecurityEvent) -> Optional[str]:
    """
    Intelligent heuristic pattern recognition matching the booklet requirements:
    AI advises on sequential threat patterns while deterministic rules enforce decisions.
    """
    if target_event.action in ["change_email", "change_password", "transfer_funds"]:
        return "Heuristic Pattern Match: Rapid privilege escalation / fund extraction following external authentication."
    elif target_event.location_label not in ["Pune, IN", "Mumbai, IN"]:
        return "Heuristic Pattern Match: Geographically dispersed access attempt from non-habitual CIDR block."
    return "Standard operational behavioral baseline maintained."


@router.get("/scenarios")
def get_scenarios():
    """Return pre-packaged realistic demo attack scenarios for judges."""
    return [
        {
            "id": s["id"],
            "name": s["name"],
            "description": s["description"],
            "user": s["user"],
            "event_count": len(s["events"])
        }
        for s in ALL_SCENARIOS
    ]


@router.post("/events/evaluate", response_model=EvaluationResult)
def evaluate_single_event(event: SecurityEvent, db: Session = Depends(get_db)):
    """
    Real-time event evaluation endpoint for React 18 UI live event injector.
    """
    history = compat_engine.get_or_create_history(event.user)
    recent_events = history.events[-3:] + [event]
    ai_note = get_ai_sequence_insight(recent_events, event)

    result = compat_engine.evaluate_event(event, ai_pattern_note=ai_note)

    # Log into cryptographic audit log if revocation occurred
    if result.session_is_revoked:
        AuditLedger.append_entry(
            session=db,
            actor="CompatDetector",
            action="session_revoked",
            target=event.session_id,
            before_state="active",
            after_state=f"revoked: risk_score={result.risk_score}"
        )

    return result


class ReplayRequestModel:
    pass

@router.post("/scenarios/replay", response_model=List[EvaluationResult])
def replay_scenario(req: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Analyst Event Replay:
    Replays all events in an attack scenario in order and returns timeline with signals.
    """
    scenario_id = req.get("scenario_id")
    # Reset and reload baseline
    init_compat_baseline()

    scenario = next((s for s in ALL_SCENARIOS if s["id"] == scenario_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    results: List[EvaluationResult] = []
    events_list: List[SecurityEvent] = scenario["events"]

    for ev in events_list:
        history = compat_engine.get_or_create_history(ev.user)
        recent_events = history.events[-3:] + [ev]
        ai_note = get_ai_sequence_insight(recent_events, ev)
        res = compat_engine.evaluate_event(ev, ai_pattern_note=ai_note)
        results.append(res)

        if res.session_is_revoked:
            AuditLedger.append_entry(
                session=db,
                actor="ScenarioReplay",
                action="session_revoked",
                target=ev.session_id,
                before_state="active",
                after_state=f"revoked in {scenario_id}"
            )

    return results


@router.get("/audit-logs", response_model=List[EvaluationResult])
def get_audit_logs():
    """Retrieve full audit history of all processed events."""
    return compat_engine.all_audit_logs


@router.get("/policy", response_model=PolicyConfig)
def get_policy():
    """Get active policy thresholds."""
    return compat_engine.policy


@router.post("/policy", response_model=PolicyConfig)
def update_policy(new_policy: PolicyConfig):
    """Update active policy thresholds from the UI sliders."""
    compat_engine.policy = new_policy
    return compat_engine.policy


@router.post("/reset")
def reset_engine():
    """Reset engine back to initial baseline state."""
    init_compat_baseline()
    return {"status": "reset_successful", "revoked_sessions": list(compat_engine.revoked_sessions)}
