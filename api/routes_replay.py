"""
Replay API Endpoints for IdentityGuard (A-03, Section 14 & 16.3).
Provides sandboxed replay execution, candidate ruleset evaluation, and delta/diff reporting.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from store.db import default_db
from store.models import DecisionModel
from core.contracts import RawEventInput
from replay.runner import ReplayRunner

router = APIRouter(prefix="/api/replay", tags=["Replay"])

_replay_runner = ReplayRunner()

# In-memory storage of completed replay runs for fast diff querying
_completed_replay_runs: Dict[str, Dict[str, Any]] = {}


def get_db():
    with default_db.session_scope() as session:
        yield session


class ReplayEventsRequest(BaseModel):
    events: List[RawEventInput]
    candidate_rules_yaml: Optional[str] = None
    candidate_rules: Optional[Dict[str, Any]] = None
    replay_run_id: Optional[str] = None


class ReplaySliceRequest(BaseModel):
    user: Optional[str] = None
    session_id: Optional[str] = None
    start_ts: Optional[datetime] = None
    end_ts: Optional[datetime] = None
    candidate_rules: Optional[Dict[str, Any]] = None
    candidate_rule_yaml_path: Optional[str] = None
    replay_run_id: Optional[str] = None


@router.post("", response_model=Dict[str, Any])
def execute_replay_on_events(req: ReplayEventsRequest):
    """
    POST /api/replay
    Executes sandboxed replay over an array of RawEventInput objects.
    R10 guarantee: Completely isolated sandbox with deterministic decision stream hash.
    """
    try:
        res = _replay_runner.run_replay(
            events=req.events,
            candidate_rules_dict=req.candidate_rules,
            candidate_rule_yaml_path=req.candidate_rules_yaml,
            replay_run_id=req.replay_run_id
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Replay execution failed: {str(e)}"
        )

    # Format decisions for JSON response
    serialized_decisions = [
        {
            "decision_id": d.decision_id,
            "event_id": d.event_id,
            "session_id": d.session_id,
            "user": d.user,
            "response": d.response.value,
            "deciding_rule": d.deciding_rule,
            "rules_fired": d.rules_fired,
            "evidence_level": d.evidence_level.value,
            "explanation_text": d.explanation_text
        }
        for d in res["decisions"]
    ]

    out = {
        "replay_run_id": res["replay_run_id"],
        "rule_set_version": res["rule_set_version"],
        "total_events": res["total_events"],
        "decision_stream_hash": res["decision_stream_hash"],
        "duration_ms": res["duration_ms"],
        "decisions": serialized_decisions
    }

    _completed_replay_runs[res["replay_run_id"]] = out
    return out


@router.post("/slice", response_model=Dict[str, Any])
def execute_replay_on_db_slice(req: ReplaySliceRequest, db: Session = Depends(get_db)):
    """
    POST /api/replay/slice
    Extracts historical event slice from production store and executes replay in sandbox.
    Computes diff against live baseline decisions.
    """
    try:
        res = _replay_runner.run_replay_from_db_slice(
            db=db,
            user=req.user,
            session_id=req.session_id,
            start_ts=req.start_ts,
            end_ts=req.end_ts,
            candidate_rules_dict=req.candidate_rules,
            candidate_rule_yaml_path=req.candidate_rule_yaml_path,
            replay_run_id=req.replay_run_id
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Replay from DB slice failed: {str(e)}"
        )

    serialized_decisions = [
        {
            "decision_id": d.decision_id,
            "event_id": d.event_id,
            "session_id": d.session_id,
            "user": d.user,
            "response": d.response.value,
            "deciding_rule": d.deciding_rule,
            "rules_fired": d.rules_fired,
            "evidence_level": d.evidence_level.value,
            "explanation_text": d.explanation_text
        }
        for d in res["decisions"]
    ]

    out = {
        "replay_run_id": res["replay_run_id"],
        "rule_set_version": res["rule_set_version"],
        "total_events": res["total_events"],
        "decision_stream_hash": res["decision_stream_hash"],
        "duration_ms": res["duration_ms"],
        "diff": res.get("diff"),
        "decisions": serialized_decisions
    }

    _completed_replay_runs[res["replay_run_id"]] = out
    return out


@router.get("/{run_id}/diff", response_model=Dict[str, Any])
def get_replay_diff(run_id: str):
    """
    GET /api/replay/{run_id}/diff
    Retrieves the difference summary for a completed replay run.
    """
    if run_id not in _completed_replay_runs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Replay run '{run_id}' not found."
        )

    run_data = _completed_replay_runs[run_id]
    return {
        "replay_run_id": run_id,
        "decision_stream_hash": run_data.get("decision_stream_hash"),
        "diff": run_data.get("diff")
    }
