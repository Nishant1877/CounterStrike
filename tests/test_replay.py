"""
Tests for Stage 4: Sandboxed Replay Engine (R10) & Determinism.
Verifies:
  1. Sandbox isolation: Replay does NOT pollute live state, live DB, or profiles.
  2. R10 Determinism: Two replay runs over the exact same event sequence produce identical SHA-256 hashes.
  3. Replay Diff computation: Correct classification into 'stricter', 'weaker', and 'unchanged'.
  4. API endpoints: POST /api/replay and GET /api/replay/{run_id}/diff work correctly.
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from replay.runner import ReplayRunner
from replay.diff import ReplayDiffCalculator
from replay.hasher import compute_decision_stream_hash
from core.contracts import RawEventInput, ResponseAction, EvidenceLevel
from store.db import default_db
from store.models import EventModel, DecisionModel, SessionModel
from api.main import app


@pytest.fixture
def client():
    with default_db.session_scope() as session:
        session.query(DecisionModel).delete()
        session.query(EventModel).delete()
        session.query(SessionModel).delete()
    return TestClient(app)


def test_sandboxed_replay_determinism_r10():
    """
    R10 Test: Replaying the same sequence twice MUST yield bit-exact identical decision stream hashes.
    """
    runner = ReplayRunner()

    events = [
        RawEventInput(
            timestamp="2026-10-11T10:00:00Z",
            user="asha",
            device_id="dev-phone",
            location_label="Pune",
            action="login"
        ),
        RawEventInput(
            timestamp="2026-10-11T10:05:00Z",
            user="asha",
            device_id="dev-phone",
            location_label="Pune",
            action="view_balance"
        ),
        RawEventInput(
            timestamp="2026-10-11T10:08:00Z",
            user="asha",
            device_id="dev-phone",
            location_label="Pune",
            action="request_transfer"
        ),
        RawEventInput(
            timestamp="2026-10-11T10:15:00Z",
            user="asha",
            device_id="dev-phone",
            location_label="London",
            action="login"  # S2 Implausible speed!
        )
    ]

    res1 = runner.run_replay(events)
    res2 = runner.run_replay(events)

    assert res1["total_events"] == 4
    assert res2["total_events"] == 4
    assert res1["decision_stream_hash"] == res2["decision_stream_hash"]
    assert len(res1["decision_stream_hash"]) == 64  # Valid SHA-256 hex string


def test_sandboxed_replay_isolation_no_leakage():
    """
    Verifies that running a replay run in the sandbox leaves the primary database completely untouched.
    """
    runner = ReplayRunner()

    with default_db.session_scope() as session:
        session.query(DecisionModel).delete()
        session.query(EventModel).delete()

    events = [
        RawEventInput(
            timestamp="2026-10-11T12:00:00Z",
            user="test_isolation_user",
            device_id="dev-iso",
            location_label="Pune",
            action="login"
        )
    ]

    res = runner.run_replay(events)
    assert res["total_events"] == 1

    # Check live DB: Must NOT contain test_isolation_user!
    with default_db.session_scope() as session:
        evt_in_live = session.query(EventModel).filter(EventModel.user == "test_isolation_user").first()
        dec_in_live = session.query(DecisionModel).filter(DecisionModel.user == "test_isolation_user").first()
        assert evt_in_live is None
        assert dec_in_live is None


def test_replay_diff_calculator_classifications():
    """
    Verifies correct categorization into stricter, weaker, and unchanged.
    """
    from core.contracts import Decision

    d_base_1 = Decision(
        decision_id="d1",
        event_id="e1",
        session_id="s1",
        user="asha",
        response=ResponseAction.NO_ACTION,
        evidence_level=EvidenceLevel.SUFFICIENT,
        evidence_statement="Normal",
        explanation_text="Normal action"
    )
    d_base_2 = Decision(
        decision_id="d2",
        event_id="e2",
        session_id="s1",
        user="asha",
        response=ResponseAction.REVOKE,
        evidence_level=EvidenceLevel.SUFFICIENT,
        evidence_statement="Attack detected",
        explanation_text="Revoked"
    )

    # Replay where e1 becomes stricter (step_up), e2 becomes weaker (analyst_review)
    d_rep_1 = Decision(
        decision_id="r1",
        event_id="e1",
        session_id="s1",
        user="asha",
        response=ResponseAction.STEP_UP,
        evidence_level=EvidenceLevel.SUFFICIENT,
        evidence_statement="Stricter policy",
        explanation_text="Step up requested"
    )
    d_rep_2 = Decision(
        decision_id="r2",
        event_id="e2",
        session_id="s1",
        user="asha",
        response=ResponseAction.ANALYST_REVIEW,
        evidence_level=EvidenceLevel.SUFFICIENT,
        evidence_statement="Weaker policy",
        explanation_text="Analyst review"
    )

    diff = ReplayDiffCalculator.compare(
        baseline_decisions=[d_base_1, d_base_2],
        replay_decisions=[d_rep_1, d_rep_2]
    )

    assert diff["total_events"] == 2
    assert diff["stricter_count"] == 1
    assert diff["stricter"][0]["event_id"] == "e1"
    assert diff["weaker_count"] == 1
    assert diff["weaker"][0]["event_id"] == "e2"
    assert diff["unchanged_count"] == 0
    assert diff["impact_percentage"] == 100.0


def test_api_replay_endpoints(client):
    """
    Tests POST /api/replay and GET /api/replay/{run_id}/diff via the HTTP client.
    """
    payload = {
        "events": [
            {
                "timestamp": "2026-10-11T14:00:00Z",
                "user": "elena",
                "device_id": "dev-elena-1",
                "location_label": "Pune",
                "action": "login"
            },
            {
                "timestamp": "2026-10-11T14:02:00Z",
                "user": "elena",
                "device_id": "dev-elena-1",
                "location_label": "Pune",
                "action": "view_balance"
            }
        ]
    }

    r_post = client.post("/api/replay", json=payload)
    assert r_post.status_code == 200
    data = r_post.json()
    assert data["total_events"] == 2
    assert len(data["decision_stream_hash"]) == 64
    run_id = data["replay_run_id"]

    r_diff = client.get(f"/api/replay/{run_id}/diff")
    assert r_diff.status_code == 200
    diff_data = r_diff.json()
    assert diff_data["replay_run_id"] == run_id
    assert diff_data["decision_stream_hash"] == data["decision_stream_hash"]
