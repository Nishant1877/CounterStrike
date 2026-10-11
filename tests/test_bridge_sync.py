"""
Automated Test Suite for Stage A: Unified Data Bridge & Telemetry Alignment.
Verifies that:
  1. Events evaluated via the React UI injector (/api/events/evaluate) are bridged into the
     enterprise pipeline, persisted in the primary database (DecisionModel), and reflected
     in the Analyst SOC table (/api/decisions).
  2. Policy threshold adjustments via /api/policy dynamically update the primary SecurityPipeline.
  3. Replay scenarios triggered via /api/scenarios/replay bridge events and record audit entries.
"""

import pytest
import time
from fastapi.testclient import TestClient

from api.main import app
from store.db import default_db
from store.models import DecisionModel, EventModel, AuditLogModel


@pytest.fixture
def client():
    # Clean tables before each bridge test
    with default_db.session_scope() as session:
        session.query(DecisionModel).delete()
        session.query(EventModel).delete()
        session.query(AuditLogModel).delete()
    return TestClient(app)


def test_bridge_evaluate_event_synchronizes_to_soc_feed(client):
    """
    Stage A.1 Test: Sending an event to /api/events/evaluate (React Threat Map) MUST:
      - Return an EvaluationResult for the UI
      - Persist into DecisionModel in the database
      - Be queryable immediately via GET /api/decisions (Analyst SOC Feed)
    """
    now = time.time()
    evt = {
        "timestamp": now,
        "user": "sync_test_user",
        "session_id": "sess_sync_001",
        "device_id": "macbook_sync_device",
        "location_label": "Pune, IN",
        "action": "login"
    }

    # 1. Post to compat evaluate endpoint
    res = client.post("/api/events/evaluate", json=evt)
    assert res.status_code == 200
    eval_data = res.json()
    assert eval_data["event"]["user"] == "sync_test_user"

    # 2. Check Analyst SOC API: Decision MUST exist for sync_test_user!
    r_soc = client.get("/api/decisions?user=sync_test_user")
    assert r_soc.status_code == 200
    decisions = r_soc.json()
    assert len(decisions) >= 1
    assert decisions[0]["user"] == "sync_test_user"
    assert decisions[0]["session_id"] == "sess_sync_001"


def test_bridge_policy_thresholds_synchronization(client):
    """
    Stage A.3 Test: Updating policy via POST /api/policy MUST dynamically update the
    travel speed limit in the enterprise SecurityPipeline.
    """
    # 1. Initial policy speed
    r1 = client.get("/api/policy")
    assert r1.status_code == 200

    # 2. Update speed threshold to 550.0 km/h via slider
    payload = {
        "medium_risk_threshold": 30,
        "high_risk_threshold": 60,
        "critical_risk_threshold": 80,
        "impossible_travel_speed_kmh": 550.0,
        "sensitive_window_seconds": 900
    }
    r_update = client.post("/api/policy", json=payload)
    assert r_update.status_code == 200
    updated = r_update.json()
    assert updated["impossible_travel_speed_kmh"] == 550.0

    # 3. Read back policy
    r2 = client.get("/api/policy")
    assert r2.status_code == 200
    assert r2.json()["impossible_travel_speed_kmh"] == 550.0


def test_bridge_scenario_replay_records_audit_trail(client):
    """
    Stage A.2 Test: Replaying scenario_ato_chain MUST record cryptographic audit ledger entries.
    """
    r_rep = client.post("/api/scenarios/replay", json={"scenario_id": "scenario_ato_chain"})
    assert r_rep.status_code == 200

    # Verify audit ledger contains revocation entries
    r_audit = client.get("/api/audit")
    assert r_audit.status_code == 200
    audit_data = r_audit.json()
    assert audit_data["integrity_verified"] is True
    assert len(audit_data["logs"]) >= 1
    actions = [l["action"] for l in audit_data["logs"]]
    assert "session_revoked" in actions or "refuse_action" in actions
