import pytest
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from api.main import app
from store.db import default_db
from store.models import SessionModel, ReviewCaseModel, QuarantineModel, StepUpChallengeModel
from core.autonomous_soar import AutonomousSOAR
from core.autonomous_worker import AutonomousWorker


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_autonomous_status_and_toggle(client):
    # Test status endpoint
    res = client.get("/api/autonomous/status")
    assert res.status_code == 200
    data = res.json()
    assert "autonomous_mode" in data
    assert "total_autonomous_actions" in data
    assert "blacklisted_ips_count" in data

    # Toggle off then on
    res_off = client.post("/api/autonomous/toggle", json={"enabled": False})
    assert res_off.status_code == 200
    assert res_off.json()["autonomous_mode"] is False

    res_on = client.post("/api/autonomous/toggle", json={"enabled": True})
    assert res_on.status_code == 200
    assert res_on.json()["autonomous_mode"] is True


def test_autonomous_kill_switch_and_quarantine(client):
    # Enable autonomous mode
    AutonomousSOAR.set_autonomous_mode(True)
    target_session = "sess_auto_test_kill_99"
    target_device = "dev_kali_auto_adversary"
    target_ip = "198.51.100.99"

    with default_db.session_scope() as db:
        # Create active test session
        sess = SessionModel(
            session_id=target_session,
            user="david",
            device_id=target_device,
            started_at=datetime.now(timezone.utc),
            last_event_at=datetime.now(timezone.utc),
            status="active"
        )
        db.add(sess)

        # Create open review case
        rev = ReviewCaseModel(
            case_id="case_auto_test_01",
            decision_id="dec_auto_test_01",
            session_id=target_session,
            user="david",
            status="open"
        )
        db.add(rev)

    # Process high-risk threat via AutonomousSOAR
    with default_db.session_scope() as db:
        actions = AutonomousSOAR.process_decision(
            decision_id="dec_auto_test_01",
            session_id=target_session,
            user="david",
            device_id=target_device,
            ip_address=target_ip,
            action="transfer_funds",
            risk_score=90,
            signals=[{"signal_name": "implausible_location_change", "severity": "danger"}],
            db=db
        )

    # Verify actions taken
    action_types = [a["action_type"] for a in actions]
    assert "AUTO_KILL_SWITCH" in action_types
    assert "AUTO_DEVICE_QUARANTINE" in action_types
    assert "AUTO_IP_BLACKLIST" in action_types
    assert "AUTO_CASE_CLOSED" in action_types

    # Verify session is revoked in DB
    with default_db.session_scope() as db:
        sess_db = db.query(SessionModel).filter(SessionModel.session_id == target_session).first()
        assert sess_db.status == "revoked"
        assert sess_db.revoked_by == "AutonomousSOAR:AutoPilot"

        case_db = db.query(ReviewCaseModel).filter(ReviewCaseModel.case_id == "case_auto_test_01").first()
        assert case_db.status == "auto_confirmed_attack"

    # Verify Gateway halts transaction on revoked session (R11 Monotonicity)
    req_payload = {
        "user": "david",
        "session_id": target_session,
        "device_id": "other_device",
        "location_label": "Unknown",
        "action": "transfer_funds",
        "amount": 1000.0
    }
    res_bank = client.post("/api/gateway/protected-action", json=req_payload)
    assert res_bank.status_code == 403
    assert "revoked" in res_bank.json()["detail"].lower()

    # Verify Gateway halts transaction on quarantined device
    req_quarantine_payload = {
        "user": "asha",
        "session_id": "sess_clean_random",
        "device_id": target_device,
        "location_label": "New York, USA",
        "action": "view_balance",
        "amount": 0.0
    }
    res_quarantine = client.post("/api/gateway/protected-action", json=req_quarantine_payload)
    assert res_quarantine.status_code == 403
    assert "quarantined" in res_quarantine.json()["detail"].lower()


def test_autonomous_demo_pulse(client):
    res = client.post("/api/autonomous/demo-pulse")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "pulse" in data
    assert "type" in data["pulse"]
    assert "latency_ms" in data["pulse"]
    assert data["pulse"]["latency_ms"] < 100.0


def test_autonomous_actions_feed(client):
    res = client.get("/api/autonomous/actions?limit=10")
    assert res.status_code == 200
    actions = res.json()
    assert isinstance(actions, list)
    assert len(actions) > 0
    assert "action_type" in actions[0]
    assert "latency_ms" in actions[0]
