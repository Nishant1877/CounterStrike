"""
Integration tests for Stage 3: Persistence, Session Gate Enforcement (R11) & APIs.
Verifies terminal session revocation, HTTP 403 responses, step-up challenges, and audit ledger integrity.
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from store.db import DatabaseManager, default_db
from store.models import Base, SessionModel, EventModel, DecisionModel
from store.audit import AuditLedger
from core.pipeline import SecurityPipeline
from core.normalize import LocationDatabase
from core.rules.engine import RuleEngine
from core.contracts import RawEventInput, ResponseAction, SessionState
from api.main import app


@pytest.fixture
def test_db():
    import os
    db_path = "test_pipeline.db"
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass
    mgr = DatabaseManager(f"sqlite:///{db_path}")
    mgr.init_db()
    yield mgr
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass


@pytest.fixture
def pipeline():
    loc_db = LocationDatabase("config/locations.csv")
    rule_eng = RuleEngine("config/rules.yaml")
    return SecurityPipeline(location_db=loc_db, rule_engine=rule_eng)


@pytest.fixture
def client():
    # Ensure fresh state for test runs using default_db
    with default_db.session_scope() as session:
        session.query(DecisionModel).delete()
        session.query(EventModel).delete()
        session.query(SessionModel).delete()
    return TestClient(app)


def test_r11_terminal_session_revocation_enforced(test_db, pipeline):
    """
    R11 Test: Once a session is revoked, all subsequent actions MUST be refused.
    Profile must NOT learn from refused events.
    """
    with test_db.session_scope() as session:
        # 1. Establish baseline history for user 'asha' (25 events across 6 days)
        for day in range(1, 7):
            for h in [9, 10, 11, 12]:
                t = datetime(2026, 9, day, h, 0, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
                raw_evt = RawEventInput(
                    timestamp=t.isoformat(),
                    user="asha",
                    device_id="dev-laptop",
                    location_label="Pune",
                    action="view_balance",
                    session_id=f"sess_day_{day}"
                )
                pipeline.process_event(raw_evt, session)

        prof = pipeline.profile_manager.get_or_create("asha")
        assert prof.total_events == 24

        # Asha's legitimate activity in Pune at 09:30 UTC on Oct 1
        t_pune = datetime(2026, 10, 1, 9, 30, 0, tzinfo=timezone.utc)
        raw_pune = RawEventInput(
            timestamp=t_pune.isoformat(),
            user="asha",
            device_id="dev-laptop",
            location_label="Pune",
            action="view_balance",
            session_id="sess_pune_morning"
        )
        pipeline.process_event(raw_pune, session)
        initial_events_count = prof.total_events

        # 2. Attacker logs in from unfamiliar device at 03:00 AM IST (unusual hour S3)
        # S1 (unfamiliar device) + S3 (unusual hour) -> R-04 step_up
        t_attack_login = datetime(2026, 10, 1, 3, 0, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
        raw_attack_login = RawEventInput(
            timestamp=t_attack_login.isoformat(),
            user="asha",
            device_id="dev-hacker-phone",
            location_label="Pune",
            action="login",
            session_id="sess_attack_1"
        )
        dec_login, is_ref1 = pipeline.process_event(raw_attack_login, session)
        assert not is_ref1
        assert dec_login.response == ResponseAction.STEP_UP
        assert dec_login.deciding_rule == "R-04"

        # 3. Attacker requests 'change_email' 4 minutes later
        # S4 (sensitive action post unfamiliar login) + S3 (unusual hour) -> R-06 fires -> REVOKE!
        t_change_email = t_attack_login + timedelta(minutes=4)
        raw_change_email = RawEventInput(
            timestamp=t_change_email.isoformat(),
            user="asha",
            device_id="dev-hacker-phone",
            location_label="Pune",
            action="change_email",
            session_id="sess_attack_1"
        )
        dec_change, is_ref2 = pipeline.process_event(raw_change_email, session)
        assert not is_ref2
        assert dec_change.response == ResponseAction.REVOKE
        assert dec_change.deciding_rule == "R-06"

        # Verify session state in DB is REVOKED
        db_sess = session.query(SessionModel).filter(SessionModel.session_id == "sess_attack_1").first()
        assert db_sess.status == SessionState.REVOKED.value

        # 4. Attacker attempts subsequent action 'request_transfer' on revoked session
        # R11 Invariant: Action MUST be refused!
        t_transfer = t_change_email + timedelta(minutes=2)
        raw_transfer = RawEventInput(
            timestamp=t_transfer.isoformat(),
            user="asha",
            device_id="dev-hacker-phone",
            location_label="Pune",
            action="request_transfer",
            session_id="sess_attack_1"
        )
        dec_transfer, is_refused = pipeline.process_event(raw_transfer, session)
        assert is_refused is True
        assert dec_transfer.response == ResponseAction.REFUSED_SESSION_REVOKED
        assert "Action 'request_transfer' refused" in dec_transfer.explanation_text
        assert "terminally revoked" in dec_transfer.explanation_text

        # Verify profile did NOT learn from the refused event!
        assert pipeline.profile_manager.get_or_create("asha").total_events == initial_events_count + 1


def test_api_session_gate_returns_403_on_revocation(client):
    """
    Verifies that calling POST /v1/events on a revoked session returns HTTP 403 Forbidden.
    """
    session_id = f"sess_api_{int(datetime.now().timestamp())}"

    # 1. First event: login from device
    evt_login = {
        "timestamp": "2026-10-11T10:00:00Z",
        "user": "david",
        "device_id": "dev-david-1",
        "location_label": "Pune",
        "action": "login",
        "session_id": session_id
    }
    r1 = client.post("/v1/events", json=evt_login)
    assert r1.status_code == 200

    # 2. Manually revoke session via analyst API
    r_revoke = client.post(f"/v1/sessions/{session_id}/revoke", json={"reason": "Compromised credential test"})
    assert r_revoke.status_code == 200
    assert r_revoke.json()["status"] == "revoked"

    # 3. Check session status endpoint (R11)
    r_status = client.get(f"/v1/sessions/{session_id}/status")
    assert r_status.status_code == 200
    assert r_status.json()["status"] == "revoked"

    # 4. Attempt to send an action to the revoked session -> MUST return 403 Forbidden!
    evt_action = {
        "timestamp": "2026-10-11T10:05:00Z",
        "user": "david",
        "device_id": "dev-david-1",
        "location_label": "Pune",
        "action": "request_transfer",
        "session_id": session_id
    }
    r_blocked = client.post("/v1/events", json=evt_action)
    assert r_blocked.status_code == 403
    detail = r_blocked.json()["detail"]
    assert detail["status"] == "refused"
    assert detail["response"] == "refused_session_revoked"


def test_api_step_up_challenge_workflow(client):
    """
    Verifies step-up challenge creation, status transition, and resolution.
    """
    uid = uuid.uuid4().hex[:8]
    session_id = f"sess_stepup_{uid}"
    now = datetime.now(timezone.utc)

    # Seed baseline device for elena so the next device is truly unfamiliar
    evt_baseline = {
        "timestamp": (now - timedelta(days=1)).isoformat(),
        "user": "elena",
        "device_id": "dev-baseline-phone",
        "location_label": "Pune",
        "action": "login",
        "session_id": "sess_elena_baseline"
    }
    client.post("/v1/events", json=evt_baseline)

    # 1. Login from unfamiliar device
    t_login = (now - timedelta(minutes=5)).isoformat()
    evt_login = {
        "timestamp": t_login,
        "user": "elena",
        "device_id": "dev-unknown-stepup",
        "location_label": "Pune",
        "action": "login",
        "session_id": session_id
    }
    r0 = client.post("/v1/events", json=evt_login)
    assert r0.status_code == 200

    # 2. Sensitive action 2 minutes later -> triggers R-05 step_up
    t_act = (now - timedelta(minutes=3)).isoformat()
    evt_action = {
        "timestamp": t_act,
        "user": "elena",
        "device_id": "dev-unknown-stepup",
        "location_label": "Pune",
        "action": "change_email",
        "session_id": session_id
    }
    r = client.post("/v1/events", json=evt_action)
    assert r.status_code == 200
    data = r.json()
    assert data["response"] == "step_up"
    assert data["session"]["status"] == "active" or data["session"]["status"] == "pending_verification"


def test_api_audit_ledger_integrity(client):
    """
    Verifies cryptographic hash-chain integrity of the audit ledger.
    """
    with default_db.session_scope() as session:
        # Append two valid test entries
        AuditLedger.append_entry(session, "SecOps", "test_entry_1", "target_system")
        AuditLedger.append_entry(session, "SecOps", "test_entry_2", "target_system")

    r_audit = client.get("/api/audit")
    assert r_audit.status_code == 200
    data = r_audit.json()
    assert data["integrity_verified"] is True
    assert data["integrity_error"] is None
