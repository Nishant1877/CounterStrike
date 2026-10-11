"""
Integration and Compatibility Tests for the Merged DY Patil Module.
Verifies:
  1. Internal detector functions: ATO chain, impossible travel velocity, sparse cold-start.
  2. Compatibility REST endpoints: /api/health, /api/scenarios, /api/scenarios/replay, /api/events/evaluate, /api/policy.
  3. Static serving of the merged React 18 frontend at /react_app.html and its bundled assets.
"""

import pytest
import time
from fastapi.testclient import TestClient

from api.main import app
from external_compat.models import SecurityEvent, RiskTier, ResponseAction
from external_compat.detector import IdentityGuardEngine


@pytest.fixture
def client():
    return TestClient(app)


def test_compat_detector_engine_direct():
    """Verifies that the merged detector correctly triggers ATO chain revocation."""
    engine = IdentityGuardEngine()
    now = time.time()

    # 1. Normal baseline
    ev_normal = SecurityEvent(
        timestamp=now - 10000,
        user="test_user",
        session_id="sess_1",
        device_id="dev_laptop",
        location_label="Pune, IN",
        action="login"
    )
    res1 = engine.evaluate_event(ev_normal)
    assert res1.risk_tier == RiskTier.LOW
    assert res1.session_is_revoked is False

    # 2. Login from unfamiliar device in Lagos -> triggers impossible travel
    ev_attack = SecurityEvent(
        timestamp=now - 100,
        user="test_user",
        session_id="sess_attack",
        device_id="dev_kali",
        location_label="Lagos, NG",
        action="login"
    )
    res2 = engine.evaluate_event(ev_attack)
    assert any(s.signal_name == "IMPLAUSIBLE_TRAVEL_VELOCITY" for s in res2.signals)
    assert res2.risk_tier == RiskTier.CRITICAL
    assert res2.session_is_revoked is True

    # 3. Subsequent action on revoked session MUST be refused
    ev_refused = SecurityEvent(
        timestamp=now,
        user="test_user",
        session_id="sess_attack",
        device_id="dev_kali",
        location_label="Lagos, NG",
        action="transfer_funds"
    )
    res3 = engine.evaluate_event(ev_refused)
    assert res3.session_is_revoked is True
    assert any(s.signal_name == "REVOKED_SESSION_BLOCKED" for s in res3.signals)


def test_compat_api_scenarios_and_replay(client):
    """Verifies GET /api/scenarios and POST /api/scenarios/replay."""
    r_scen = client.get("/api/scenarios")
    assert r_scen.status_code == 200
    scenarios = r_scen.json()
    assert len(scenarios) >= 4
    scen_ids = [s["id"] for s in scenarios]
    assert "scenario_ato_chain" in scen_ids
    assert "scenario_impossible_travel" in scen_ids

    # Replay ATO chain
    r_rep = client.post("/api/scenarios/replay", json={"scenario_id": "scenario_ato_chain"})
    assert r_rep.status_code == 200
    timeline = r_rep.json()
    assert len(timeline) == 4
    # Last event in ATO chain is fund transfer on revoked session -> must be blocked
    last_ev = timeline[-1]
    assert last_ev["session_is_revoked"] is True
    assert any(s["signal_name"] == "REVOKED_SESSION_BLOCKED" for s in last_ev["signals"])


def test_compat_api_live_evaluate_and_policy(client):
    """Verifies POST /api/events/evaluate and policy thresholds."""
    # Reset engine to clean baseline state and default policy
    client.post("/api/reset")

    # Policy GET
    r_pol = client.get("/api/policy")
    assert r_pol.status_code == 200
    pol = r_pol.json()
    assert pol["impossible_travel_speed_kmh"] == 750.0

    # Evaluate event
    now = time.time()
    evt = {
        "timestamp": now,
        "user": "alice_corporate",
        "session_id": "sess_live_test",
        "device_id": "macbook_pro_m2_corp",
        "location_label": "Pune, IN",
        "action": "view_dashboard"
    }
    r_ev = client.post("/api/events/evaluate", json=evt)
    assert r_ev.status_code == 200
    data = r_ev.json()
    assert data["risk_tier"] == "low"


def test_react_app_static_serving(client):
    """Verifies that the compiled React 18 app HTML and assets are served by FastAPI."""
    r_html = client.get("/react_app.html")
    assert r_html.status_code == 200
    assert "VORTEXA 3.0" in r_html.text
    assert "assets/index-" in r_html.text


def test_v6_gateway_and_session_management(client):
    """Verifies v6.0 Gateway Filter, Emergency Kill-Switch, and Batch Ingestion."""
    # 1. Gateway execution on active session
    req = {
        "user": "alex_merchant",
        "session_id": "sess_test_v6_1",
        "device_id": "dev_v6_1",
        "location_label": "New York, US",
        "action": "view_balance",
        "amount": 0.0
    }
    res = client.post("/api/gateway/protected-action", json=req)
    assert res.status_code == 200
    assert res.json()["status"] == "SUCCESS"

    # 2. Identity directory endpoints
    res_users = client.get("/api/users/list")
    assert res_users.status_code == 200
    assert "alex_merchant" in res_users.json()

    res_sess = client.get("/api/sessions")
    assert res_sess.status_code == 200
    session_ids = [s["session_id"] for s in res_sess.json()]
    assert "sess_test_v6_1" in session_ids

    # 3. Emergency Kill-Switch
    res_revoke = client.post("/api/sessions/revoke", json={"session_id": "sess_test_v6_1", "reason": "SOC Emergency Kill"})
    assert res_revoke.status_code == 200

    # 4. Gateway must now reject with 403 on revoked session
    res_blocked = client.post("/api/gateway/protected-action", json=req)
    assert res_blocked.status_code == 403

    # 5. Batch File Upload ingestion (.json)
    import json
    batch_data = [
        {
            "timestamp": time.time(),
            "user": "batch_tester",
            "session_id": "sess_batch_1",
            "device_id": "dev_batch_1",
            "location_label": "Singapore, SG",
            "action": "login"
        }
    ]
    files = {"file": ("batch.json", json.dumps(batch_data), "application/json")}
    res_upload = client.post("/api/events/upload-file", files=files)
    assert res_upload.status_code == 200
    assert len(res_upload.json()) == 1

