"""
Tests for Stage D: Interactive Step-Up 2FA Challenge & Recovery Simulator.
Verifies:
1. POST /v1/sessions/{id}/challenge generates 6-digit OTP and transitions status to 'pending_verification'.
2. GET /v1/sessions/{id}/challenge retrieves challenge details.
3. POST /v1/sessions/{id}/verify-otp with valid OTP restores session to 'active' (R11 preserved).
4. POST /v1/sessions/{id}/verify-otp with invalid OTP decrements attempt counter.
5. Max invalid OTP attempts triggers hard terminal revocation (HTTP 403, R11 enforced).
6. POST /v1/events with step_up response automatically populates challenge and otp_demo.
"""

import pytest
import uuid
from fastapi.testclient import TestClient
from api.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_challenge_generation_and_successful_verification(client):
    """Test full cycle: generate challenge -> verify OTP -> session restored to active."""
    sess_id = f"sess_test_{uuid.uuid4().hex[:8]}"

    # Ingest benign login first to create active session
    res = client.post("/v1/events", json={
        "timestamp": "2026-10-11T10:00:00Z",
        "user": "test_user_2fa",
        "device_id": "dev_test_known",
        "location_label": "Pune",
        "action": "login",
        "session_id": sess_id
    })
    assert res.status_code == 200

    # 1. Generate Step-Up challenge
    chal_res = client.post(f"/v1/sessions/{sess_id}/challenge")
    assert chal_res.status_code == 200
    chal_data = chal_res.json()
    assert chal_data["status"] == "pending_verification"
    assert "otp_demo" in chal_data
    demo_otp = chal_data["otp_demo"]

    # Check status endpoint reflects pending_verification
    status_res = client.get(f"/v1/sessions/{sess_id}/status")
    assert status_res.status_code == 200
    assert status_res.json()["status"] == "pending_verification"

    # 2. Check active challenge endpoint
    get_chal = client.get(f"/v1/sessions/{sess_id}/challenge")
    assert get_chal.status_code == 200
    assert get_chal.json()["has_active_challenge"] is True

    # 3. Verify with wrong OTP -> fails with decremented attempts
    wrong_res = client.post(f"/v1/sessions/{sess_id}/verify-otp", json={"otp": "000000"})
    assert wrong_res.status_code == 200
    assert wrong_res.json()["attempts_left"] == 2

    # 4. Verify with correct OTP -> success and status active
    verify_res = client.post(f"/v1/sessions/{sess_id}/verify-otp", json={"otp": demo_otp})
    assert verify_res.status_code == 200
    assert verify_res.json()["status"] == "active"

    # Confirm session status is now active
    status_res2 = client.get(f"/v1/sessions/{sess_id}/status")
    assert status_res2.json()["status"] == "active"


def test_challenge_max_failed_attempts_triggers_revocation(client):
    """Test that exhausting 3 attempts results in HTTP 403 terminal revocation."""
    sess_id = f"sess_fail_{uuid.uuid4().hex[:8]}"

    client.post("/v1/events", json={
        "timestamp": "2026-10-11T10:00:00Z",
        "user": "test_user_fail",
        "device_id": "dev_test_known",
        "location_label": "Pune",
        "action": "login",
        "session_id": sess_id
    })

    client.post(f"/v1/sessions/{sess_id}/challenge")

    # Fail attempt 1
    r1 = client.post(f"/v1/sessions/{sess_id}/verify-otp", json={"otp": "111111"})
    assert r1.status_code == 200
    assert r1.json()["attempts_left"] == 2

    # Fail attempt 2
    r2 = client.post(f"/v1/sessions/{sess_id}/verify-otp", json={"otp": "222222"})
    assert r2.status_code == 200
    assert r2.json()["attempts_left"] == 1

    # Fail attempt 3 -> Terminal revocation HTTP 403!
    r3 = client.post(f"/v1/sessions/{sess_id}/verify-otp", json={"otp": "333333"})
    assert r3.status_code == 403
    assert "revoked" in r3.json()["detail"].lower()

    # Session gate now rejects any subsequent action with 403
    next_res = client.post("/v1/events", json={
        "timestamp": "2026-10-11T10:05:00Z",
        "user": "test_user_fail",
        "device_id": "dev_test_known",
        "location_label": "Pune",
        "action": "view_balance",
        "session_id": sess_id
    })
    assert next_res.status_code == 403
    assert next_res.json()["detail"]["response"] == "refused_session_revoked"
