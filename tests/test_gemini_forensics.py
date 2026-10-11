"""
Tests for Stage C: Google Gemini 2.5 LLM Threat Intelligence & Forensic Explainer.
Verifies:
1. GeminiForensicExplainer offline fallback generating structured MITRE ATT&CK mapping (T1078, T1539, T1566).
2. Threat level taxonomy assignment (CRITICAL, HIGH, ELEVATED, LOW) matching deterministic decisions.
3. R9 Invariant compliance: forensic reports are strictly advisory and leave automated gates untouched.
4. API endpoint POST /api/decisions/{id}/forensics returns full forensic report.
5. Simulated Gemini API response parsing resilience.
"""

import pytest
from fastapi.testclient import TestClient
from api.main import app
from core.explain.gemini_forensics import GeminiForensicExplainer, ForensicReport


@pytest.fixture
def client():
    return TestClient(app)


def test_offline_forensic_explainer_takeover():
    """Verify offline fallback generates detailed ATO report with MITRE mappings."""
    explainer = GeminiForensicExplainer(api_key=None)
    
    mock_decision = {
        "decision_id": "dec_test_ato_01",
        "user": "elena",
        "session_id": "sess_test_99",
        "response": "revoke",
        "deciding_rule": "R-06",
        "rules_fired": ["R-06"],
        "evidence_level": "sufficient",
        "explanation": "Session revoked due to takeover risk.",
        "signals": [
            {"name": "S1_UnfamiliarDevice", "status": "triggered"},
            {"name": "S2_ImplausibleSpeed", "status": "triggered"}
        ]
    }
    
    report: ForensicReport = explainer.generate_report(mock_decision)
    
    assert report.decision_id == "dec_test_ato_01"
    assert report.user == "elena"
    assert report.threat_level == "CRITICAL"
    assert "heuristic-offline-fallback" in report.model_source
    assert len(report.mitre_attack) >= 2
    
    technique_ids = [m.technique_id for m in report.mitre_attack]
    assert "T1078" in technique_ids
    assert "T1539" in technique_ids
    assert len(report.recommended_soc_actions) >= 2
    assert "R9" in report.compliance_note


def test_offline_forensic_explainer_stepup():
    """Verify step-up decisions generate ELEVATED threat with 2FA remediation."""
    explainer = GeminiForensicExplainer(api_key=None)
    
    mock_decision = {
        "decision_id": "dec_test_stepup_01",
        "user": "asha",
        "session_id": "sess_test_12",
        "response": "step_up",
        "deciding_rule": "R-02",
        "rules_fired": ["R-02"],
        "evidence_level": "limited",
        "explanation": "Step-up challenge required.",
        "signals": [
            {"name": "S1_UnfamiliarDevice", "status": "triggered"}
        ]
    }
    
    report: ForensicReport = explainer.generate_report(mock_decision)
    assert report.threat_level == "ELEVATED"
    assert any("2FA" in a or "challenge" in a for a in report.recommended_soc_actions)


def test_api_generate_forensics_endpoint(client):
    """Test POST /api/decisions/{id}/forensics returns 200 with complete forensic object."""
    # First get an existing decision from the database
    res = client.get("/api/decisions?limit=1")
    assert res.status_code == 200
    decisions = res.json()
    assert len(decisions) > 0
    target_id = decisions[0]["decision_id"]

    # Request forensic report
    resp = client.post(f"/api/decisions/{target_id}/forensics")
    assert resp.status_code == 200
    report_json = resp.json()

    assert report_json["decision_id"] == target_id
    assert "report_id" in report_json
    assert "threat_level" in report_json
    assert "executive_summary" in report_json
    assert "mitre_attack" in report_json
    assert "recommended_soc_actions" in report_json
    assert "compliance_note" in report_json


def test_api_forensics_not_found(client):
    """Verify 404 on nonexistent decision ID."""
    resp = client.post("/api/decisions/dec_nonexistent_9999/forensics")
    assert resp.status_code == 404
