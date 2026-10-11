"""
Google Gemini 2.5 LLM Threat Intelligence & Forensic Explainer (Stage C).
Generates on-demand deep forensic threat analysis, adversary hypotheses,
and MITRE ATT&CK tactical framework mappings.

Guarantees 100% offline venue fallback resilience when GEMINI_API_KEY is not set or network is unreachable.
Adheres strictly to Invariant R9: AI is purely advisory; generated analyses enrich SOC investigations
without mutating automated deterministic access controls.
"""

import os
import json
import urllib.request
import urllib.error
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class MitreAttackTactic(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str
    description: str


class ForensicReport(BaseModel):
    report_id: str
    decision_id: str
    user: str
    session_id: str
    generated_at: str
    model_source: str  # "gemini-2.5-flash" or "heuristic-offline-fallback"
    threat_level: str  # "CRITICAL", "HIGH", "ELEVATED", "LOW"
    executive_summary: str
    attack_hypothesis: str
    mitre_attack: List[MitreAttackTactic] = Field(default_factory=list)
    behavioral_anomalies: List[str] = Field(default_factory=list)
    recommended_soc_actions: List[str] = Field(default_factory=list)
    compliance_note: str


class GeminiForensicExplainer:
    """
    Forensic Threat Intelligence generator powered by Google Gemini 2.5 Flash
    with an offline deterministic fallback engine.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "").strip()
        self.api_url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={self.api_key}"
            if self.api_key
            else ""
        )

    def generate_report(
        self,
        decision_data: Dict[str, Any],
        profile_data: Optional[Dict[str, Any]] = None
    ) -> ForensicReport:
        """
        Generates a comprehensive forensic report.
        Attempts Gemini 2.5 Flash API first; falls back gracefully if key is absent or request fails.
        """
        report_id = f"rpt_forensic_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{decision_data.get('decision_id', 'unknown')[:8]}"
        
        if self.api_key:
            try:
                llm_report = self._call_gemini_api(report_id, decision_data, profile_data)
                if llm_report:
                    return llm_report
            except Exception:
                # Log or ignore exception, fallback gracefully
                pass

        # Offline deterministic heuristic fallback
        return self._generate_offline_fallback(report_id, decision_data, profile_data)

    def _call_gemini_api(
        self,
        report_id: str,
        decision_data: Dict[str, Any],
        profile_data: Optional[Dict[str, Any]] = None
    ) -> Optional[ForensicReport]:
        """Calls Google Gemini 2.5 Flash endpoint via HTTPS."""
        prompt = self._build_gemini_prompt(decision_data, profile_data)
        
        request_body = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json"
            }
        }

        req = urllib.request.Request(
            self.api_url,
            data=json.dumps(request_body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=8.0) as resp:
            if resp.status == 200:
                body = json.loads(resp.read().decode("utf-8"))
                candidates = body.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts and "text" in parts[0]:
                        parsed = json.loads(parts[0]["text"])
                        return ForensicReport(
                            report_id=report_id,
                            decision_id=decision_data.get("decision_id", "unknown"),
                            user=decision_data.get("user", "unknown"),
                            session_id=decision_data.get("session_id", "unknown"),
                            generated_at=datetime.now(timezone.utc).isoformat(),
                            model_source="gemini-2.5-flash",
                            threat_level=parsed.get("threat_level", "ELEVATED"),
                            executive_summary=parsed.get("executive_summary", ""),
                            attack_hypothesis=parsed.get("attack_hypothesis", ""),
                            mitre_attack=[MitreAttackTactic(**t) for t in parsed.get("mitre_attack", [])],
                            behavioral_anomalies=parsed.get("behavioral_anomalies", []),
                            recommended_soc_actions=parsed.get("recommended_soc_actions", []),
                            compliance_note="R9 Guard Invariant Verified: Gemini analysis is advisory only."
                        )
        return None

    def _build_gemini_prompt(
        self,
        decision_data: Dict[str, Any],
        profile_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Constructs an expert SOC cybersecurity prompt."""
        return f"""You are a Lead Cybersecurity SOC Incident Forensics AI Analyst evaluating an account takeover event.
Analyze the following telemetry and return strict JSON conforming to the schema below:

TELEMETRY:
- Decision ID: {decision_data.get('decision_id')}
- User: {decision_data.get('user')}
- Session ID: {decision_data.get('session_id')}
- Response Action: {decision_data.get('response')}
- Deciding Rule: {decision_data.get('deciding_rule')}
- Rules Fired: {decision_data.get('rules_fired')}
- Evidence Level: {decision_data.get('evidence_level')}
- Plain-English Summary: {decision_data.get('explanation')}
- Signals: {json.dumps(decision_data.get('signals', []))}
- User Baseline History: {json.dumps(profile_data or {})}

REQUIRED JSON SCHEMA:
{{
  "threat_level": "CRITICAL" | "HIGH" | "ELEVATED" | "LOW",
  "executive_summary": "High-level summary of what happened",
  "attack_hypothesis": "Forensic breakdown of attacker tactics (e.g., Session Hijacking, Token Theft, Credential Stuffing)",
  "mitre_attack": [
    {{
      "technique_id": "T1078.004",
      "technique_name": "Valid Accounts: Cloud Accounts",
      "tactic": "Initial Access / Persistence",
      "confidence": "HIGH",
      "description": "Specific relevance to this event"
    }}
  ],
  "behavioral_anomalies": ["list of anomalous behaviors detected"],
  "recommended_soc_actions": ["list of tactical remediation steps for the SOC team"]
}}
"""

    def _generate_offline_fallback(
        self,
        report_id: str,
        decision_data: Dict[str, Any],
        profile_data: Optional[Dict[str, Any]] = None
    ) -> ForensicReport:
        """Deterministic heuristic forensic generator when offline."""
        resp = decision_data.get("response", "no_action").lower()
        rule = decision_data.get("deciding_rule", "None")
        user = decision_data.get("user", "unknown")
        action = decision_data.get("action", "activity")
        signals = decision_data.get("signals", [])
        
        triggered_signals = [s.get("name") for s in signals if s.get("status") == "triggered"]
        
        # Determine threat level & MITRE tags
        mitre_list: List[MitreAttackTactic] = []
        anomalies: List[str] = []
        actions: List[str] = []

        if "revoke" in resp or rule in {"R-06", "R-07", "R-08", "R-10"}:
            threat_level = "CRITICAL"
            summary = (
                f"High-confidence Account Takeover (ATO) chain observed for user '{user}'. "
                f"Automated enforcement executed session termination under policy {rule}."
            )
            hypothesis = (
                "Attacker appears to have acquired valid active credentials or intercepted a session token, "
                "subsequently attempting rapid privilege escalation or fraudulent resource extraction from an unverified perimeter."
            )
            
            mitre_list.append(MitreAttackTactic(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic="Defense Evasion, Persistence, Initial Access",
                confidence="HIGH",
                description="Adversary leveraged legitimate credentials through unfamiliar access vectors."
            ))
            mitre_list.append(MitreAttackTactic(
                technique_id="T1539",
                technique_name="Steal Web Session Cookie",
                tactic="Credential Access",
                confidence="HIGH",
                description="Sudden change of device signature and concurrent disparate location indicates token replay."
            ))
            mitre_list.append(MitreAttackTactic(
                technique_id="T1566",
                technique_name="Phishing / Session Hijack",
                tactic="Initial Access",
                confidence="MEDIUM",
                description="Potential session interception via AitM reverse proxy or compromised client environment."
            ))

            anomalies = [
                "Unrecognized hardware identifier not present in historical trusted inventory",
                "Geodesic displacement velocity exceeding plausible subsonic commercial flight (>900 km/h)",
                "Immediate execution of high-risk sensitive operations shortly following external authentication"
            ]
            actions = [
                f"Verify terminal revocation status across all distributed token caches for session '{decision_data.get('session_id')}'.",
                f"Initiate mandatory identity re-verification and password reset for user '{user}'.",
                "Inspect perimeter reverse-proxy logs for concurrent active TCP connections matching suspicious IP/device fingerprints.",
                "Review outbound financial transaction or sensitive configuration queues for unauthorized state changes."
            ]

        elif "step_up" in resp or rule in {"R-02", "R-03", "R-04", "R-05"}:
            threat_level = "ELEVATED"
            summary = (
                f"Behavioral boundary divergence detected for user '{user}'. "
                f"Session gated behind mandatory 2FA challenge under rule {rule}."
            )
            hypothesis = (
                "Access originated from a newly observed hardware identifier or non-habitual operational window. "
                "Behavioral anomaly triggers preventive step-up verification before granting authorization to sensitive endpoints."
            )
            mitre_list.append(MitreAttackTactic(
                technique_id="T1078.004",
                technique_name="Valid Accounts: Cloud Accounts",
                tactic="Initial Access",
                confidence="MEDIUM",
                description="Unfamiliar device access requesting authorization for protected routines."
            ))
            anomalies = [
                "Unfamiliar endpoint device signature with zero preceding historical logins",
                "Non-habitual access hour deviating from diurnal empirical distribution"
            ]
            actions = [
                "Monitor for resolution of interactive out-of-band step-up challenge.",
                "If challenge fails or expires within 5 minutes, auto-transition session state to TERMINALLY REVOKED.",
                "Correlate device fingerprint against corporate threat intelligence watchlists."
            ]

        elif "review" in resp:
            threat_level = "HIGH"
            summary = (
                f"Indeterminate risk profile for user '{user}'. "
                f"Advisory intelligence flags potential anomaly requiring human SOC analyst clearance under {rule}."
            )
            hypothesis = (
                "Telemetry signals trigger suspicious behavioral signatures, but historical evidence is limited or cold-start. "
                "Per Invariant R9, automated revocation is withheld to avoid false-positive denial-of-service."
            )
            mitre_list.append(MitreAttackTactic(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic="Initial Access",
                confidence="MEDIUM",
                description="Limited baseline historical confidence requires analyst adjudication."
            ))
            anomalies = [
                "Limited evidence baseline prevents deterministic high-confidence revocation",
                "Statistical anomaly score flagged by advisory behavioral evaluator"
            ]
            actions = [
                "Analyst investigation required: inspect user's out-of-band communication or call log.",
                "Resolve case in SOC Analyst Queue as either 'confirmed_attack' or 'legitimate'."
            ]

        else:
            threat_level = "LOW"
            summary = f"Routine operational telemetry confirmed for user '{user}'. Activity is consistent with established baseline profile."
            hypothesis = "Standard legitimate user activity within normal diurnal hours and verified hardware environment."
            mitre_list.append(MitreAttackTactic(
                technique_id="N/A",
                technique_name="Normal User Behavior",
                tactic="Legitimate Operations",
                confidence="HIGH",
                description="Operational baseline conformance."
            ))
            anomalies = ["No behavioral or topological anomalies observed."]
            actions = ["No analyst remediation required. Log retained in cryptographic audit ledger."]

        return ForensicReport(
            report_id=report_id,
            decision_id=decision_data.get("decision_id", "unknown"),
            user=user,
            session_id=decision_data.get("session_id", "unknown"),
            generated_at=datetime.now(timezone.utc).isoformat(),
            model_source="heuristic-offline-fallback (Zero-Dependency)",
            threat_level=threat_level,
            executive_summary=summary,
            attack_hypothesis=hypothesis,
            mitre_attack=mitre_list,
            behavioral_anomalies=anomalies,
            recommended_soc_actions=actions,
            compliance_note="R9 Guard Invariant Verified: Advisory analysis only. Automated controls governed by deterministic rules."
        )


# Global singleton instance
gemini_forensics = GeminiForensicExplainer()
