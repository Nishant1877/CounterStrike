import time
from typing import List, Dict, Any
from external_compat.models import SecurityEvent

NOW = time.time()

# Baseline events to preload realistic history for demo users
BASELINE_EVENTS_ALICE: List[SecurityEvent] = [
    SecurityEvent(
        timestamp=NOW - 86400 * 3,  # 3 days ago, 10:00 AM UTC
        user="alice_corporate",
        session_id="sess_baseline_1",
        device_id="macbook_pro_m2_corp",
        location_label="Pune, IN",
        action="login",
        details={"ip": "103.21.144.12", "browser": "Chrome 122"}
    ),
    SecurityEvent(
        timestamp=NOW - 86400 * 3 + 120,
        user="alice_corporate",
        session_id="sess_baseline_1",
        device_id="macbook_pro_m2_corp",
        location_label="Pune, IN",
        action="view_dashboard",
        details={"path": "/reports/monthly"}
    ),
    SecurityEvent(
        timestamp=NOW - 86400 * 2,  # 2 days ago, 11:30 AM UTC
        user="alice_corporate",
        session_id="sess_baseline_2",
        device_id="macbook_pro_m2_corp",
        location_label="Pune, IN",
        action="login",
        details={"ip": "103.21.144.12"}
    ),
    SecurityEvent(
        timestamp=NOW - 86400 * 1,  # 1 day ago, 10:15 AM UTC
        user="alice_corporate",
        session_id="sess_baseline_3",
        device_id="iphone_15_alice",
        location_label="Pune, IN",
        action="login",
        details={"ip": "103.21.144.15"}
    ),
    SecurityEvent(
        timestamp=NOW - 86400 * 1 + 300,
        user="alice_corporate",
        session_id="sess_baseline_3",
        device_id="iphone_15_alice",
        location_label="Pune, IN",
        action="approve_timesheet",
        details={"target": "team"}
    )
]

# Attack Scenario 1: Account Takeover (ATO) Chain -> Ends with Session Revocation & Action Block
SCENARIO_ATO_CHAIN: Dict[str, Any] = {
    "id": "scenario_ato_chain",
    "name": "Scenario 1: Full Account Takeover (ATO) Chain Attack",
    "description": (
        "Attacker accesses account from a brand new device in a different continent, "
        "immediately requests an email change and tries to transfer funds. "
        "Shows automatic session revocation and blocking subsequent actions."
    ),
    "user": "alice_corporate",
    "events": [
        SecurityEvent(
            timestamp=NOW - 300,
            user="alice_corporate",
            session_id="sess_hacker_99",
            device_id="unknown_linux_kali_device",
            location_label="Lagos, NG",
            action="login",
            details={"ip": "197.210.44.89", "browser": "Headless Chrome / Tor"}
        ),
        SecurityEvent(
            timestamp=NOW - 240,
            user="alice_corporate",
            session_id="sess_hacker_99",
            device_id="unknown_linux_kali_device",
            location_label="Lagos, NG",
            action="view_account_settings",
            details={"tab": "security"}
        ),
        SecurityEvent(
            timestamp=NOW - 120,
            user="alice_corporate",
            session_id="sess_hacker_99",
            device_id="unknown_linux_kali_device",
            location_label="Lagos, NG",
            action="change_email",
            details={"new_email": "attacker_shadow@darkmail.xyz"}
        ),
        SecurityEvent(
            timestamp=NOW,
            user="alice_corporate",
            session_id="sess_hacker_99",
            device_id="unknown_linux_kali_device",
            location_label="Lagos, NG",
            action="transfer_funds",
            details={"amount": 450000, "beneficiary": "shadow_vault_0x99"}
        )
    ]
}

# Attack Scenario 2: Impossible Travel Velocity (Pune -> London in 15 mins)
SCENARIO_IMPOSSIBLE_TRAVEL: Dict[str, Any] = {
    "id": "scenario_impossible_travel",
    "name": "Scenario 2: Implausible Travel Velocity (7,200 km in 15 mins)",
    "description": (
        "Alice is actively logged in from Pune, IN. Only 15 minutes later, an event is logged from London, UK. "
        "Detects extreme impossible travel (>25,000 km/h) and triggers step-up verification / revocation."
    ),
    "user": "alice_corporate",
    "events": [
        SecurityEvent(
            timestamp=NOW - 900,
            user="alice_corporate",
            session_id="sess_pune_legit",
            device_id="macbook_pro_m2_corp",
            location_label="Pune, IN",
            action="view_dashboard",
            details={"path": "/workspace"}
        ),
        SecurityEvent(
            timestamp=NOW,
            user="alice_corporate",
            session_id="sess_london_spoof",
            device_id="windows_pc_unknown",
            location_label="London, UK",
            action="login",
            details={"ip": "82.165.197.1", "browser": "Firefox"}
        )
    ]
}

# Scenario 3: Cold Start / Sparse History
SCENARIO_COLD_START: Dict[str, Any] = {
    "id": "scenario_cold_start",
    "name": "Scenario 3: New User Cold Start & Sparse History Handling",
    "description": (
        "Brand new employee 'bob_intern' has only 1 recorded event. Demonstrates how IdentityGuard handles "
        "sparse history gracefully, flagging 'Limited Information' rather than spamming false-positive critical alarms."
    ),
    "user": "bob_intern",
    "events": [
        SecurityEvent(
            timestamp=NOW,
            user="bob_intern",
            session_id="sess_bob_01",
            device_id="dell_latitude_laptop",
            location_label="Mumbai, IN",
            action="login",
            details={"role": "intern", "onboarding": True}
        )
    ]
}

# Scenario 4: Out of Order & Unmapped Location Label
SCENARIO_EDGE_CASES: Dict[str, Any] = {
    "id": "scenario_edge_cases",
    "name": "Scenario 4: Out-of-Order Events & Unmapped Location Label",
    "description": (
        "Simulates network telemetry buffer lag where an event arrives out of order, and reports an unmapped "
        "location tag 'Satellite_Relay_Antarctica'. Demonstrates robust error and edge-case handling."
    ),
    "user": "alice_corporate",
    "events": [
        SecurityEvent(
            timestamp=NOW - 3600,  # 1 hour ago (Arrives late)
            user="alice_corporate",
            session_id="sess_lagged_call",
            device_id="macbook_pro_m2_corp",
            location_label="Satellite_Relay_Antarctica",
            action="sync_telemetry",
            details={"retry_count": 3}
        )
    ]
}

ALL_SCENARIOS = [
    SCENARIO_ATO_CHAIN,
    SCENARIO_IMPOSSIBLE_TRAVEL,
    SCENARIO_COLD_START,
    SCENARIO_EDGE_CASES
]
