"""
Golden Test Fixtures and Realistic Persona Scenarios (A-03, Section 18.2).
Provides pre-built, realistic event sequences for personas:
  - Asha: Regular developer with established 9-5 IST baseline; targeted by midnight account takeover.
  - David: Traveling sales director; rapid intercontinental travel and new device provisioning.
  - Elena: High-value treasury manager; sparse baseline, large wire transfers requiring step-up.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from core.contracts import RawEventInput

IST = timezone(timedelta(hours=5, minutes=30))


def generate_asha_baseline(base_date: datetime) -> List[RawEventInput]:
    """
    Generates 6 days of regular office activity (9:00 - 18:00 IST) from laptop and office phone in Pune.
    Total events: 30 events.
    """
    events: List[RawEventInput] = []
    actions_pool = ["login", "view_balance", "view_portfolio", "transfer_own_accounts", "logout"]

    for day in range(6):
        day_date = base_date - timedelta(days=(6 - day))
        for idx, hour in enumerate([9, 11, 14, 16, 17]):
            t = day_date.replace(hour=hour, minute=15 + (idx * 5), second=0, microsecond=0)
            events.append(
                RawEventInput(
                    timestamp=t.isoformat(),
                    user="asha",
                    device_id="dev-asha-macbook" if hour < 16 else "dev-asha-pixel",
                    location_label="Pune",
                    action=actions_pool[idx],
                    session_id=f"sess_asha_base_d{day}"
                )
            )
    return events


def generate_asha_takeover_attack(base_date: datetime) -> List[RawEventInput]:
    """
    Simulates targeted account takeover attack against Asha at 03:15 AM IST from an unfamiliar device.
    Attack steps:
      1. Login at 03:15 IST (unfamiliar device + unusual hour -> triggers R-04 STEP_UP).
      2. Sensitive action: change_email at 03:19 IST (sensitive post unfamiliar login -> triggers R-06 REVOKE).
      3. Attacker tries request_transfer at 03:22 IST (session terminally revoked -> REFUSED 403).
    """
    attack_date = base_date.replace(hour=3, minute=15, second=0, microsecond=0)
    return [
        RawEventInput(
            timestamp=attack_date.isoformat(),
            user="asha",
            device_id="dev-hacker-kali",
            location_label="Pune",
            action="login",
            session_id="sess_asha_takeover_01"
        ),
        RawEventInput(
            timestamp=(attack_date + timedelta(minutes=4)).isoformat(),
            user="asha",
            device_id="dev-hacker-kali",
            location_label="Pune",
            action="change_email",
            session_id="sess_asha_takeover_01"
        ),
        RawEventInput(
            timestamp=(attack_date + timedelta(minutes=7)).isoformat(),
            user="asha",
            device_id="dev-hacker-kali",
            location_label="Pune",
            action="request_transfer",
            session_id="sess_asha_takeover_01"
        )
    ]


def generate_david_impossible_travel(base_date: datetime) -> List[RawEventInput]:
    """
    Simulates impossible travel for David:
      1. Login in Pune at 10:00 UTC
      2. Login in London at 10:15 UTC (distance > 7000 km in 15 mins -> speed ~28,000 km/h -> REVOKE).
    """
    t1 = base_date.replace(hour=10, minute=0, second=0, microsecond=0)
    t2 = t1 + timedelta(minutes=15)
    return [
        RawEventInput(
            timestamp=t1.isoformat(),
            user="david",
            device_id="dev-david-laptop",
            location_label="Pune",
            action="login",
            session_id="sess_david_01"
        ),
        RawEventInput(
            timestamp=t2.isoformat(),
            user="david",
            device_id="dev-david-laptop",
            location_label="London",
            action="login",
            session_id="sess_david_02"
        )
    ]


def generate_elena_sparse_history(base_date: datetime) -> List[RawEventInput]:
    """
    Elena has sparse history (< 15 events).
    Performing a sensitive action on an unfamiliar device triggers R-05 STEP_UP with LIMITED evidence.
    """
    t1 = base_date - timedelta(days=2)
    t2 = base_date.replace(hour=11, minute=0, second=0, microsecond=0)
    return [
        RawEventInput(
            timestamp=t1.isoformat(),
            user="elena",
            device_id="dev-elena-phone",
            location_label="Pune",
            action="login",
            session_id="sess_elena_old"
        ),
        RawEventInput(
            timestamp=t2.isoformat(),
            user="elena",
            device_id="dev-elena-new-tablet",
            location_label="Pune",
            action="login",
            session_id="sess_elena_new"
        ),
        RawEventInput(
            timestamp=(t2 + timedelta(minutes=3)).isoformat(),
            user="elena",
            device_id="dev-elena-new-tablet",
            location_label="Pune",
            action="change_password",
            session_id="sess_elena_new"
        )
    ]
