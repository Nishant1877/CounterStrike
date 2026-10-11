"""
Unit tests for S1-S4 Signals & User Profile Derivation (Stage 1 validation).
"""

import pytest
from datetime import datetime, timezone, timedelta
from core.contracts import RawEventInput, SignalStatus, EvidenceLevel
from core.normalize import LocationDatabase, EventNormalizer
from core.profile import ProfileManager
from core.signals import (
    UnfamiliarDeviceDetector,
    ImplausibleLocationChangeDetector,
    UnusualHourDetector,
    SensitiveAfterUnfamiliarLoginDetector
)


@pytest.fixture
def location_db():
    return LocationDatabase("config/locations.csv")


@pytest.fixture
def normalizer(location_db):
    return EventNormalizer(location_db)


def test_s1_unfamiliar_device(normalizer, location_db):
    detector = UnfamiliarDeviceDetector()
    prof_mgr = ProfileManager()
    profile = prof_mgr.get_or_create("asha")

    # 1. First-ever user event -> baseline device, NOT triggered
    t0 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
    e1 = normalizer.normalize(RawEventInput(timestamp=t0.isoformat(), user="asha", device_id="dev-laptop", location_label="Pune", action="login"))
    res1 = detector.evaluate(e1, profile, location_db)
    assert res1.status == SignalStatus.NOT_TRIGGERED
    assert res1.evidence == EvidenceLevel.NONE

    # Update profile with this baseline event
    prof_mgr.update_from_event(e1, location_timezone="Asia/Kolkata")

    # 2. Subsequent event with SAME device -> NOT triggered
    t1 = datetime(2026, 10, 1, 11, 0, 0, tzinfo=timezone.utc)
    e2 = normalizer.normalize(RawEventInput(timestamp=t1.isoformat(), user="asha", device_id="dev-laptop", location_label="Pune", action="view_balance"))
    res2 = detector.evaluate(e2, profile, location_db)
    assert res2.status == SignalStatus.NOT_TRIGGERED

    # 3. New unfamiliar device -> TRIGGERED
    t2 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
    e3 = normalizer.normalize(RawEventInput(timestamp=t2.isoformat(), user="asha", device_id="dev-hacker-phone", location_label="Pune", action="login"))
    res3 = detector.evaluate(e3, profile, location_db)
    assert res3.status == SignalStatus.TRIGGERED
    assert "has not appeared" in res3.reason


def test_s2_implausible_speed_and_plausible_travel(normalizer, location_db):
    detector = ImplausibleLocationChangeDetector()
    prof_mgr = ProfileManager()
    profile = prof_mgr.get_or_create("asha")

    # Seed initial event in Pune
    t0 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
    e0 = normalizer.normalize(RawEventInput(timestamp=t0.isoformat(), user="asha", device_id="d1", location_label="Pune", action="login"))
    prof_mgr.update_from_event(e0, location_timezone="Asia/Kolkata")

    # Scenario A: Plausible flight (Pune -> London after 10 hours ~ 720 km/h)
    t_flight = t0 + timedelta(hours=10)
    e_flight = normalizer.normalize(RawEventInput(timestamp=t_flight.isoformat(), user="asha", device_id="d1", location_label="London", action="login"))
    res_flight = detector.evaluate(e_flight, profile, location_db)
    assert res_flight.status == SignalStatus.NOT_TRIGGERED
    assert res_flight.value["speed_kmh"] < 900.0

    # Scenario B: Impossible jump (Pune -> London after 30 minutes ~ 14,400 km/h)
    t_attack = t0 + timedelta(minutes=30)
    e_attack = normalizer.normalize(RawEventInput(timestamp=t_attack.isoformat(), user="asha", device_id="d1", location_label="London", action="login"))
    res_attack = detector.evaluate(e_attack, profile, location_db)
    assert res_attack.status == SignalStatus.TRIGGERED
    assert res_attack.value["speed_kmh"] > 900.0
    assert "7,200 km" in res_attack.reason or "7,1" in res_attack.reason or "7,3" in res_attack.reason

    # Scenario C: Unknown location -> not evaluable (honesty about data)
    t_unk = t0 + timedelta(minutes=15)
    e_unk = normalizer.normalize(RawEventInput(timestamp=t_unk.isoformat(), user="asha", device_id="d1", location_label="Xyzville", action="login"))
    res_unk = detector.evaluate(e_unk, profile, location_db)
    assert res_unk.status == SignalStatus.NOT_EVALUABLE


def test_s3_unusual_hour(normalizer, location_db):
    detector = UnusualHourDetector()
    prof_mgr = ProfileManager()
    profile = prof_mgr.get_or_create("asha")

    # Build history: 25 events across 6 distinct days strictly between 09:00 and 12:00 IST (UTC 03:30 - 06:30)
    for day in range(1, 7):
        for h_ist in [9, 10, 11, 12]:
            t = datetime(2026, 9, day, h_ist, 0, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
            e = normalizer.normalize(RawEventInput(timestamp=t.isoformat(), user="asha", device_id="d1", location_label="Pune", action="view_balance"))
            prof_mgr.update_from_event(e, location_timezone="Asia/Kolkata")

    assert profile.get_evidence_level() == EvidenceLevel.SUFFICIENT
    assert len(profile.active_days) == 6

    # Normal hour test (10:00 IST) -> NOT triggered
    t_norm = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    e_norm = normalizer.normalize(RawEventInput(timestamp=t_norm.isoformat(), user="asha", device_id="d1", location_label="Pune", action="view_balance"))
    res_norm = detector.evaluate(e_norm, profile, location_db)
    assert res_norm.status == SignalStatus.NOT_TRIGGERED

    # Rare hour test (03:00 IST - 3 AM) -> TRIGGERED
    t_rare = datetime(2026, 10, 1, 3, 0, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    e_rare = normalizer.normalize(RawEventInput(timestamp=t_rare.isoformat(), user="asha", device_id="d1", location_label="Pune", action="view_balance"))
    res_rare = detector.evaluate(e_rare, profile, location_db)
    assert res_rare.status == SignalStatus.TRIGGERED
    assert "03:00" in res_rare.reason


def test_s4_sensitive_action_post_login(normalizer, location_db):
    detector = SensitiveAfterUnfamiliarLoginDetector()
    prof_mgr = ProfileManager()
    profile = prof_mgr.get_or_create("asha")

    login_ts = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
    session_ctx_unfamiliar = {
        "login_event_id": "evt_login_1",
        "login_event_ts": login_ts,
        "login_device_unfamiliar": True,
        "step_up_passed": False
    }

    # Action within 4 minutes -> TRIGGERED
    t_action = login_ts + timedelta(minutes=4)
    e_action = normalizer.normalize(RawEventInput(
        timestamp=t_action.isoformat(),
        user="asha",
        device_id="dev-unknown",
        location_label="London",
        action="change_email"
    ))
    res = detector.evaluate(e_action, profile, location_db, session_info=session_ctx_unfamiliar)
    assert res.status == SignalStatus.TRIGGERED
    assert "change_email was performed 4 minutes after a login" in res.reason

    # Routine action (view_balance) -> NOT triggered
    e_routine = normalizer.normalize(RawEventInput(
        timestamp=t_action.isoformat(),
        user="asha",
        device_id="dev-unknown",
        location_label="London",
        action="view_balance"
    ))
    res_routine = detector.evaluate(e_routine, profile, location_db, session_info=session_ctx_unfamiliar)
    assert res_routine.status == SignalStatus.NOT_TRIGGERED
