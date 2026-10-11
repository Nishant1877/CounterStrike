"""
Unit tests for Stage 1: Data Contracts, Normalization & Geodesic Foundation.
"""

import pytest
from datetime import datetime, timezone, timedelta
from core.contracts import RawEventInput, IngestStatus
from core.normalize import LocationDatabase, EventNormalizer, haversine_distance_km
from core.ordering import OrderingHandler, OrderingClassification


@pytest.fixture
def location_db():
    return LocationDatabase("config/locations.csv")


@pytest.fixture
def normalizer(location_db):
    return EventNormalizer(location_db)


def test_location_alias_and_resolution(location_db):
    # Direct label
    canon, rec, is_unk = location_db.resolve("Pune")
    assert not is_unk
    assert canon == "Pune"
    assert rec is not None
    assert pytest.approx(rec.latitude, 0.01) == 18.52
    assert rec.timezone_name == "Asia/Kolkata"

    # Alias mapping
    canon_alias, rec_alias, _ = location_db.resolve("bangalore")
    assert canon_alias == "Bengaluru"
    assert rec_alias is not None

    # Empty / unknown
    canon_none, rec_none, is_unk_none = location_db.resolve("")
    assert is_unk_none
    assert canon_none == "UNKNOWN"

    # Unresolvable city not in CSV
    canon_xyz, rec_xyz, is_unk_xyz = location_db.resolve("Xyzville")
    assert not is_unk_xyz
    assert canon_xyz == "Xyzville"
    assert rec_xyz is None


def test_haversine_pune_to_london(location_db):
    _, pune, _ = location_db.resolve("Pune")
    _, london, _ = location_db.resolve("London")
    assert pune is not None and london is not None

    distance = haversine_distance_km(pune.latitude, pune.longitude, london.latitude, london.longitude)
    # Pune to London is approximately 7,200 km (within 5% margin)
    assert 7000.0 < distance < 7400.0

    # 10 hours travel implies ~720 km/h
    speed_10h = distance / 10.0
    assert speed_10h < 900.0  # Commercial flight limit

    # 30 minutes travel implies ~14,400 km/h
    speed_30m = distance / 0.5
    assert speed_30m > 900.0  # Physically implausible


def test_normalize_valid_5field_event(normalizer):
    raw = RawEventInput(
        timestamp="2026-10-11T09:30:00Z",
        user="asha",
        device_id="dev-4471",
        location_label="Pune",
        action="login"
    )
    norm = normalizer.normalize(raw)
    assert norm.user == "asha"
    assert norm.device_id == "dev-4471"
    assert norm.location_label_norm == "Pune"
    assert norm.action == "login"
    assert norm.ingest_status == IngestStatus.ACCEPTED
    assert len(norm.warnings) == 0
    assert norm.event_id.startswith("evt_")


def test_normalize_missing_device_and_unknown_location(normalizer):
    raw = RawEventInput(
        timestamp="2026-10-11T10:00:00+05:30",
        user="bob",
        device_id="",
        location_label=None,
        action="change_email"
    )
    norm = normalizer.normalize(raw)
    assert norm.device_id == "UNKNOWN_DEVICE"
    assert norm.location_label_norm == "UNKNOWN"
    assert norm.ingest_status == IngestStatus.ACCEPTED_WITH_WARNINGS
    assert "missing_device" in norm.warnings
    assert "unknown_location" in norm.warnings


def test_normalize_empty_user_rejected(normalizer):
    with pytest.raises(ValueError):
        raw = RawEventInput(
            timestamp="2026-10-11T10:00:00Z",
            user="",
            device_id="dev-1",
            location_label="Pune",
            action="login"
        )
        normalizer.normalize(raw)


def test_ordering_handler_duplicates_and_late(normalizer):
    handler = OrderingHandler()
    t0 = datetime(2026, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 11, 10, 30, 0, tzinfo=timezone.utc)
    t_late = datetime(2026, 10, 11, 10, 15, 0, tzinfo=timezone.utc)

    raw1 = RawEventInput(timestamp=t0.isoformat(), user="asha", device_id="d1", location_label="Pune", action="login")
    e1 = normalizer.normalize(raw1)
    status1, _ = handler.check_ordering(e1)
    assert status1 == OrderingClassification.ON_TIME

    # Duplicate check
    status_dup, _ = handler.check_ordering(e1)
    assert status_dup == OrderingClassification.DUPLICATE

    # On time next event
    raw2 = RawEventInput(timestamp=t1.isoformat(), user="asha", device_id="d1", location_label="Pune", action="view_balance")
    e2 = normalizer.normalize(raw2)
    status2, _ = handler.check_ordering(e2)
    assert status2 == OrderingClassification.ON_TIME

    # Late arrival event (happened at 10:15, after 10:30 already processed)
    raw_late = RawEventInput(timestamp=t_late.isoformat(), user="asha", device_id="d1", location_label="Pune", action="search")
    e_late = normalizer.normalize(raw_late)
    status_late, lateness = handler.check_ordering(e_late)
    assert status_late == OrderingClassification.LATE
    assert lateness == 900.0  # 15 minutes = 900s
