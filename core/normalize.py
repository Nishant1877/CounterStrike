"""
Normalization and Geodesic Engine for IdentityGuard (A-03).
Handles timestamp UTC conversion, alias mapping, distance calculations, and deterministic hashing.
"""

from __future__ import annotations
import csv
import hashlib
import math
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dateutil import parser as date_parser

from core.contracts import RawEventInput, NormalizedEvent, IngestStatus


class LocationRecord:
    def __init__(self, label: str, latitude: float, longitude: float, granularity: str, timezone_name: str):
        self.label = label
        self.latitude = latitude
        self.longitude = longitude
        self.granularity = granularity
        self.timezone_name = timezone_name


class LocationDatabase:
    """In-memory fast lookup for normalized location coordinates and timezones."""

    def __init__(self, csv_path: Optional[str] = None):
        self.locations: Dict[str, LocationRecord] = {}
        self.alias_map: Dict[str, str] = {}
        if csv_path and os.path.exists(csv_path):
            self.load_csv(csv_path)

    def load_csv(self, csv_path: str) -> None:
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                label = row["label"].strip()
                lat = float(row["latitude"])
                lon = float(row["longitude"])
                granularity = row.get("granularity", "city").strip()
                tz = row.get("timezone", "UTC").strip()

                rec = LocationRecord(label, lat, lon, granularity, tz)
                self.locations[label.lower()] = rec

                # Register primary label in alias map
                self.alias_map[label.lower()] = label

                # Register aliases
                aliases = row.get("aliases", "")
                if aliases:
                    for alias in aliases.split("|"):
                        cleaned = alias.strip().lower()
                        if cleaned:
                            self.alias_map[cleaned] = label

    def resolve(self, raw_label: Optional[str]) -> Tuple[str, Optional[LocationRecord], bool]:
        """
        Resolves raw location string.
        Returns: (canonical_label, LocationRecord or None, is_unknown)
        """
        if not raw_label:
            return "UNKNOWN", None, True

        cleaned = raw_label.strip()
        lower_cleaned = cleaned.lower()

        if lower_cleaned in {"", "unknown", "n/a", "null", "none"}:
            return "UNKNOWN", None, True

        # Check alias map
        if lower_cleaned in self.alias_map:
            canonical_name = self.alias_map[lower_cleaned]
            record = self.locations.get(canonical_name.lower())
            return canonical_name, record, False

        # Not found in table: preserve cleaned string, coordinates unresolvable
        return cleaned, None, False


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Great-Circle distance between two points on the Earth's surface in kilometers.
    Radius = 6371.0 km
    """
    radius = 6371.0  # Earth's mean radius in km

    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (math.sin(delta_phi / 2.0) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2)
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

    return radius * c


class EventNormalizer:
    """Validates raw 5-field events and converts them into normalized internal representations."""

    def __init__(self, location_db: LocationDatabase, clock_skew_minutes: float = 5.0):
        self.location_db = location_db
        self.clock_skew_minutes = clock_skew_minutes
        self._seq_counter = 0

    def parse_timestamp_to_utc(
        self, ts_input: Any, reference_time: Optional[datetime] = None
    ) -> Tuple[datetime, List[str]]:
        warnings = []
        if isinstance(ts_input, datetime):
            dt = ts_input
        else:
            ts_str = str(ts_input).strip()
            try:
                dt = date_parser.parse(ts_str)
            except Exception as e:
                raise ValueError(f"Unparseable timestamp: {ts_input}") from e

        if dt.tzinfo is None:
            # Missing offset accepted, assumed UTC with warning (Section 5.1)
            warnings.append("missing_offset")
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        # Check clock skew if reference time is given
        if reference_time is not None:
            ref_utc = reference_time.astimezone(timezone.utc) if reference_time.tzinfo else reference_time.replace(tzinfo=timezone.utc)
            if dt > ref_utc + timedelta(minutes=self.clock_skew_minutes):
                warnings.append("clock_skew")

        return dt, warnings

    def normalize(
        self, raw: RawEventInput, session_id: Optional[str] = None, reference_time: Optional[datetime] = None
    ) -> NormalizedEvent:
        warnings: List[str] = []

        # 1. User validation (Empty rejects event)
        if not raw.user or not raw.user.strip():
            raise ValueError("Empty or missing user identifier")
        user = raw.user.strip()

        # 2. Timestamp validation and UTC conversion
        event_ts, ts_warnings = self.parse_timestamp_to_utc(raw.timestamp, reference_time=reference_time)
        warnings.extend(ts_warnings)

        # 3. Device validation
        if not raw.device_id or not raw.device_id.strip():
            device_id = "UNKNOWN_DEVICE"
            warnings.append("missing_device")
        else:
            device_id = raw.device_id.strip()

        # 4. Location normalization
        raw_loc = raw.location_label or ""
        norm_loc, loc_record, is_unknown = self.location_db.resolve(raw_loc)
        if is_unknown:
            warnings.append("unknown_location")
        elif loc_record is None:
            warnings.append("unresolvable_location")

        # 5. Action normalization
        if not raw.action or not raw.action.strip():
            raise ValueError("Empty or missing action")
        action = raw.action.strip().lower()

        # 6. Deterministic Event ID generation (SHA-256 hash of 5 raw fields)
        hasher = hashlib.sha256()
        hasher.update(f"{event_ts.isoformat()}|{user}|{device_id}|{norm_loc}|{action}".encode("utf-8"))
        event_id = f"evt_{hasher.hexdigest()[:16]}"

        # 7. Incremental Sequence and Arrival Stamp
        self._seq_counter += 1
        received_at = datetime.now(timezone.utc)

        # 8. Status calculation
        ingest_status = (
            IngestStatus.ACCEPTED_WITH_WARNINGS if warnings else IngestStatus.ACCEPTED
        )

        # Inferred session_id fallback if not provided
        assigned_session = session_id or f"sess_{user}_{device_id}"

        return NormalizedEvent(
            event_id=event_id,
            received_at=received_at,
            ingest_seq=self._seq_counter,
            event_ts=event_ts,
            user=user,
            device_id=device_id,
            location_label_raw=raw_loc,
            location_label_norm=norm_loc,
            action=action,
            session_id=assigned_session,
            warnings=warnings,
            ingest_status=ingest_status,
            raw_payload=raw.model_dump()
        )
