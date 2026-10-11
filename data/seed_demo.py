"""
Demo Seed Script for IdentityGuard (A-03, Section 18.2).
Seeds realistic profiles and initial scenario state into the primary database
so the analyst UI and API have rich, demonstrative data out-of-the-box.
"""

from datetime import datetime, timezone, timedelta
from store.db import default_db
from store.models import EventModel, DecisionModel, SessionModel, ReviewCaseModel
from core.pipeline import SecurityPipeline
from core.normalize import LocationDatabase
from core.rules.engine import RuleEngine
from data.fixtures import (
    generate_asha_baseline,
    generate_asha_takeover_attack,
    generate_david_impossible_travel,
    generate_elena_sparse_history
)


def seed_demo_database():
    """Seeds baseline profiles, attack scenarios, and initial cases."""
    print("[IdentityGuard] Seeding demo database...")
    default_db.init_db()

    loc_db = LocationDatabase("config/locations.csv")
    rule_engine = RuleEngine("config/rules.yaml")
    pipeline = SecurityPipeline(location_db=loc_db, rule_engine=rule_engine)

    now = datetime.now(timezone.utc)

    # 1. Clear existing records for clean demo
    with default_db.session_scope() as session:
        session.query(DecisionModel).delete()
        session.query(EventModel).delete()
        session.query(SessionModel).delete()
        session.query(ReviewCaseModel).delete()

    # 2. Feed Asha baseline
    print(" -> Seeding Asha baseline (30 events across 6 days)...")
    asha_base = generate_asha_baseline(now)
    with default_db.session_scope() as session:
        for evt in asha_base:
            pipeline.process_event(raw_event=evt, db=session, mode="live")

    # 3. Feed Asha takeover attack
    print(" -> Seeding Asha takeover attack scenario (R-04 step_up, R-06 revoke, R-11 refused)...")
    asha_attack = generate_asha_takeover_attack(now)
    with default_db.session_scope() as session:
        for evt in asha_attack:
            pipeline.process_event(raw_event=evt, db=session, mode="live")

    # 4. Feed David impossible travel
    print(" -> Seeding David impossible travel scenario (S2 speed > 900 km/h -> REVOKE)...")
    david_events = generate_david_impossible_travel(now)
    with default_db.session_scope() as session:
        for evt in david_events:
            pipeline.process_event(raw_event=evt, db=session, mode="live")

    # 5. Feed Elena sparse history
    print(" -> Seeding Elena sparse history scenario (sparse history -> STEP_UP with limited evidence)...")
    elena_events = generate_elena_sparse_history(now)
    with default_db.session_scope() as session:
        for evt in elena_events:
            pipeline.process_event(raw_event=evt, db=session, mode="live")

    print("[IdentityGuard] Database successfully seeded with 3 realistic personas!")


if __name__ == "__main__":
    seed_demo_database()
