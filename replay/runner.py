"""
Sandboxed Replay Execution Engine for IdentityGuard (A-03, Section 14.1 & R10).
Replays historical event slices in complete isolation using the identical
pipeline (SecurityPipeline) without mutating live state, production databases, or active profiles.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from store.db import DatabaseManager
from store.models import EventModel, DecisionModel
from core.contracts import RawEventInput, Decision, ResponseAction
from core.pipeline import SecurityPipeline
from core.normalize import LocationDatabase
from core.rules.engine import RuleEngine
from replay.hasher import compute_decision_stream_hash
from replay.diff import ReplayDiffCalculator


class ReplayRunner:
    """
    Executes historical event slices in an isolated in-memory sandbox.
    Uses the exact same SecurityPipeline and normalization logic.
    """

    def __init__(
        self,
        location_db: Optional[LocationDatabase] = None,
        rule_yaml_path: Optional[str] = "config/rules.yaml"
    ):
        self.location_db = location_db or LocationDatabase("config/locations.csv")
        self.default_rule_yaml_path = rule_yaml_path

    def run_replay(
        self,
        events: List[RawEventInput],
        candidate_rule_yaml_path: Optional[str] = None,
        candidate_rules_dict: Optional[Dict[str, Any]] = None,
        replay_run_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes a sandboxed replay run.
        Parameters:
          - events: Ordered slice of RawEventInput instances
          - candidate_rule_yaml_path: Optional path to candidate rule file
          - candidate_rules_dict: Optional direct rule dict for candidate policy
          - replay_run_id: Optional identifier for the replay batch
        Returns:
          Dictionary with replay_run_id, decision_hash, total_events, decisions, and duration_ms.
        """
        run_id = replay_run_id or f"replay_{uuid.uuid4().hex[:12]}"
        t_start = datetime.now(timezone.utc)

        # 1. Initialize isolated in-memory database for sandbox
        sandbox_db = DatabaseManager("sqlite:///:memory:")
        sandbox_db.init_db()

        # 2. Instantiate RuleEngine with candidate or baseline rules
        if candidate_rules_dict:
            rule_engine = RuleEngine.from_dict(candidate_rules_dict)
        elif candidate_rule_yaml_path:
            rule_engine = RuleEngine(candidate_rule_yaml_path)
        else:
            rule_engine = RuleEngine(self.default_rule_yaml_path)

        # 3. Instantiate pipeline inside sandbox (fresh profile manager and ordering state)
        pipeline = SecurityPipeline(
            location_db=self.location_db,
            rule_engine=rule_engine
        )

        decisions: List[Decision] = []

        # 4. Process all events deterministically in order
        with sandbox_db.session_scope() as session:
            for raw_evt in events:
                decision, _ = pipeline.process_event(
                    raw_event=raw_evt,
                    db=session,
                    mode="replay",
                    replay_run_id=run_id
                )
                decisions.append(decision)

        # 5. Compute deterministic SHA-256 result stream hash (R10 requirement)
        stream_hash = compute_decision_stream_hash(decisions)
        duration_ms = round((datetime.now(timezone.utc) - t_start).total_seconds() * 1000, 2)

        return {
            "replay_run_id": run_id,
            "rule_set_version": rule_engine.version,
            "total_events": len(decisions),
            "decision_stream_hash": stream_hash,
            "duration_ms": duration_ms,
            "decisions": decisions
        }

    def run_replay_from_db_slice(
        self,
        db: Session,
        user: Optional[str] = None,
        session_id: Optional[str] = None,
        start_ts: Optional[datetime] = None,
        end_ts: Optional[datetime] = None,
        candidate_rule_yaml_path: Optional[str] = None,
        candidate_rules_dict: Optional[Dict[str, Any]] = None,
        replay_run_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Pulls an event slice from an existing database and runs it through the sandboxed runner.
        Also retrieves the baseline decisions from the database to compute an immediate diff.
        """
        query = db.query(EventModel)
        if user:
            query = query.filter(EventModel.user == user)
        if session_id:
            query = query.filter(EventModel.session_id == session_id)
        if start_ts:
            query = query.filter(EventModel.event_ts >= start_ts)
        if end_ts:
            query = query.filter(EventModel.event_ts <= end_ts)

        # Preserve strict sequential arrival order
        db_events = query.order_by(EventModel.ingest_seq.asc()).all()

        # Convert to RawEventInputs
        raw_events: List[RawEventInput] = []
        for e in db_events:
            raw_events.append(
                RawEventInput(
                    timestamp=e.event_ts.isoformat(),
                    user=e.user,
                    device_id=e.device_id,
                    location_label=e.location_label_raw or e.location_label_norm,
                    action=e.action,
                    event_id=e.event_id,
                    session_id=e.session_id
                )
            )

        replay_result = self.run_replay(
            events=raw_events,
            candidate_rule_yaml_path=candidate_rule_yaml_path,
            candidate_rules_dict=candidate_rules_dict,
            replay_run_id=replay_run_id
        )

        # Retrieve original baseline decisions
        baseline_event_ids = [e.event_id for e in db_events]
        db_decisions = db.query(DecisionModel).filter(
            DecisionModel.event_id.in_(baseline_event_ids),
            DecisionModel.mode == "live"
        ).all()

        baseline_decisions: List[Decision] = []
        for d in db_decisions:
            baseline_decisions.append(
                Decision(
                    decision_id=d.decision_id,
                    event_id=d.event_id,
                    session_id=d.session_id,
                    user=d.user,
                    mode=d.mode,
                    rule_set_version=d.rule_set_version,
                    deciding_rule=d.deciding_rule,
                    response=ResponseAction(d.response),
                    evidence_level=d.evidence_level,
                    evidence_statement=d.evidence_statement,
                    explanation_text=d.explanation_text
                )
            )

        diff = ReplayDiffCalculator.compare(
            baseline_decisions=baseline_decisions,
            replay_decisions=replay_result["decisions"]
        )

        replay_result["diff"] = diff
        return replay_result
