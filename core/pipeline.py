"""
Unified Deterministic Pipeline (A-03, Section 7 & 14.3).
Exact same code path runs for both live processing and sandboxed replay.
Guarantees 100% determinism, atomic session gate enforcement (R11), and evidence traceability.
"""

from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from sqlalchemy.orm import Session

from core.contracts import (
    RawEventInput,
    NormalizedEvent,
    SignalResult,
    AdvisoryResult,
    Decision,
    IngestStatus,
    SignalStatus,
    EvidenceLevel,
    ResponseAction,
    SessionState
)
from core.normalize import LocationDatabase, EventNormalizer
from core.ordering import OrderingHandler, OrderingClassification
from core.profile import ProfileManager, UserProfile
from core.signals import (
    UnfamiliarDeviceDetector,
    ImplausibleLocationChangeDetector,
    UnusualHourDetector,
    SensitiveAfterUnfamiliarLoginDetector,
    UnfamiliarLocationDetector,
    SensitiveActionChainDetector
)
from core.advisory.markov import MarkovSequenceAdvisor
from core.rules.engine import RuleEngine, RuleEvaluationResult
from core.explain.templates import ExplanationGenerator
from store.models import (
    EventModel,
    SessionModel,
    DecisionModel,
    StepUpChallengeModel,
    ReviewCaseModel,
    QuarantineModel
)
from store.audit import AuditLedger


class SecurityPipeline:
    """The central unified detection pipeline for live and replayed event evaluation."""

    def __init__(
        self,
        location_db: LocationDatabase,
        rule_engine: RuleEngine,
        normalizer: Optional[EventNormalizer] = None,
        ordering_handler: Optional[OrderingHandler] = None,
        profile_manager: Optional[ProfileManager] = None,
        advisor: Optional[MarkovSequenceAdvisor] = None
    ):
        self.location_db = location_db
        self.rule_engine = rule_engine
        self.normalizer = normalizer or EventNormalizer(location_db)
        self.ordering_handler = ordering_handler or OrderingHandler()
        self.profile_manager = profile_manager or ProfileManager()
        self.advisor = advisor or MarkovSequenceAdvisor()

        # Instantiate detectors
        self.s1_detector = UnfamiliarDeviceDetector()
        self.s2_detector = ImplausibleLocationChangeDetector()
        self.s3_detector = UnusualHourDetector()
        self.s4_detector = SensitiveAfterUnfamiliarLoginDetector()
        self.s5_detector = UnfamiliarLocationDetector()
        self.s6_detector = SensitiveActionChainDetector()

    def process_event(
        self,
        raw_event: RawEventInput,
        db: Session,
        mode: str = "live",
        replay_run_id: Optional[str] = None
    ) -> Tuple[Decision, bool]:
        """
        Executes the full pipeline for one event.
        Returns: (Decision, is_refused_due_to_revocation)
        """
        # Step 1: Normalize & Validate (R1)
        try:
            norm_event = self.normalizer.normalize(raw_event)
        except Exception as e:
            # Store in quarantine (Section 5.5)
            q_entry = QuarantineModel(
                raw_payload=json.dumps(raw_event.model_dump()),
                reason=str(e),
                received_at=datetime.now(timezone.utc)
            )
            db.add(q_entry)
            db.commit()
            raise ValueError(f"Event rejected and quarantined: {e}") from e

        # Store raw event in append-only table (Section 6)
        db_event = EventModel(
            event_id=norm_event.event_id,
            ingest_seq=norm_event.ingest_seq,
            received_at=norm_event.received_at,
            event_ts=norm_event.event_ts,
            user=norm_event.user,
            device_id=norm_event.device_id,
            location_label_raw=norm_event.location_label_raw,
            location_label_norm=norm_event.location_label_norm,
            action=norm_event.action,
            session_id=norm_event.session_id,
            warnings_json=json.dumps(norm_event.warnings),
            ingest_status=norm_event.ingest_status.value,
            raw_payload_json=json.dumps(norm_event.raw_payload)
        )
        db.add(db_event)

        # Step 2: Session Gate (R11 & Section 12.4)
        # Look up session state in transactional store
        session_rec = db.query(SessionModel).filter(SessionModel.session_id == norm_event.session_id).first()

        if session_rec and session_rec.status == SessionState.REVOKED.value:
            # R11 Terminal Refusal: Do NOT execute action, do NOT learn into profile
            decision_id = f"dec_refused_{uuid.uuid4().hex[:12]}"
            explanation = (
                f"Action '{norm_event.action}' refused for user '{norm_event.user}': "
                f"Session '{norm_event.session_id}' was terminally revoked at {session_rec.revoked_at.isoformat()} "
                f"by {session_rec.revoked_by}."
            )
            decision = Decision(
                decision_id=decision_id,
                event_id=norm_event.event_id,
                session_id=norm_event.session_id,
                user=norm_event.user,
                mode=mode,
                replay_run_id=replay_run_id,
                rule_set_version=self.rule_engine.version,
                signals=[],
                advisory=None,
                rules_fired=["R-11-REFUSED"],
                deciding_rule="SESSION_GATE",
                response=ResponseAction.REFUSED_SESSION_REVOKED,
                evidence_level=EvidenceLevel.NONE,
                evidence_statement="Session is terminally revoked.",
                explanation_text=explanation
            )

            # Persist decision record
            db_dec = DecisionModel(
                decision_id=decision.decision_id,
                event_id=decision.event_id,
                session_id=decision.session_id,
                user=decision.user,
                mode=mode,
                replay_run_id=replay_run_id,
                rule_set_version=decision.rule_set_version,
                signals_json="[]",
                advisory_json=None,
                rules_fired_json=json.dumps(["SESSION_GATE"]),
                deciding_rule="SESSION_GATE",
                response=decision.response.value,
                evidence_level=decision.evidence_level.value,
                evidence_statement=decision.evidence_statement,
                explanation_text=decision.explanation_text
            )
            db.add(db_dec)
            db.commit()

            AuditLedger.append_entry(
                session=db,
                actor="SessionGate",
                action="refuse_action",
                target=norm_event.session_id,
                before_state="revoked",
                after_state="refused_action"
            )
            return decision, True  # True indicates session refusal

        # If session does not exist, initialize active session
        is_new_session = False
        if not session_rec:
            is_new_session = True
            is_unfamiliar_dev = (profile_mgr := self.profile_manager.get_or_create(norm_event.user)).known_devices.get(norm_event.device_id) is None and profile_mgr.total_events > 0
            session_rec = SessionModel(
                session_id=norm_event.session_id,
                user=norm_event.user,
                device_id=norm_event.device_id,
                started_at=norm_event.event_ts,
                last_event_at=norm_event.event_ts,
                status=SessionState.ACTIVE.value,
                derived=(raw_event.session_id is None),
                login_device_unfamiliar=is_unfamiliar_dev
            )
            db.add(session_rec)
        else:
            session_rec.last_event_at = norm_event.event_ts
            if norm_event.action == "login":
                is_unfamiliar_dev = (profile_mgr := self.profile_manager.get_or_create(norm_event.user)).known_devices.get(norm_event.device_id) is None and profile_mgr.total_events > 0
                session_rec.login_device_unfamiliar = is_unfamiliar_dev

        # Step 3: Ordering Check (R6)
        ordering_status, lateness = self.ordering_handler.check_ordering(norm_event)
        if ordering_status == OrderingClassification.LATE:
            norm_event.warnings.append(f"late_event_{int(lateness or 0)}s")

        # Step 4: Point-in-Time Profile
        profile = self.profile_manager.get_or_create(norm_event.user)
        evidence_level = profile.get_evidence_level()

        # Prepare session context for detectors
        # Check login event and sensitive history in this session
        session_events = db.query(EventModel).filter(
            EventModel.session_id == norm_event.session_id
        ).order_by(EventModel.ingest_seq.asc()).all()

        login_event = next((e for e in session_events if e.action == "login"), None)
        sensitive_events = [
            {"action": e.action, "ts": e.event_ts}
            for e in session_events
            if e.action in {"change_email", "change_password", "request_transfer", "add_payee"}
        ]

        # Check if step-up challenge passed in this session
        passed_challenge = db.query(StepUpChallengeModel).filter(
            StepUpChallengeModel.session_id == norm_event.session_id,
            StepUpChallengeModel.status == "passed"
        ).first()

        session_ctx = {
            "login_event_id": login_event.event_id if login_event else None,
            "login_event_ts": login_event.event_ts if login_event else norm_event.event_ts,
            "login_device_unfamiliar": session_rec.login_device_unfamiliar,
            "sensitive_actions_in_session": sensitive_events,
            "step_up_passed": (passed_challenge is not None),
            "action": norm_event.action
        }

        # Step 5: Evaluate Signals S1 to S6
        s1 = self.s1_detector.evaluate(norm_event, profile, self.location_db, session_ctx)
        s2 = self.s2_detector.evaluate(norm_event, profile, self.location_db, session_ctx)
        s3 = self.s3_detector.evaluate(norm_event, profile, self.location_db, session_ctx)
        s4 = self.s4_detector.evaluate(norm_event, profile, self.location_db, session_ctx)
        s5 = self.s5_detector.evaluate(norm_event, profile, self.location_db, session_ctx)
        s6 = self.s6_detector.evaluate(norm_event, profile, self.location_db, session_ctx)

        signals_dict: Dict[str, SignalResult] = {
            s1.signal_id: s1,
            s2.signal_id: s2,
            s3.signal_id: s3,
            s4.signal_id: s4,
            s5.signal_id: s5,
            s6.signal_id: s6,
        }

        # Step 6: AI Advisory Sequence Anomaly Module (R9)
        actions_in_session = [e.action for e in session_events] + [norm_event.action]
        advisory_res = self.advisor.evaluate_sequence(
            session_actions=actions_in_session,
            user_session_count=profile.total_sessions,
            user_transitions=profile.action_transitions
        )

        # Step 7: Evaluate Rules & Precedence (R8)
        rule_eval = self.rule_engine.evaluate(
            signals=signals_dict,
            evidence_level=evidence_level,
            advisory=advisory_res,
            extra_context={"action": norm_event.action}
        )

        # Step 8: Execute Response & State Machine Transitions (Section 12)
        decision_id = f"dec_{uuid.uuid4().hex[:12]}"
        final_response = rule_eval.final_response

        if final_response == ResponseAction.REVOKE:
            session_rec.status = SessionState.REVOKED.value
            session_rec.revoked_at = norm_event.event_ts
            session_rec.revoked_by = rule_eval.deciding_rule_id or "RuleEngine"
            session_rec.revoke_decision_id = decision_id

            AuditLedger.append_entry(
                session=db,
                actor="RuleEngine",
                action="session_revocation",
                target=norm_event.session_id,
                before_state="active",
                after_state="revoked"
            )

        elif final_response == ResponseAction.STEP_UP:
            session_rec.status = SessionState.PENDING_VERIFICATION.value
            challenge = StepUpChallengeModel(
                challenge_id=f"chal_{uuid.uuid4().hex[:12]}",
                session_id=norm_event.session_id,
                decision_id=decision_id,
                status="open"
            )
            db.add(challenge)

        if final_response == ResponseAction.ANALYST_REVIEW or rule_eval.also_open_review:
            review_case = ReviewCaseModel(
                case_id=f"case_{uuid.uuid4().hex[:12]}",
                decision_id=decision_id,
                session_id=norm_event.session_id,
                user=norm_event.user,
                status="open",
                analyst_note=f"Triggered by rule {rule_eval.deciding_rule_id}"
            )
            db.add(review_case)

        # Step 9: Explanations (Section 17)
        ev_statement = ExplanationGenerator.generate_evidence_statement(
            profile, evidence_level, signals_dict
        )
        summary_text = ExplanationGenerator.generate_decision_summary(
            action=norm_event.action,
            user=norm_event.user,
            response=final_response,
            rule_result=rule_eval,
            signals=signals_dict,
            evidence_statement=ev_statement,
            advisory=advisory_res
        )

        # Build Decision contract
        decision = Decision(
            decision_id=decision_id,
            event_id=norm_event.event_id,
            session_id=norm_event.session_id,
            user=norm_event.user,
            mode=mode,
            replay_run_id=replay_run_id,
            rule_set_version=self.rule_engine.version,
            signals=list(signals_dict.values()),
            advisory=advisory_res,
            rules_fired=rule_eval.rules_fired,
            deciding_rule=rule_eval.deciding_rule_id,
            response=final_response,
            evidence_level=evidence_level,
            evidence_statement=ev_statement,
            explanation_text=summary_text
        )

        # Persist Decision
        db_dec = DecisionModel(
            decision_id=decision.decision_id,
            event_id=decision.event_id,
            session_id=decision.session_id,
            user=decision.user,
            mode=mode,
            replay_run_id=replay_run_id,
            rule_set_version=decision.rule_set_version,
            signals_json=json.dumps([s.model_dump() for s in decision.signals]),
            advisory_json=json.dumps(advisory_res.model_dump()) if advisory_res else None,
            rules_fired_json=json.dumps(decision.rules_fired),
            deciding_rule=decision.deciding_rule,
            response=decision.response.value,
            evidence_level=decision.evidence_level.value,
            evidence_statement=decision.evidence_statement,
            explanation_text=decision.explanation_text
        )
        db.add(db_dec)
        db.commit()

        # Step 10: Learn Profile (Section 8.4)
        # Only learn from events eligible for baseline updates (non-revoked, legitimate)
        if final_response in {ResponseAction.NO_ACTION, ResponseAction.STEP_UP}:
            _, loc_rec, is_unk = self.location_db.resolve(norm_event.location_label_norm)
            loc_tz = loc_rec.timezone_name if loc_rec else "UTC"
            self.profile_manager.update_from_event(
                norm_event,
                location_timezone=loc_tz,
                is_resolvable_location=(loc_rec is not None)
            )

        return decision, False
