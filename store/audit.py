"""
Cryptographic Hash-Chained Audit Ledger (A-03, Section 6 & 16.3).
Provides tamper-evident record keeping where every entry is chained to the SHA-256 digest of the previous entry.
"""

from __future__ import annotations
import hashlib
import threading
from datetime import datetime, timezone
from typing import Optional, Tuple, List
from sqlalchemy.orm import Session
from store.models import AuditLogModel

GENESIS_HASH = "0" * 64


class AuditLedger:
    """Appends records to the audit log and verifies chain integrity."""

    _lock = threading.Lock()

    @classmethod
    def append_entry(
        cls,
        session: Session,
        actor: str,
        action: str,
        target: str,
        before_state: Optional[str] = None,
        after_state: Optional[str] = None
    ) -> AuditLogModel:
        """Appends a new hash-chained audit entry safely under concurrency."""
        with cls._lock:
            # Find latest entry to get prev_hash
            latest = session.query(AuditLogModel).order_by(AuditLogModel.audit_id.desc()).first()
            prev_hash = latest.row_hash if latest else GENESIS_HASH

            now_utc = datetime.now(timezone.utc)
            ts_str = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

            # Compute row_hash = SHA256(prev_hash | actor | action | target | ts_str | before | after)
            hasher = hashlib.sha256()
            payload = f"{prev_hash}|{actor}|{action}|{target}|{ts_str}|{before_state or ''}|{after_state or ''}"
            hasher.update(payload.encode("utf-8"))
            row_hash = hasher.hexdigest()

            entry = AuditLogModel(
                actor=actor,
                action=action,
                target=target,
                before_state=before_state,
                after_state=after_state,
                ts=now_utc,
                prev_hash=prev_hash,
                row_hash=row_hash
            )
            session.add(entry)
            session.commit()
            return entry

    @staticmethod
    def verify_chain(session: Session) -> Tuple[bool, int, Optional[str]]:
        """
        Verifies cryptographic integrity of the entire audit trail.
        Returns: (is_valid, total_records_verified, error_message)
        """
        records = session.query(AuditLogModel).order_by(AuditLogModel.audit_id.asc()).all()
        if not records:
            return True, 0, None

        expected_prev = GENESIS_HASH
        for idx, rec in enumerate(records):
            if rec.prev_hash != expected_prev:
                return (
                    False,
                    idx,
                    f"Chain break at record #{rec.audit_id}: expected prev_hash '{expected_prev}', got '{rec.prev_hash}'"
                )

            # Re-hash using identical deterministic timestamp format
            ts_str = rec.ts.strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(rec.ts, "strftime") else str(rec.ts)[:19] + "Z"
            hasher = hashlib.sha256()
            payload = f"{rec.prev_hash}|{rec.actor}|{rec.action}|{rec.target}|{ts_str}|{rec.before_state or ''}|{rec.after_state or ''}"
            hasher.update(payload.encode("utf-8"))
            computed_hash = hasher.hexdigest()

            if computed_hash != rec.row_hash:
                return (
                    False,
                    idx,
                    f"Hash mismatch at record #{rec.audit_id}: row content has been tampered with!"
                )

            expected_prev = rec.row_hash

        return True, len(records), None
