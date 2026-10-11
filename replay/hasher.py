"""
Deterministic Decision Stream Hasher for IdentityGuard (A-03, Section 14.3).
Calculates SHA-256 integrity hash over ordered sequence of replay decisions.
Guarantees identical hash for identical event streams and rule sets.
"""

import hashlib
import json
from typing import List
from core.contracts import Decision


def compute_decision_stream_hash(decisions: List[Decision]) -> str:
    """
    Computes a canonical SHA-256 hash over an ordered list of decisions.
    Fields included:
      - event_id
      - session_id
      - response (value)
      - deciding_rule (or 'NONE')
      - rules_fired (sorted)
      - evidence_level (value)
    """
    hasher = hashlib.sha256()

    for dec in decisions:
        record = {
            "event_id": dec.event_id,
            "session_id": dec.session_id,
            "response": dec.response.value,
            "deciding_rule": dec.deciding_rule or "NONE",
            "rules_fired": sorted(dec.rules_fired or []),
            "evidence_level": dec.evidence_level.value
        }
        canonical_str = json.dumps(record, sort_keys=True)
        hasher.update(canonical_str.encode("utf-8"))

    return hasher.hexdigest()
