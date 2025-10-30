"""
Decision Ledger
===============

Comprehensive audit trail for all firewall decisions.

KUE-proof: Every decision is reproducible and auditable.

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from llm_firewall.core.types import Decision, ModelContext


@dataclass
class JudgeVote:
    """Vote from a single judge."""

    name: str
    version: str
    risk: float
    band: str
    severity: int
    latency_ms: float


@dataclass
class DecisionRecord:
    """
    Complete audit record for a firewall decision.

    KUE-Proof: Contains all information needed to reproduce decision.
    """

    # Context
    ctx: ModelContext

    # Gate results
    captcha: Optional[Dict[str, Any]] = None  # {item_id, seed, params, passed}
    stream_stats: Optional[Dict[str, Any]] = None  # {tokens, aborts, rewrites}
    votes: List[JudgeVote] = field(default_factory=list)

    # Aggregation
    aggregation: Dict[str, Any] = field(
        default_factory=dict
    )  # {overall_risk, band, qhat, coverage}
    thresholds: Dict[str, Any] = field(
        default_factory=dict
    )  # {deny_band, abstain_band, weights}

    # Final decision
    decision: Decision = Decision.ALLOW

    # Audit
    kue_proof_id: Optional[str] = None

    def id(self) -> str:
        """
        Compute deterministic ID for this decision.

        Based on request context + decision parameters.
        Used for deduplication and audit trail.

        Returns:
            SHA-256 hash (64 hex chars)
        """
        data = {
            "request_id": self.ctx.request_id,
            "time": self.ctx.time_utc.isoformat(),
            "prompt_hash": self.ctx.prompt_hash,
            "decision": self.decision.value,
            "overall_risk": self.aggregation.get("overall_risk", 0.0),
        }
        content = json.dumps(data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def to_json(self) -> str:
        """
        Serialize to JSON for storage.

        Returns:
            JSON string
        """
        return json.dumps(asdict(self), default=str, sort_keys=True, indent=2)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for Postgres JSONB.

        Returns:
            Dict representation
        """
        return asdict(self)


class DecisionLedger:
    """
    Persistence layer for decision records.

    Supports:
    - PostgreSQL JSONB (structured queries)
    - File-based (ndjson/parquet for long-term analysis)
    """

    def __init__(self, db_connection=None, file_path: Optional[str] = None):
        """
        Initialize ledger.

        Args:
            db_connection: PostgreSQL connection (optional)
            file_path: NDJSON file path for file-based persistence (optional)
        """
        self.db = db_connection
        self.file_path = file_path

    def persist(self, record: DecisionRecord) -> str:
        """
        Persist decision record.

        Args:
            record: Decision record to store

        Returns:
            Record ID
        """
        record_id = record.id()

        # PostgreSQL storage
        if self.db:
            self._persist_postgres(record, record_id)

        # File storage
        if self.file_path:
            self._persist_file(record)

        return record_id

    def _persist_postgres(self, record: DecisionRecord, record_id: str):
        """Persist to PostgreSQL JSONB column."""
        # TODO: Implement PostgreSQL INSERT
        # INSERT INTO decision_ledger (id, data, created_at)
        # VALUES (%s, %s, NOW())
        pass

    def _persist_file(self, record: DecisionRecord):
        """Persist to NDJSON file."""
        import pathlib

        if self.file_path is None:
            return

        path = pathlib.Path(self.file_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "a", encoding="utf-8") as f:
            f.write(record.to_json() + "\n")

    def query(self, filters: Dict[str, Any]) -> List[DecisionRecord]:
        """
        Query decision records.

        Args:
            filters: Query filters (session_id, user_id, decision, etc.)

        Returns:
            List of matching records
        """
        # TODO: Implement PostgreSQL query
        # SELECT data FROM decision_ledger WHERE ...
        return []
