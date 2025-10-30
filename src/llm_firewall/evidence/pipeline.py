"""
Evidence Pipeline - Orchestration of Verification Steps
========================================================

Coordinates: EvidenceValidator, DomainTrust, SourceVerifier, NLI, Hashing

Based on GPT-5 Evidence Pipeline (2025-10-27)
Persona/Epistemik separation: No personality variables here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Optional, Sequence

from llm_firewall.evidence.source_verifier import SourceVerifier
from llm_firewall.evidence.validator import EvidenceValidator
from llm_firewall.trust.content_hasher import blake3_hex
from llm_firewall.trust.domain_scorer import DomainTrustScorer
from llm_firewall.trust.nli_consistency import FakeNLI, consistency_against_kb

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PipelineConfig:
    """Evidence pipeline configuration."""

    tau_trust: float = 0.75
    tau_nli: float = 0.85
    require_corroboration: bool = True
    min_corroborations: int = 2


@dataclass
class EvidenceRecord:
    """Evidence record for pipeline processing."""

    content: str
    source_url: Optional[str] = None
    source_domain: Optional[str] = None
    doi: Optional[str] = None
    kb_corroborations: int = 0


class EvidencePipeline:
    """
    Orchestrates evidence verification.

    CRITICAL: Persona/Epistemik separation maintained.
    No personality variables in pipeline logic.
    """

    def __init__(
        self,
        config: PipelineConfig,
        evidence_validator: EvidenceValidator,
        domain_trust_scorer: DomainTrustScorer,
        source_verifier: SourceVerifier,
        nli_model=None,  # Optional, defaults to FakeNLI
    ):
        """Initialize pipeline with all components."""
        self.cfg = config
        self.evidence_validator = evidence_validator
        self.domain_trust = domain_trust_scorer
        self.source_verifier = source_verifier
        self.nli = nli_model or FakeNLI()

        logger.info("[EvidencePipeline] Initialized with security components")

    def process(self, record: EvidenceRecord, kb_sentences: Sequence[str]) -> Dict:
        """
        Process evidence record through verification pipeline.

        Steps:
        1. Content hashing (BLAKE3)
        2. Self-authorship check (EvidenceValidator)
        3. Domain trust scoring
        4. Source verification (Link/DOI)
        5. NLI consistency (against KB)
        6. Corroboration check
        7. Decision (PROMOTE | QUARANTINE)

        Args:
            record: Evidence to process
            kb_sentences: Existing KB facts for consistency check

        Returns:
            Pipeline result dict
        """
        # Step 1: Content hashing
        digest = blake3_hex(record.content)

        # Step 2: Self-authorship check
        evidence_obj = {
            "content": record.content,
            "source": record.source_domain or "external",
            "url": record.source_url,
        }

        is_valid_evidence, rejection_reason = self.evidence_validator.is_valid_evidence(
            evidence_obj
        )

        if not is_valid_evidence:
            return {
                "digest": digest,
                "decision": "REJECT",
                "reasons": [rejection_reason],
                "trust": 0.0,
                "nli": 0.0,
                "verified": False,
            }

        # Step 3: Domain trust
        trust = 0.5  # Default
        if record.source_url:
            trust, trust_reasoning = self.domain_trust.score_source(record.source_url)

        # Step 4: Source verification
        link_verified = False
        if record.source_url:
            verification = self.source_verifier.verify_source(
                record.source_url, content=record.content, expected_doi=record.doi
            )
            link_verified = verification["verified"]

        # Step 5: NLI consistency
        nli_score = 0.0
        if kb_sentences:
            nli_score = consistency_against_kb(
                record.content, kb_sentences, self.nli, agg="max"
            )

        # Step 6: Corroboration check
        has_corroboration = record.kb_corroborations >= self.cfg.min_corroborations

        # Step 7: Decision
        decision = "QUARANTINE"
        reasons = []

        if trust < self.cfg.tau_trust:
            reasons.append(f"low_trust:{trust:.2f} < tau({self.cfg.tau_trust:.2f})")

        if nli_score < self.cfg.tau_nli:
            reasons.append(f"low_nli:{nli_score:.2f} < tau({self.cfg.tau_nli:.2f})")

        if self.cfg.require_corroboration and not has_corroboration:
            reasons.append(
                f"low_corroboration:{record.kb_corroborations} < "
                f"{self.cfg.min_corroborations}"
            )

        if not reasons:
            decision = "PROMOTE"

        logger.info(
            f"[EvidencePipeline] {decision}: "
            f"trust={trust:.2f}, nli={nli_score:.2f}, "
            f"corr={record.kb_corroborations}"
        )

        return {
            "digest": digest,
            "trust": trust,
            "nli": nli_score,
            "link_verified": link_verified,
            "corroborations": record.kb_corroborations,
            "decision": decision,
            "reasons": reasons,
            "verified": decision == "PROMOTE",
        }
