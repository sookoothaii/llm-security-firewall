"""
Evidence Validator - Memory-Poisoning Prevention
=================================================

Prevents circular reasoning through self-authored evidence.

GPT-5 Critical Analysis (2025-10-27):
"LLM schreibt 'unschuldig' verfärbte Zusammenfassungen in Supermemory
 → biased spätere Urteile durch zirkuläre Referenzen"

Solution: No self-authored evidence allowed.
"""

from typing import Dict, Tuple, Optional, Set
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class EvidenceValidator:
    """
    Validates evidence against self-authorship policy.
    
    Critical Security Feature:
    - Prevents Memory-Poisoning attacks
    - Blocks circular reasoning
    - Ensures evidence independence
    """
    
    def __init__(self, instance_id: str):
        """
        Initialize validator.
        
        Args:
            instance_id: Unique identifier for this LLM instance
        """
        self.instance_id = instance_id
        self.rejected_count = 0
        self.rejection_reasons = {
            'SELF_AUTHORED_EVIDENCE': 0,
            'SELF_AUTHORED_SUPERMEMORY': 0,
            'CIRCULAR_REFERENCE': 0,
            'SELF_AUTHORED_KB': 0,
            'MISSING_PROVENANCE': 0
        }
    
    def is_valid_evidence(self, evidence: dict) -> Tuple[bool, str]:
        """
        Validate evidence against self-authorship policy.
        
        Args:
            evidence: Evidence dict with metadata
            
        Returns:
            (is_valid, reason)
            
        Examples:
            >>> validator = EvidenceValidator("inst-123")
            >>> evidence = {'authored_by': 'inst-123', 'text': 'X is true'}
            >>> validator.is_valid_evidence(evidence)
            (False, 'SELF_AUTHORED_EVIDENCE')
        """
        # Check 1: Direct self-authorship
        if evidence.get('authored_by') == self.instance_id:
            self._log_rejection('SELF_AUTHORED_EVIDENCE', evidence)
            return False, "SELF_AUTHORED_EVIDENCE"
        
        # Check 2: Creator instance ID
        if evidence.get('creator_instance_id') == self.instance_id:
            self._log_rejection('SELF_AUTHORED_EVIDENCE', evidence)
            return False, "SELF_AUTHORED_EVIDENCE"
        
        # Check 3: Supermemory self-authored content
        if evidence.get('source') == 'supermemory':
            metadata = evidence.get('metadata', {})
            if metadata.get('creator_instance_id') == self.instance_id:
                self._log_rejection('SELF_AUTHORED_SUPERMEMORY', evidence)
                return False, "SELF_AUTHORED_SUPERMEMORY"
            
            # Supermemory content marked as excluded
            if metadata.get('excluded_from_evidence', False):
                self._log_rejection('SELF_AUTHORED_SUPERMEMORY', evidence)
                return False, "SELF_AUTHORED_SUPERMEMORY"
        
        # Check 4: KB facts created by this instance
        if evidence.get('source') == 'kb':
            if evidence.get('created_by_instance') == self.instance_id:
                self._log_rejection('SELF_AUTHORED_KB', evidence)
                return False, "SELF_AUTHORED_KB"
        
        # Check 5: Circular reference detection
        if self._is_circular_reference(evidence):
            self._log_rejection('CIRCULAR_REFERENCE', evidence)
            return False, "CIRCULAR_REFERENCE"
        
        # Check 6: Provenance exists
        if not self._has_valid_provenance(evidence):
            self._log_rejection('MISSING_PROVENANCE', evidence)
            return False, "MISSING_PROVENANCE"
        
        return True, "VALID"
    
    def _is_circular_reference(self, evidence: dict) -> bool:
        """
        Check for circular chains of evidence.
        
        Example:
            Session 1: LLM writes "System is production-ready"
            Session 2: Other instance reads this as evidence
            → CIRCULAR!
        
        Args:
            evidence: Evidence to check
            
        Returns:
            True if circular reference detected
        """
        # Check if evidence references this instance's previous outputs
        reference_chain = evidence.get('reference_chain', [])
        
        for ref in reference_chain:
            if ref.get('instance_id') == self.instance_id:
                logger.warning(
                    f"[EvidenceValidator] Circular reference detected: "
                    f"Evidence references output from instance {self.instance_id}"
                )
                return True
        
        # Check if evidence is a derivative of our own content
        if evidence.get('derived_from_instance') == self.instance_id:
            return True
        
        return False
    
    def _has_valid_provenance(self, evidence: dict) -> bool:
        """
        Check if evidence has valid provenance metadata.
        
        Args:
            evidence: Evidence to check
            
        Returns:
            True if provenance is valid
        """
        # Must have source
        if not evidence.get('source'):
            return False
        
        # Supermemory/KB must have creator info
        source = evidence.get('source')
        if source in ['supermemory', 'kb']:
            metadata = evidence.get('metadata', {})
            if not metadata.get('creator_instance_id'):
                # Missing creator info is suspicious
                logger.warning(
                    f"[EvidenceValidator] Supermemory/KB evidence missing creator_instance_id"
                )
                # For now, allow (backward compatibility)
                # TODO: Make this strict after migration
                return True
        
        return True
    
    def _log_rejection(self, reason: str, evidence: dict):
        """Log rejection for audit trail."""
        self.rejected_count += 1
        self.rejection_reasons[reason] += 1
        
        logger.warning(
            f"[EvidenceValidator] REJECTED evidence: {reason} | "
            f"Source: {evidence.get('source', 'unknown')} | "
            f"Instance: {self.instance_id}"
        )
    
    def get_statistics(self) -> Dict:
        """
        Get validator statistics.
        
        Returns:
            Dict with rejection counts by reason
        """
        return {
            'total_rejected': self.rejected_count,
            'rejection_reasons': self.rejection_reasons.copy(),
            'instance_id': self.instance_id
        }
    
    def validate_batch(self, evidence_list: list) -> Tuple[list, list]:
        """
        Validate a batch of evidence items.
        
        Args:
            evidence_list: List of evidence dicts
            
        Returns:
            (valid_evidence, rejected_evidence)
        """
        valid = []
        rejected = []
        
        for evidence in evidence_list:
            is_valid, reason = self.is_valid_evidence(evidence)
            
            if is_valid:
                valid.append(evidence)
            else:
                rejected.append({
                    'evidence': evidence,
                    'rejection_reason': reason,
                    'timestamp': datetime.now().isoformat()
                })
        
        logger.info(
            f"[EvidenceValidator] Batch validated: "
            f"{len(valid)} valid, {len(rejected)} rejected"
        )
        
        return valid, rejected


# Singleton instance (initialized with actual instance_id at startup)
_global_validator: Optional[EvidenceValidator] = None


def initialize_validator(instance_id: str):
    """Initialize global validator instance."""
    global _global_validator
    _global_validator = EvidenceValidator(instance_id)
    logger.info(f"[EvidenceValidator] Initialized with instance_id: {instance_id}")


def get_validator() -> Optional[EvidenceValidator]:
    """Get global validator instance."""
    return _global_validator

