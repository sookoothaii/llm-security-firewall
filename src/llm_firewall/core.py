"""
LLM Security Firewall - Core API
=================================

Unified interface for the 9-layer security framework.

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import yaml  # type: ignore
import logging

from llm_firewall.evidence.pipeline import EvidencePipeline, PipelineConfig, EvidenceRecord
from llm_firewall.evidence.validator import EvidenceValidator
from llm_firewall.trust.domain_scorer import DomainTrustScorer
from llm_firewall.evidence.source_verifier import SourceVerifier
from llm_firewall.safety.validator import SafetyValidator
from llm_firewall.monitoring.shingle_hasher import ShingleHasher
from llm_firewall.monitoring.influence_budget import InfluenceBudgetTracker

logger = logging.getLogger(__name__)


@dataclass
class FirewallConfig:
    """Firewall configuration."""
    
    config_dir: str = "config"
    instance_id: str = "default"
    
    # Evidence pipeline
    tau_trust: float = 0.75
    tau_nli: float = 0.85
    require_corroboration: bool = True
    min_corroborations: int = 2
    
    # Safety
    safety_threshold: float = 0.8
    
    # Monitoring
    drift_threshold: float = 0.15
    influence_z_threshold: float = 2.5
    kl_threshold: float = 0.05
    
    @classmethod
    def from_yaml(cls, config_path: str) -> FirewallConfig:
        """Load configuration from YAML file."""
        path = Path(config_path)
        
        if not path.exists():
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return cls()
        
        with open(path) as f:
            config_data = yaml.safe_load(f)
        
        return cls(
            config_dir=str(path.parent),
            instance_id=config_data.get("instance_id", "default"),
            tau_trust=config_data.get("evidence", {}).get("tau_trust", 0.75),
            tau_nli=config_data.get("evidence", {}).get("tau_nli", 0.85),
            safety_threshold=config_data.get("safety", {}).get("threshold", 0.8),
            drift_threshold=config_data.get("canaries", {}).get("drift_threshold", 0.15),
            influence_z_threshold=config_data.get("influence", {}).get("z_score_threshold", 2.5),
            kl_threshold=config_data.get("shingle", {}).get("kl_threshold", 0.05),
        )


@dataclass
class ValidationResult:
    """Result from input validation."""
    is_safe: bool
    reason: str
    risk_score: float = 0.0
    category: Optional[str] = None


@dataclass
class EvidenceDecision:
    """Result from evidence validation."""
    should_promote: bool
    should_quarantine: bool
    should_reject: bool
    confidence: float
    reason: str
    evidence_hash: Optional[str] = None


class SecurityFirewall:
    """
    Unified security firewall for LLM systems.
    
    Provides:
    - Input validation (HUMAN → LLM)
    - Output validation (LLM → HUMAN)
    - Memory monitoring (drift, influence, duplicates)
    
    Example:
        config = FirewallConfig.from_yaml("config.yaml")
        firewall = SecurityFirewall(config)
        
        is_safe, reason = firewall.validate_input(user_query)
        decision = firewall.validate_evidence(content, sources, kb_facts)
    """
    
    def __init__(self, config: FirewallConfig):
        """Initialize firewall with configuration."""
        self.config = config
        
        # Initialize components
        pipeline_config = PipelineConfig(
            tau_trust=config.tau_trust,
            tau_nli=config.tau_nli,
            require_corroboration=config.require_corroboration,
            min_corroborations=config.min_corroborations,
        )
        
        evidence_validator = EvidenceValidator(instance_id=config.instance_id)
        domain_trust_scorer = DomainTrustScorer()
        source_verifier = SourceVerifier()
        
        self.evidence_pipeline = EvidencePipeline(
            config=pipeline_config,
            evidence_validator=evidence_validator,
            domain_trust_scorer=domain_trust_scorer,
            source_verifier=source_verifier
        )
        
        self.safety_validator = SafetyValidator(config_dir=config.config_dir)
        
        # Canaries require NLI model - initialize later when needed
        self.canary_monitor = None
        self.shingle_hasher = ShingleHasher()
        self.influence_tracker = InfluenceBudgetTracker(
            z_score_threshold=config.influence_z_threshold
        )
        
        logger.info(f"SecurityFirewall initialized (instance: {config.instance_id})")
    
    def validate_input(self, text: str) -> Tuple[bool, str]:
        """
        Validate input text for safety.
        
        Args:
            text: Input text to validate
            
        Returns:
            (is_safe, reason) tuple
        """
        # Safety check
        safety_decision = self.safety_validator.validate(text)
        
        if safety_decision.action == "BLOCK":
            return False, f"Blocked: {safety_decision.reason} (category: {safety_decision.category})"
        elif safety_decision.action == "GATE":
            return False, f"Gated: {safety_decision.reason}"
        
        # Safe
        return True, "Input passed safety validation"
    
    def validate_evidence(
        self,
        content: str,
        sources: List[Dict],
        kb_facts: List[str]
    ) -> EvidenceDecision:
        """
        Validate evidence through full pipeline.
        
        Args:
            content: Claim to validate
            sources: List of source dicts with 'name', 'url', 'doi' keys
            kb_facts: List of KB facts for corroboration
            
        Returns:
            EvidenceDecision with promote/quarantine/reject decision
        """
        # Create evidence record
        source_url = sources[0].get('url') if sources else None
        source_domain = sources[0].get('domain') if sources else None
        doi = sources[0].get('doi') if sources else None
        
        record = EvidenceRecord(
            content=content,
            source_url=source_url,
            source_domain=source_domain,
            doi=doi,
            kb_corroborations=len(kb_facts)
        )
        
        # Run evidence pipeline
        result = self.evidence_pipeline.process(
            record=record,
            kb_sentences=kb_facts
        )
        
        # Map to decision
        decision = result.get('decision', 'REJECT')
        
        if decision == "PROMOTE":
            should_promote = True
            should_quarantine = False
            should_reject = False
        elif decision == "QUARANTINE":
            should_promote = False
            should_quarantine = True
            should_reject = False
        else:  # REJECT
            should_promote = False
            should_quarantine = False
            should_reject = True
        
        return EvidenceDecision(
            should_promote=should_promote,
            should_quarantine=should_quarantine,
            should_reject=should_reject,
            confidence=result.get('confidence', 0.0),
            reason=result.get('reason', 'Unknown'),
            evidence_hash=result.get('evidence_hash')
        )
    
    def check_drift(self, sample_size: int = 10) -> Tuple[bool, Dict]:
        """
        Check for memory drift using canaries.
        
        Args:
            sample_size: Number of canaries to test
            
        Returns:
            (has_drift, canary_scores) tuple
        """
        # Simplified implementation - full version requires NLI model
        if self.canary_monitor is None:
            logger.warning("Canary monitor not initialized, returning no drift")
            return False, {}
        
        canaries = self.canary_monitor.get_random_sample(sample_size)
        scores = {}
        
        failures = 0
        for canary in canaries:
            # Simulate verification (in production, check against actual KB)
            score = 1.0 if canary.expected_truth else 0.0
            scores[canary.claim] = score
            
            if score < 0.5:
                failures += 1
        
        failure_rate = failures / len(canaries) if canaries else 0.0
        has_drift = failure_rate > self.config.drift_threshold
        
        return has_drift, scores
    
    def get_alerts(self, domain: str = "SCIENCE") -> List[str]:
        """
        Get active alerts for domain.
        
        Args:
            domain: Domain to filter alerts
            
        Returns:
            List of alert messages
        """
        # Placeholder - in production, query from monitoring system
        alerts = []
        
        # Check influence budget
        if hasattr(self.influence_tracker, 'current_z_score'):
            z = self.influence_tracker.current_z_score
            if abs(z) > self.config.influence_z_threshold:
                alerts.append(f"Influence spike detected: Z={z:.2f}")
        
        return alerts


# Export main classes
__all__ = [
    'SecurityFirewall',
    'FirewallConfig',
    'ValidationResult',
    'EvidenceDecision',
]

