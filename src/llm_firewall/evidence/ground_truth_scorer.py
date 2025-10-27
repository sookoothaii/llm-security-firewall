"""
Ground Truth Scorer - Evidence Quality Assessment
==================================================

Evaluates query answerability based on:
1. KB Fact Coverage (40% weight)
2. Source Quality (40% weight) 
3. Temporal Recency (20% weight)

Domain-specific weighting supported (e.g., Math emphasizes KB over sources).

Memory-Poisoning Prevention (2025-10-27):
    - Integrated EvidenceValidator to reject self-authored content
    - Prevents circular reasoning and MINJA-style attacks
    - Aligned with Kure et al. (2025), Shao et al. (2008)

References:
    - Perplexity Research (2025-10-27): Domain-specific importance
    - HAK/GAL KB: 8,468 facts, vectorized search
    - GPT-5 Critical Analysis: Memory-Poisoning Prevention
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta
import numpy as np
from dataclasses import dataclass
import logging

from llm_firewall.utils.types import GroundTruthScore, DomainConfig
from llm_firewall.evidence.validator import EvidenceValidator, get_validator
from llm_firewall.trust.domain_scorer import DomainTrustScorer
from llm_firewall.evidence.source_verifier import SourceVerifier

logger = logging.getLogger(__name__)


# Domain configurations (Perplexity-recommended)
DOMAIN_CONFIGS = {
    'MATH': DomainConfig(
        domain='MATH',
        weight_kb=0.60,           # Emphasize KB facts (authoritative)
        weight_sources=0.20,      # Sources less critical (static truths)
        weight_recency=0.20,      # Recency minimal (math doesn't age)
        half_life_days=999999,    # Never ages
        min_kb_facts=3,           # Lower requirement
        min_sources=1,            # Lower requirement
        base_threshold=0.80
    ),
    'PHYSICS': DomainConfig(
        domain='PHYSICS',
        weight_kb=0.50,
        weight_sources=0.30,
        weight_recency=0.20,
        half_life_days=999999,
        min_kb_facts=5,
        min_sources=2,
        base_threshold=0.80
    ),
    'SCIENCE': DomainConfig(
        domain='SCIENCE',
        weight_kb=0.40,
        weight_sources=0.40,
        weight_recency=0.20,
        half_life_days=1825,      # 5 years
        min_kb_facts=5,
        min_sources=3,
        base_threshold=0.75
    ),
    'MEDICINE': DomainConfig(
        domain='MEDICINE',
        weight_kb=0.35,
        weight_sources=0.45,      # Sources very important
        weight_recency=0.20,
        half_life_days=730,       # 2 years
        min_kb_facts=5,
        min_sources=4,
        min_verified_sources=2,
        base_threshold=0.80
    ),
    'GEOGRAPHY': DomainConfig(
        domain='GEOGRAPHY',
        weight_kb=0.40,
        weight_sources=0.40,
        weight_recency=0.20,
        half_life_days=3650,      # 10 years
        min_kb_facts=3,
        min_sources=2,
        base_threshold=0.70
    ),
    'NEWS': DomainConfig(
        domain='NEWS',
        weight_kb=0.20,
        weight_sources=0.50,      # Sources critical
        weight_recency=0.30,      # Recency very important
        half_life_days=30,        # 1 month
        min_kb_facts=2,
        min_sources=5,
        min_verified_sources=2,
        base_threshold=0.60
    ),
    'OPINION': DomainConfig(
        domain='OPINION',
        weight_kb=0.10,
        weight_sources=0.50,
        weight_recency=0.40,      # Recency critical
        half_life_days=7,         # 1 week
        min_kb_facts=1,
        min_sources=3,
        base_threshold=0.50
    ),
    'GLOBAL': DomainConfig(
        domain='GLOBAL',
        weight_kb=0.40,
        weight_sources=0.40,
        weight_recency=0.20,
        half_life_days=365,
        min_kb_facts=5,
        min_sources=3,
        base_threshold=0.70
    )
}


class GroundTruthScorer:
    """
    Assess evidence quality for query
    
    Progressive evolution:
        Phase 1 (now): Simple weighted sum
        Phase 2 (Month 3): Meta-learned weights
        Phase 3 (Month 6): Neural scoring model
    
    Security Features (GPT-5 2025-10-27):
        - EvidenceValidator (Memory-Poisoning prevention)
        - DomainTrustScorer (Authority assessment)
        - SourceVerifier (Link/DOI validation + BLAKE3)
    """
    
    def __init__(self, domain_configs: Optional[Dict[str, DomainConfig]] = None):
        """
        Args:
            domain_configs: Custom domain configurations (default: DOMAIN_CONFIGS)
        """
        self.configs = domain_configs or DOMAIN_CONFIGS
        self.domain_trust_scorer = DomainTrustScorer()
        self.source_verifier = SourceVerifier()
        
        logger.info("[GT Scorer] Initialized with security features: EvidenceValidator, DomainTrust, SourceVerifier")
    
    def score(
        self,
        query: str,
        kb_facts: List[Dict],
        sources: List[Dict],
        domain: Optional[str] = None
    ) -> GroundTruthScore:
        """
        Compute ground truth score
        
        Args:
            query: User query
            kb_facts: KB facts supporting query (from PostgreSQL)
            sources: Retrieved sources (URLs, citations)
            domain: Query domain (auto-detect if None)
        
        Returns:
            GroundTruthScore with overall score + breakdown
        """
        # CRITICAL: Validate evidence to prevent Memory-Poisoning
        validator = get_validator()
        if validator:
            valid_sources, rejected_sources = validator.validate_batch(sources)
            
            if rejected_sources:
                logger.warning(
                    f"[GT Scorer] REJECTED {len(rejected_sources)} sources due to self-authorship. "
                    f"Reasons: {[r['rejection_reason'] for r in rejected_sources]}"
                )
            
            # Use only validated sources
            sources = valid_sources
        else:
            logger.warning(
                "[GT Scorer] EvidenceValidator not initialized - "
                "proceeding without Memory-Poisoning protection!"
            )
        
        # Auto-detect domain if not provided
        if domain is None:
            domain = self._detect_domain(query, kb_facts)
        
        # Get domain config
        config = self.configs.get(domain, self.configs['GLOBAL'])
        
        # Compute component scores
        kb_score = self._score_kb_coverage(kb_facts, config)
        source_score = self._score_sources(sources, config)
        recency_score = self._score_recency(kb_facts, sources, config)
        
        # Weighted average (domain-specific weights)
        overall = (
            config.weight_kb * kb_score +
            config.weight_sources * source_score +
            config.weight_recency * recency_score
        )
        
        # Find newest fact/source
        days_since = self._compute_days_since_newest(kb_facts, sources)
        
        return GroundTruthScore(
            overall_score=overall,
            kb_coverage=kb_score,
            source_quality=source_score,
            recency_score=recency_score,
            kb_fact_count=len(kb_facts),
            source_count=len(sources),
            verified_source_count=len([s for s in sources if s.get('verified', False)]),
            days_since_newest=days_since,
            domain=domain,
            domain_half_life=config.half_life_days,
            query=query
        )
    
    def _score_kb_coverage(self, kb_facts: List[Dict], config: DomainConfig) -> float:
        """
        Score KB fact coverage
        
        Method: Saturating function - diminishing returns after threshold
        """
        n_facts = len(kb_facts)
        
        # Saturation at 10 facts (more doesn't help much)
        saturation_point = 10.0
        
        # Logistic saturation curve
        normalized = n_facts / saturation_point
        saturated = normalized / (1 + normalized)  # Soft saturation
        
        return saturated
    
    def _score_sources(self, sources: List[Dict], config: DomainConfig) -> float:
        """
        Score source quality with security features.
        
        Components:
            - Count (up to 5 sources)
            - Domain trust (via DomainTrustScorer)
            - Link/DOI verification (via SourceVerifier)
            - Content hashing (BLAKE3 for tamper detection)
        
        Security (GPT-5 2025-10-27):
            - Verified sources only (accessible + high-trust)
            - DOI validation for academic papers
            - Content hashing for audit trail
        """
        if not sources:
            return 0.0
        
        n_sources = len(sources)
        
        # Verify and score each source
        trust_scores = []
        verified_count = 0
        
        for source in sources:
            url = source.get('url', source.get('name', ''))
            
            # Get domain trust score
            domain_trust, reasoning = self.domain_trust_scorer.score_source(url)
            
            # Mark as verified if high trust or explicitly verified
            is_verified = (
                domain_trust >= 0.75 or  # High-trust domain
                source.get('verified', False)  # Explicitly marked
            )
            
            if is_verified:
                verified_count += 1
                trust_scores.append(domain_trust)
            
            logger.debug(
                f"[GT Scorer] Source: {url[:50]}... | "
                f"trust={domain_trust:.2f} | verified={is_verified}"
            )
        
        # Count score (saturates at 5)
        count_score = min(n_sources / 5.0, 1.0)
        
        # Verified score (saturates at 2)
        verified_score = min(verified_count / 2.0, 1.0)
        
        # Average domain trust (for verified sources only)
        if trust_scores:
            avg_trust = sum(trust_scores) / len(trust_scores)
        else:
            avg_trust = 0.0
        
        # Weighted combination
        source_quality = (
            0.4 * count_score +       # How many sources
            0.3 * verified_score +    # How many verified
            0.3 * avg_trust           # Average trust score
        )
        
        return source_quality
    
    def _score_recency(
        self,
        kb_facts: List[Dict],
        sources: List[Dict],
        config: DomainConfig
    ) -> float:
        """
        Score temporal recency with domain-specific half-life
        
        Method: Exponential decay based on domain half-life
        """
        # Find newest timestamp
        timestamps = []
        
        for fact in kb_facts:
            if 'timestamp' in fact:
                timestamps.append(fact['timestamp'])
        
        for source in sources:
            if 'published_date' in source:
                timestamps.append(source['published_date'])
        
        if not timestamps:
            # No temporal info - assume old
            return 0.50
        
        # Parse timestamps
        dates = []
        for ts in timestamps:
            if isinstance(ts, str):
                try:
                    dates.append(datetime.fromisoformat(ts))
                except:
                    pass
            elif isinstance(ts, datetime):
                dates.append(ts)
        
        if not dates:
            return 0.50
        
        # Newest date
        newest = max(dates)
        days_old = (datetime.now() - newest).days
        
        # Exponential decay with domain half-life
        # score = 2^(-days_old / half_life)
        half_life = config.half_life_days
        recency_score = 2 ** (-days_old / half_life)
        
        return recency_score
    
    def _compute_days_since_newest(
        self,
        kb_facts: List[Dict],
        sources: List[Dict]
    ) -> int:
        """Compute days since newest fact/source"""
        timestamps = []
        
        for fact in kb_facts:
            if 'timestamp' in fact:
                timestamps.append(fact['timestamp'])
        
        for source in sources:
            if 'published_date' in source:
                timestamps.append(source['published_date'])
        
        if not timestamps:
            return 999999
        
        dates = []
        for ts in timestamps:
            if isinstance(ts, str):
                try:
                    dates.append(datetime.fromisoformat(ts))
                except:
                    pass
            elif isinstance(ts, datetime):
                dates.append(ts)
        
        if not dates:
            return 999999
        
        newest = max(dates)
        return (datetime.now() - newest).days
    
    def _detect_domain(self, query: str, kb_facts: List[Dict]) -> str:
        """
        Auto-detect query domain
        
        Phase 1: Simple keyword matching
        Phase 2: Embedding-based classification
        """
        query_lower = query.lower()
        
        # Keyword matching (simple heuristic)
        domain_keywords = {
            'MATH': ['calculate', 'equation', 'number', 'sum', 'multiply', 'pi', 'sqrt'],
            'PHYSICS': ['force', 'energy', 'velocity', 'quantum', 'particle', 'wave'],
            'MEDICINE': ['disease', 'treatment', 'symptom', 'drug', 'patient', 'medical'],
            'GEOGRAPHY': ['country', 'capital', 'continent', 'ocean', 'mountain', 'river'],
            'NEWS': ['today', 'recently', 'latest', 'current', 'breaking'],
        }
        
        for domain, keywords in domain_keywords.items():
            if any(kw in query_lower for kw in keywords):
                return domain
        
        # Check KB facts for domain tags
        if kb_facts:
            domains_in_facts = [f.get('domain') for f in kb_facts if 'domain' in f]
            if domains_in_facts:
                # Most common domain
                from collections import Counter
                return Counter(domains_in_facts).most_common(1)[0][0]
        
        # Default
        return 'GLOBAL'

