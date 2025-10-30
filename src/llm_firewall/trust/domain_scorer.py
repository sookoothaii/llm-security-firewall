"""
Domain Trust Scorer - Source Authority Assessment
==================================================

Assigns trust scores to sources based on domain authority.

Based on GPT-5 Policy & Controls (2025-10-27):
- Domain allowlist/denylist
- Source reputation scoring
- DKIM/Signature verification support

Literature:
- Nature Medicine (2025): Med-LLMs need high-trust sources
- Emergents Mind (2025): Domain-trust as first defense layer
"""

import logging
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# Domain Trust Tiers (0.0-1.0)
DOMAIN_TRUST_SCORES = {
    # Tier 1: Authoritative (0.95-1.0)
    'nature.com': 0.98,
    'science.org': 0.98,
    'cell.com': 0.98,
    'thelancet.com': 0.98,
    'nejm.org': 0.98,             # New England Journal of Medicine
    'jamanetwork.com': 0.98,       # JAMA

    # Tier 2: Academic/Government (0.85-0.94)
    'arxiv.org': 0.95,
    'who.int': 0.95,
    'cdc.gov': 0.95,
    'nih.gov': 0.95,
    'ieee.org': 0.92,
    'acm.org': 0.92,
    'springer.com': 0.90,
    'sciencedirect.com': 0.90,
    '.edu': 0.88,                  # Academic institutions
    '.gov': 0.90,                  # Government

    # Tier 3: Established Media (0.70-0.84)
    'nytimes.com': 0.80,
    'bbc.com': 0.82,
    'reuters.com': 0.85,
    'apnews.com': 0.85,
    'theguardian.com': 0.78,

    # Tier 4: General Reference (0.60-0.69)
    'wikipedia.org': 0.70,
    'britannica.com': 0.75,
    'stackexchange.com': 0.65,
    'stackoverflow.com': 0.68,

    # Tier 5: Social/Community (0.30-0.59)
    'medium.com': 0.40,
    'substack.com': 0.35,
    'reddit.com': 0.30,
    'quora.com': 0.35,
    'twitter.com': 0.25,
    'x.com': 0.25,

    # Tier 6: Low Trust (0.10-0.29)
    'blogspot.com': 0.20,
    'wordpress.com': 0.20,
    'tumblr.com': 0.15,

    # Tier 7: Denylist (0.0)
    'fake-news.com': 0.0,
    '.tk': 0.0,                    # Free TLD often abused
    '.ml': 0.0,
    '.ga': 0.0,
}


class DomainTrustScorer:
    """
    Assigns trust scores to sources based on domain authority.
    
    Features:
    - Pre-configured trust scores for known domains
    - TLD-based heuristics (.edu, .gov)
    - Denylist support
    - Signature verification integration points
    """

    def __init__(self, custom_scores: Optional[Dict[str, float]] = None):
        """
        Initialize scorer.
        
        Args:
            custom_scores: Optional custom domain scores (overrides defaults)
        """
        self.trust_scores = DOMAIN_TRUST_SCORES.copy()

        if custom_scores:
            self.trust_scores.update(custom_scores)

        logger.info(
            f"[DomainTrust] Initialized with {len(self.trust_scores)} "
            f"domain trust scores"
        )

    def score_source(
        self,
        url: str,
        has_signature: bool = False,
        signature_type: Optional[str] = None
    ) -> Tuple[float, str]:
        """
        Score a source based on its domain.
        
        Args:
            url: Source URL
            has_signature: Whether source has DKIM/PGP signature
            signature_type: Type of signature (dkim, pgp, etc.)
        
        Returns:
            (trust_score, reasoning)
        
        Examples:
            >>> scorer = DomainTrustScorer()
            >>> scorer.score_source("https://nature.com/articles/123")
            (0.98, "Tier 1: Authoritative (nature.com)")
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]

            # Check exact match first
            if domain in self.trust_scores:
                base_score = self.trust_scores[domain]
                reasoning = f"Exact match: {domain}"

            # Check TLD patterns (.edu, .gov, .tk, .ml, .ga, etc.)
            elif any(domain.endswith(tld) for tld in ['.edu', '.gov', '.tk', '.ml', '.ga']):
                for tld in ['.edu', '.gov', '.tk', '.ml', '.ga']:
                    if domain.endswith(tld) and tld in self.trust_scores:
                        base_score = self.trust_scores[tld]
                        reasoning = f"TLD match: {tld}"
                        break
                else:
                    base_score = 0.10
                    reasoning = "Unknown TLD"

            # Check partial matches (e.g., "example.nature.com" matches "nature.com")
            else:
                base_score = 0.10  # Default: low trust
                reasoning = "Unknown domain (default low trust)"

                for trusted_domain, score in self.trust_scores.items():
                    if not trusted_domain.startswith('.') and trusted_domain in domain:
                        base_score = score
                        reasoning = f"Partial match: {trusted_domain}"
                        break

            # Bonus for signature
            if has_signature and base_score > 0:
                signature_bonus = 0.05
                final_score = min(base_score + signature_bonus, 1.0)
                reasoning += f" + signature ({signature_type})"
            else:
                final_score = base_score

            logger.debug(
                f"[DomainTrust] {domain}: {final_score:.2f} ({reasoning})"
            )

            return final_score, reasoning

        except Exception as e:
            logger.error(f"[DomainTrust] Scoring failed for {url}: {e}")
            return 0.0, f"Error: {e}"

    def is_denylisted(self, url: str) -> bool:
        """
        Check if domain is on denylist.
        
        Args:
            url: Source URL
            
        Returns:
            True if denylisted (trust = 0.0)
        """
        score, _ = self.score_source(url)
        return score == 0.0

    def get_tier(self, trust_score: float) -> str:
        """
        Get trust tier name from score.
        
        Args:
            trust_score: 0.0-1.0
            
        Returns:
            Tier name
        """
        if trust_score >= 0.95:
            return "Tier 1: Authoritative"
        elif trust_score >= 0.85:
            return "Tier 2: Academic/Government"
        elif trust_score >= 0.75:
            return "Tier 3: Established Media"
        elif trust_score >= 0.60:
            return "Tier 4: General Reference"
        elif trust_score >= 0.30:
            return "Tier 5: Social/Community"
        elif trust_score >= 0.10:
            return "Tier 6: Low Trust"
        else:
            return "Tier 7: Denylisted"

    def batch_score(self, urls: list) -> Dict[str, Tuple[float, str]]:
        """
        Score multiple sources in batch.
        
        Args:
            urls: List of source URLs
            
        Returns:
            Dict mapping URL → (score, reasoning)
        """
        results = {}

        for url in urls:
            score, reasoning = self.score_source(url)
            results[url] = (score, reasoning)

        logger.info(
            f"[DomainTrust] Batch scored {len(urls)} sources"
        )

        return results

    def get_statistics(self) -> Dict:
        """Get scorer statistics."""
        return {
            'total_domains': len(self.trust_scores),
            'tier_1_count': len([s for s in self.trust_scores.values() if s >= 0.95]),
            'tier_2_count': len([s for s in self.trust_scores.values() if 0.85 <= s < 0.95]),
            'tier_3_count': len([s for s in self.trust_scores.values() if 0.70 <= s < 0.85]),
            'denylisted_count': len([s for s in self.trust_scores.values() if s == 0.0])
        }

