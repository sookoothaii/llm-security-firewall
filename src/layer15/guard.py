"""Layer 15 Guard - Orchestrator for all vulnerable domain protections.

Integrates:
- Age-aware routing
- Crisis detection
- Deceptive empathy filtering
- RSI metrics
- ChildSafe aggregation
- OWASP sink guards

Credit: GPT-5 collaboration 2025-11-04
"""

from typing import Dict, Any, List
from .age_router import AgeRouter, AgePolicy
from .crisis import CrisisDetector
from .deceptive_empathy import DeceptiveEmpathyFilter
from .rsi_childsafe import RSIMetrics, ChildSafeAggregator
from .owasp_sinks import OWASPSinkGuards


class Layer15Guard:
    """Main orchestrator for Layer 15 vulnerable domain protections."""
    
    def __init__(self, cfg: Dict[str, Any]):
        """Initialize with full Layer 15 configuration.
        
        Args:
            cfg: Full configuration dict from layer15.yaml
        """
        self.cfg = cfg
        
        # Initialize all components
        self.age = AgeRouter(cfg["age_router"])
        self.crisis = CrisisDetector(cfg["crisis_detection"])
        self.de = DeceptiveEmpathyFilter(cfg["deceptive_empathy_filter"])
        self.rsi = RSIMetrics(cfg["rsi_childsafe"])
        self.childsafe = ChildSafeAggregator(cfg["rsi_childsafe"])
        
        # OWASP sinks are optional
        self.sinks = None
        if cfg.get("owasp_sinks", {}).get("enabled"):
            self.sinks = OWASPSinkGuards(cfg["owasp_sinks"])

    # Age-aware routing
    
    def route_age(self, band: str) -> AgePolicy:
        """Get generation policy for age band.
        
        Args:
            band: Age band identifier (e.g., 'A6_8')
            
        Returns:
            AgePolicy with generation constraints
        """
        return self.age.get(band)

    # Crisis detection hotpath
    
    def crisis_hotpath(self, text: str, ctx: str, country: str) -> Dict[str, Any]:
        """Run crisis detection and get appropriate actions + resources.
        
        Args:
            text: User message
            ctx: Conversation context
            country: User country code for resource card
            
        Returns:
            Dict with level, actions, resource card, and metadata
        """
        level, meta = self.crisis.decide(text, ctx)
        actions = self.cfg["crisis_detection"]["escalation"]["actions"][level]
        card = self.crisis.resource_card(country)
        
        return {
            "level": level,
            "actions": actions,
            "resource": card,
            "meta": meta
        }

    # Deceptive empathy filtering
    
    def make_nonhuman_transparent(self, text: str, lang: str = "en") -> tuple[str, bool]:
        """Rewrite text to remove deceptive empathy and add transparency.
        
        Args:
            text: Generated text
            lang: Language code ('en' or 'de')
            
        Returns:
            Tuple of (rewritten_text, was_changed)
        """
        return self.de.rewrite(text, lang)

    # RSI metrics
    
    def compute_rsi(self, defect_rate: float, refusal_rate: float) -> float:
        """Compute RSI score.
        
        Args:
            defect_rate: Defect rate (0-1)
            refusal_rate: Refusal rate (0-1)
            
        Returns:
            RSI score (0-1)
        """
        return self.rsi.rsi(defect_rate, refusal_rate)

    # ChildSafe aggregation
    
    def update_childsafe(self, dim_scores: List[float]) -> Dict[str, Any]:
        """Update ChildSafe 9D vector with new scores.
        
        Args:
            dim_scores: List of 9 scores (0-1) for each dimension
            
        Returns:
            Current aggregated state
        """
        self.childsafe.update(dim_scores)
        return self.childsafe.as_dict()

    # OWASP sink guards
    
    def sink_sql(self, query: str) -> str:
        """Check SQL query for injection patterns.
        
        Args:
            query: SQL query string
            
        Returns:
            'BLOCK' or 'ALLOW'
        """
        return self.sinks.check_sql(query) if self.sinks else "ALLOW"

    def sink_shell(self, cmd: str) -> str:
        """Check shell command for meta-characters.
        
        Args:
            cmd: Shell command string
            
        Returns:
            'BLOCK' or 'ALLOW'
        """
        return self.sinks.check_shell(cmd) if self.sinks else "ALLOW"

    def sink_html_md(self, html: str) -> str:
        """Sanitize HTML/Markdown output.
        
        Args:
            html: HTML/Markdown string
            
        Returns:
            Sanitized output
        """
        return self.sinks.sanitize_html_md(html) if self.sinks else html










