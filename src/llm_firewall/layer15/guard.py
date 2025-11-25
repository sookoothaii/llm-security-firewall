"""Layer 15 Guard - Main orchestrator for vulnerable domain protection."""

from typing import Dict, Any, Tuple
from .age_router import AgeRouter
from .crisis import CrisisDetector
from .deceptive_empathy import DeceptiveEmpathyFilter
from .rsi_childsafe import RSIMetrics, ChildSafeAggregator
from .owasp_sinks import OWASPSinkGuards


class Layer15Guard:
    """Orchestrates all Layer 15 components."""

    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.age = AgeRouter(cfg["age_router"])
        self.crisis = CrisisDetector(cfg["crisis_detection"])
        self.de = DeceptiveEmpathyFilter(cfg["deceptive_empathy_filter"])
        self.rsi = RSIMetrics(cfg["rsi_childsafe"])
        self.childsafe = ChildSafeAggregator(cfg["rsi_childsafe"])
        self.sinks = (
            OWASPSinkGuards(cfg["owasp_sinks"])
            if cfg.get("owasp_sinks", {}).get("enabled")
            else None
        )

    def route_age(self, band: str) -> Any:
        """Get age-appropriate policy for given band."""
        return self.age.get(band)

    def crisis_hotpath(self, text: str, ctx: str, country: str) -> Dict[str, Any]:
        """Execute crisis detection and escalation logic."""
        level, meta = self.crisis.decide(text, ctx)
        actions = self.cfg["crisis_detection"]["escalation"]["actions"][level]
        card = self.crisis.resource_card(country)
        return {"level": level, "actions": actions, "resource": card, "meta": meta}

    def make_nonhuman_transparent(
        self, text: str, lang: str = "en"
    ) -> Tuple[str, bool]:
        """Rewrite text to remove deceptive empathy and add transparency."""
        return self.de.rewrite(text, lang)

    def compute_rsi(self, defect_rate: float, refusal_rate: float) -> float:
        """Calculate Risk Severity Index."""
        return self.rsi.rsi(defect_rate, refusal_rate)

    def update_childsafe(self, dim_scores: list[float]) -> Dict[str, Any]:
        """Update ChildSafe 9-dimensional vector."""
        self.childsafe.update(dim_scores)
        return self.childsafe.as_dict()

    def sink_sql(self, query: str) -> str:
        """Check SQL query safety."""
        return self.sinks.check_sql(query) if self.sinks else "ALLOW"

    def sink_shell(self, cmd: str) -> str:
        """Check shell command safety."""
        return self.sinks.check_shell(cmd) if self.sinks else "ALLOW"

    def sink_html_md(self, html: str) -> str:
        """Sanitize HTML/Markdown output."""
        return self.sinks.sanitize_html_md(html) if self.sinks else html
